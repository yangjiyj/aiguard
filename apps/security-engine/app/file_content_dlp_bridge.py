"""文件内容 DLP 正文提取器 —— engine 接入层。

把提取出的正文拼成供检测器扫描的文本，并把解析失败（损坏/加密/超时/zip 越界）
转成显式的“检测未完成” finding（action=audit，放行并记录），供 engine.check_input 合并进决策。

红线：
- 仅在 SECURITY_FILE_CONTENT_DLP_ENABLED 开启时执行；关闭时本函数返回空，行为不变。
- 解析失败绝不静默：返回 parse_failed finding（action=audit，放行并记录，2026-09-23 定案），
  「未完成检测」绝不写成「检测通过」。
- 证据脱敏：finding 的 matched_text_preview 只写失败原因与文件名 basename，绝不回显正文。
"""
from __future__ import annotations

import os
import re as _re
from typing import List, Optional, Tuple

from app import feature_flags as ff
from app.bounded_work import WorkUnavailable, check_work_budget
from app.file_inspector import (  # 复用既有声明类型推断、真实类型识别与文件名清洗
    _declared_type,
    _detect_real_type,
    _sanitize_filename,
)
from app.file_text_extractor import (
    TEXTUAL_TYPES,
    extract_attachment_text,
)

# 单附件正文送检上限（受部署硬上限约束；tenant 配置不得突破）
MAX_SCAN_FILE_BYTES = int(os.getenv("SECURITY_FILE_CONTENT_MAX_SCAN_MB", "100")) * 1024 * 1024

_AUDIT_IF_EMPTY_TYPES = {"pdf", "docx", "pptx", "xlsx", "zip", "tar", "gzip"}
_REFERENCE_FIELDS = ("reference_id", "file_id", "file_url", "download_url", "url", "object_id")


_PII_NAME_PATTERNS = [
    _re.compile(r"1[3-9]\d{9}"),              # 手机号
    _re.compile(r"\b\d{17}[\dXx]\b"),        # 身份证
    _re.compile(r"\b\d{16,19}\b"),            # 长卡号
    _re.compile(r"AKIA[0-9A-Z]{16}"),            # AWS key
    _re.compile(r"sk-[A-Za-z0-9]{20,}"),         # openai key
]


def _redact_name_pii(name: str) -> str:
    """对进入 finding 证据的文件名做 PII 掩码（保留可读性，脱敏数字/密钥串）。"""
    if not name:
        return name
    out = name
    for pat in _PII_NAME_PATTERNS:
        out = pat.sub(lambda m: m.group(0)[:3] + "***", out)
    return out


def _parse_failure_finding(att: dict, idx: int, reason: str, rule_id: str) -> Optional[dict]:
    """构造解析失败 finding（dict 形式，与 custom_rules 一致，由 engine 转 SecurityFinding）。

    reason: encrypted / timeout / corrupt / zip_unsafe / oversized / unsupported
    """
    from app.detectors.engine import SecurityFinding

    raw_name = att.get("file_name") or att.get("field_name") or f"attachment-{idx}"
    safe_name, _ = _sanitize_filename(raw_name)
    ev_name = _redact_name_pii(safe_name)  # 证据里的文件名再做 PII 脱敏
    location = f"attachment[{idx}]:{ev_name}"
    severity = "high"
    # 解析失败/超时/加密/超限属于"检测未完成"：一律放行并记录（2026-09-23 定案），
    # 只有控制台显式配置为阻断的文件类型策略才会拦截文件。
    action = "audit"
    preview = f"文件正文未完成检测({reason})：{ev_name}，已放行并记录"
    category_map = {
        "encrypted": "file_content_encrypted",
        "timeout": "file_content_parse_timeout",
        "canceled": "file_content_parse_canceled",
        "zip_unsafe": "file_content_zip_unsafe",
        "oversized": "file_content_oversized",
        "corrupt": "file_content_parse_failed",
        "unsupported": "file_content_unsupported",
        "object_unavailable": "file_content_object_unavailable",
        "capacity": "file_content_capacity_unavailable",
        "incomplete": "file_content_incomplete",
    }
    return SecurityFinding(
        type="file",
        category=category_map.get(reason, "file_content_parse_failed"),
        severity=severity,
        matched_text_preview=preview,
        rule_id=rule_id,
        confidence=0.9,
        rule_name="文件正文未完成检测",
        rule_type="file_fingerprint",
        action=action,
        matched_location=location,
        redacted_evidence=f"reason={reason} file={ev_name}",
        attachment_index=idx,
    )


def _uninspected_finding(
    att: dict, idx: int, reason: str, *, unknown_risk: bool = False
) -> Optional[dict]:
    """记录正文检测覆盖缺口；未知二进制仍按风险 finding 保留。"""
    from app.detectors.engine import SecurityFinding

    raw_name = att.get("file_name") or att.get("field_name") or f"attachment-{idx}"
    safe_name, _ = _sanitize_filename(raw_name)
    ev_name = _redact_name_pii(safe_name)
    if unknown_risk:
        return SecurityFinding(
            type="file",
            category="file_content_uninspected",
            severity="medium",
            matched_text_preview=f"文件正文未完成检测({reason})：{ev_name}，已记录审计",
            rule_id="file-content-uninspected",
            confidence=0.8,
            rule_name="未知文件正文未完成检测",
            rule_type="file_fingerprint",
            action="audit",
            matched_location=f"attachment[{idx}]:{ev_name}",
            redacted_evidence=f"reason={reason} file={ev_name}",
            evidence_kind="runtime",
            attachment_index=idx,
        )
    return SecurityFinding(
        type="engine_runtime",
        category="file_content_uninspected",
        severity="low",
        matched_text_preview=f"文件正文未完成检测({reason})：{ev_name}，已记录覆盖缺口",
        rule_id="file-content-uninspected",
        confidence=1.0,
        rule_name="文件正文检测覆盖缺口",
        rule_type="file_fingerprint",
        action="audit",
        counts_as_security_finding=False,
        matched_location=f"attachment[{idx}]:{ev_name}",
        redacted_evidence=f"reason={reason} file={ev_name}",
        evidence_kind="runtime",
        attachment_index=idx,
        triage={
            "disposition": "observation",
            "disposition_reason": "coverage_gap",
            "reason": reason,
        },
    )


def _has_unmaterialized_reference(att: dict) -> bool:
    """判断附件是否声称存在外部对象，但当前上下文没有可读取字节。"""
    return any(att.get(key) for key in _REFERENCE_FIELDS)


def _effective_extract_type(declared: str, data: bytes) -> Tuple[str, str]:
    """以魔术字节为主、声明类型为 Office/纯文本兼容补充，返回(提取类型,真实类型)。"""
    real = _detect_real_type(data)
    if real == "zip" and declared in {"docx", "pptx", "xlsx"}:
        # OOXML 的真实容器也是 ZIP，声明类型只用于选择对应 XML 正文路径。
        return declared, real
    if real in TEXTUAL_TYPES or real in {"png", "jpeg", "jpg", "gif", "bmp", "webp", "tiff"}:
        return real, real
    if real == "unknown" and declared in TEXTUAL_TYPES:
        # 纯文本没有稳定魔术字节；声明类型只在无法识别真实二进制时兜底。
        return declared, real
    return "", real


def file_content_dlp_enabled() -> bool:
    """文件内容 DLP 全局动态开关：唯一执行门控。

    由 system_settings.file_content_dlp_enabled 经托管配置投影驱动（loader 把
    JSON boolean 映射为 SECURITY_FILE_CONTENT_DLP_ENABLED 覆盖层）；控制平面不可
    用时回落到启动环境变量，默认关闭。租户级旧字段不再参与执行判断。
    """
    return ff.is_enabled(ff.ENV_FILE_CONTENT_DLP)


def _policy_content_dlp_enabled(file_policy: Optional[dict]) -> bool:
    """租户级内容 DLP 开关：仅当 file_policy 显式声明 content_dlp_enabled=true 才认为开启。

    缺字段（旧 rule pack / 未下发）一律视为关闭——「前端有开关」不等于「能力已可用」，
    必须后端显式下发合法策略且节点接收成功才生效。
    """
    if not isinstance(file_policy, dict):
        return False
    return bool(file_policy.get("content_dlp_enabled"))


def extract_textual_attachment_content(
    context: Optional[dict],
    file_policy: Optional[dict] = None,
    tenant_id: str = "",
) -> Tuple[str, List]:
    """提取 context.attachments 中文本类附件的正文，返回 (正文文本, 解析失败 findings)。

    启用条件：全局动态开关 file_content_dlp_enabled()（system_settings 真源，默认关）。
    旧租户字段 file_policy.content_dlp_enabled 仅保留解析兼容，不再参与执行门控。
    """
    if not file_content_dlp_enabled():
        return "", []
    if not context or not isinstance(context, dict):
        return "", []
    attachments = context.get("attachments")
    if not isinstance(attachments, list) or not attachments:
        return "", []

    texts: List[str] = []
    failures: List = []
    for idx, att in enumerate(attachments):
        if not isinstance(att, dict):
            continue
        try:
            check_work_budget()
        except WorkUnavailable as exc:
            finding = _parse_failure_finding(att, idx, exc.reason, "file-content-request-" + exc.reason)
            finding.redacted_evidence += f" unscanned_attachment_range={idx}:{len(attachments)}"
            failures.append(finding)
            break
        # proxy 已明确声明对象物化失败时，不得继续当成“无正文附件”静默放行。
        # 该标记只表达基础设施失败，不回显上传错误或文件正文。
        if att.get("object_id_unavailable"):
            failures.append(
                _parse_failure_finding(
                    att, idx, "object_unavailable", "file-content-object-unavailable"
                )
            )
            continue
        # 字节来源优先级：object_id(大文件临时区，不跨服务传 base64) > data_base64(≤2MB 内联)
        data, byte_err = _resolve_attachment_bytes(att, tenant_id)
        if byte_err:
            failures.append(_parse_failure_finding(att, idx, byte_err, "file-content-" + byte_err.replace("_", "-")))
            continue
        if data is None:
            # 没有可读取字节时，引用型附件必须阻断；普通元数据附件至少留下未检查审计。
            if _has_unmaterialized_reference(att):
                failures.append(
                    _parse_failure_finding(
                        att, idx, "object_unavailable", "file-content-object-unavailable"
                    )
                )
            elif att.get("file_name") or att.get("content_type"):
                failures.append(_uninspected_finding(att, idx, "bytes_unavailable"))
            continue
        if len(data) > MAX_SCAN_FILE_BYTES:
            failures.append(_parse_failure_finding(att, idx, "oversized", "file-content-oversized"))
            continue

        declared = _declared_type(att.get("content_type"), att.get("file_name") or "")
        real_for_extract, real_type = _effective_extract_type(declared, data)
        if not real_for_extract:
            failures.append(
                _uninspected_finding(
                    att,
                    idx,
                    real_type or "unknown",
                    unknown_risk=(real_type or "unknown") == "unknown",
                )
            )
            continue

        if real_for_extract in {"png", "jpeg", "jpg", "gif", "bmp", "webp", "tiff"}:
            from app.ocr import extract_image_text
            res = extract_image_text(data)
        else:
            res = extract_attachment_text(real_for_extract, data)
        if res.encrypted:
            failures.append(_parse_failure_finding(att, idx, "encrypted", "file-content-encrypted"))
            continue
        if res.timeout:
            failures.append(_parse_failure_finding(att, idx, "timeout", "file-content-parse-timeout"))
            continue
        if res.error == "unsupported":
            failures.append(_uninspected_finding(att, idx, real_for_extract))
            continue
        if res.error:
            failures.append(_parse_failure_finding(att, idx, res.error, "file-content-parse-failed"))
            continue
        if res.truncated or res.incomplete_reasons:
            finding = _parse_failure_finding(att, idx, "incomplete", "file-content-incomplete")
            reasons = sorted(set(res.incomplete_reasons + (["truncated"] if res.truncated else [])))
            finding.redacted_evidence += " incomplete=" + ",".join(reasons)
            finding.evidence_kind = "runtime"
            finding.triage = {"disposition": "observation", "disposition_reason": "coverage_gap", "reason": ",".join(reasons)}
            failures.append(finding)
        if res.text:
            name = att.get("file_name") or att.get("field_name") or f"attachment-{idx}"
            safe, _ = _sanitize_filename(name)
            texts.append(f"[attachment:{idx} file:{safe}] {res.text}")
        elif real_for_extract in _AUDIT_IF_EMPTY_TYPES:
            failures.append(_uninspected_finding(att, idx, f"{real_for_extract}_no_text"))
    return ("\n".join(texts), failures)


def _magic_textual_type(att: dict) -> str:
    """声明类型不可靠时，退而用前几字节判 pdf（其它文本类无可靠魔术字节，跳过）。"""
    b64 = att.get("data_base64") or ""
    if not b64:
        return ""
    try:
        import base64 as _b64mod
        head = _b64mod.b64decode(b64[:12] + "==", validate=False)
    except Exception:
        return ""
    if head[:5] == b"%PDF-" or head[:4] == b"%PDF":
        return "pdf"
    return ""

def _resolve_attachment_bytes(att: dict, tenant_id: str) -> Tuple[Optional[bytes], Optional[str]]:
    """解析附件字节：优先 object_id 临时区（大文件，不跨服务传 base64），其次 data_base64。

    返回 (bytes, None) 成功；(None, None) 无字节可取；(None, error) 受控失败。
    object_id 路径从受限临时区读字节，读后由 consume 删除（即焚）。
    """
    obj_id = att.get("object_id") or ""
    if obj_id and tenant_id:
        try:
            from app.scan_service import scan_service
            store = scan_service.store
            if store is not None:
                data = store.read_bytes(obj_id, tenant_id)
                return data, None
        except Exception as exc:
            msg = str(exc)
            reason = "corrupt"
            if "not_found" in msg or "invalid" in msg:
                reason = "corrupt"
            return None, reason
        return None, "corrupt"  # 声称有 object_id 但 store 未启用 → 视为损坏阻断
    b64 = att.get("data_base64") or ""
    if not b64:
        return None, None
    import base64 as _b64mod
    try:
        return _b64mod.b64decode(b64, validate=True), None
    except Exception:
        return None, "corrupt"
