"""
P2-1 自定义规则匹配引擎（方案A：规则编译下发 —— 引擎消费侧）

control-plane 将租户在策略中心配置的规则编译为「规则包」下发；本模块在
security-engine 内消费规则包并执行匹配，产出与内置检测器一致的统一结果模型
（SecurityFinding）。引擎保持无状态，不直连数据库。

安全红线：
- 命中证据必须脱敏；原始敏感值（尤其密钥类）不得完整写入 finding / 日志。
- 正则需防 ReDoS：编译期识别灾难性回溯模式并跳过，运行期限制扫描长度。
"""
from __future__ import annotations

from collections import Counter, OrderedDict
import hashlib
import logging
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

import regex as bounded_regex
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.detectors.engine import SecurityFinding
from app.detectors.numeric_context import is_complete_pii_token, non_pii_numeric_spans
from app.detectors.pii_checksum import validate_bank_card, validate_id_card_cn
from app.detectors.sensitive_data import is_public_service_email, is_non_mailbox_at_reference
from app.detectors.numeric_context import is_git_remote_reference
from app.detectors.policy_catalog import PRECISE_CATALOG_CATEGORIES, catalog_candidate_has_required_terms
from app.detectors.severity_downgrade import match_has_real_value, match_is_key_only
from app.principal_context import PrincipalContext
from app.regex_budget import AttemptStats, env_float, run_with_cpu_budget
from app.text_normalize import NormalizedText, keyword_view, normalize_keyword

logger = logging.getLogger(__name__)

# 与 gateway chat request 的 10 MiB 接收上限对齐。范围内必须完整扫描；
# 只有绕过网关直连、超过该边界的内容才进入 fail-closed 完整性保护。
MAX_SCAN_LEN = 10 * 1024 * 1024
# 单条正则最大长度，过长直接判定不安全
MAX_PATTERN_LEN = 1000
# 第三方 regex 引擎支持可中断的单次匹配；再加整组预算，避免大量坏规则
# 各自耗尽超时后把请求热路径拖慢。
# 预算按本线程 CPU 时间记账（等 GIL 的时间不算），可用环境变量覆盖，
# 非法值回落默认并告警，详见 app/regex_budget.py。
MAX_REGEX_MATCH_SECONDS = env_float("SECURITY_CUSTOM_REGEX_RULE_SECONDS", 0.01, 0.001, 1.0)
MAX_REGEX_RULESET_SECONDS = env_float("SECURITY_CUSTOM_REGEX_PACK_SECONDS", 0.05, 0.005, 5.0)
# 随内容大小放大后的单条 / 整包封顶。
MAX_REGEX_MATCH_CEILING_SECONDS = env_float("SECURITY_CUSTOM_REGEX_RULE_MAX_SECONDS", 0.2, 0.01, 5.0)
MAX_REGEX_RULESET_CEILING_SECONDS = env_float("SECURITY_CUSTOM_REGEX_PACK_MAX_SECONDS", 0.5, 0.05, 10.0)
# 脱敏规则必须拿到全部 span；超过上限时该规则不返回部分脱敏，改记一条“检测未完成”
# （action=audit，按原文放行并告警，见 runtime_failure_finding）。
MAX_REGEX_MASK_MATCHES = 256
# 会实际改变流量的动作；整包预算优先分给这些规则。
_ENFORCING_ACTIONS = frozenset({"block", "mask"})

# 系统内置邮箱规则：RFC 长度边界减少无效候选，原子组阻止候选内部回溯。
# 后视捕获完整局部段、以 @ 为搜索锚点，避免在超长伪邮箱的每个字符位置
# 重新尝试。运行时按稳定 rule_id 覆盖旧规则包，兼容迁移生效前窗口。
RULE_G_EMAIL_REGEX = (
    r"(?<=(?P<email_local>(?a:\b)(?>[A-Za-z0-9._%+-]{1,64})))@(?:(?>[A-Za-z0-9-]{1,63})\.)+(?>[A-Za-z]{2,63})(?a:\b)"
)
_CN_ID_CATEGORIES = frozenset({"id_card_cn", "pii_idcard", "pii_id_card"})
_BANK_CARD_CATEGORIES = frozenset({"bank_card_cn", "pii_bankcard", "pii_bank_card"})
_PII_VALUE_SHAPES = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "id_card_cn": re.compile(r"[0-9]{17}[0-9Xx]"),
    "bank_card_cn": re.compile(r"[0-9]{12,19}"),
    "phone_cn": re.compile(r"1[3-9][0-9]{9}"),
}


def _pii_match_kind(rule: CompiledRule) -> str:
    if rule.rule_id == "rule_g_idcard" or rule.category in _CN_ID_CATEGORIES:
        return "id_card_cn"
    if rule.rule_id == "rule_g_bankcard" or rule.category in _BANK_CARD_CATEGORIES:
        return "bank_card_cn"
    if rule.rule_id == "rule_g_phone" or rule.category in {"phone_cn", "pii_phone"}:
        return "phone_cn"
    if rule.rule_id == "rule_g_email" or rule.category in {"email", "pii_email"}:
        return "email"
    return ""

# 灾难性回溯启发式：分组内含无界量词(+/*)、且分组整体又被量词修饰，
# 例如 (a+)+ / (a*)* / (\d+)+ —— 典型 ReDoS 模式
_NESTED_QUANT = re.compile(r"\([^()]*[+*][^()]*\)[*+{]")
# 重复执行的分支可能拥有相同前缀，例如 (a|aa)+$。Python 回溯引擎会
# 指数级探索这类分支；保存时保守拒绝，运行时 timeout 仍作为最终边界。
_REPEATED_ALTERNATION = re.compile(r"\([^()]*\|[^()]*\)[*+{]")


class CompiledRule(BaseModel):
    """规则包中的单条规则（control-plane 编译产物的引擎侧映射）"""

    model_config = ConfigDict(extra="forbid", strict=True)

    rule_id: str
    rule_name: str
    rule_type: str          # regex | keyword | field_name | secret | edm | file_fingerprint
    category: str
    severity: str           # low | medium | high | critical
    action: Literal["allow", "audit", "mask", "block"]
    enabled: bool = True
    regex: Optional[str] = None
    keywords: Optional[List[str]] = None
    field_names: Optional[List[str]] = None
    scope: Dict[str, Any] = Field(default_factory=dict)
    # ：命中此规则的 finding 不允许被任何例外降级（私钥/凭证路径/恶意脚本/云元数据/内网高危）

    @field_validator("regex")
    @classmethod
    def normalize_regex(cls, value: Optional[str]) -> Optional[str]:
        """Strip boundary whitespace before compiling a cross-service rule."""
        return value.strip() if value is not None else None

    @field_validator("keywords", "field_names")
    @classmethod
    def normalize_literal_matchers(
        cls, value: Optional[List[str]]
    ) -> Optional[List[str]]:
        """Strip literal matchers and discard whitespace-only entries."""
        if value is None:
            return None
        return [normalized for item in value if (normalized := item.strip())]

    @model_validator(mode="after")
    def mask_requires_exact_value_span(self):
        if self.scope.get("redaction") is not None:
            from app.policy_bindings import RedactionSettings
            RedactionSettings.model_validate(self.scope["redaction"])
        if self.action == "mask" and self.rule_type != "regex":
            raise ValueError("mask action requires a regex matcher")
        return self


def is_safe_regex(pattern: str) -> bool:
    """编译期 ReDoS 防护：识别明显的灾难性回溯模式。

    引擎侧纵深防御；权威校验在 control-plane 编译期完成。
    保守策略：宁可跳过可疑规则，也不放行高风险正则。
    """
    if not pattern or len(pattern) > MAX_PATTERN_LEN:
        return False
    if _NESTED_QUANT.search(pattern) or _REPEATED_ALTERNATION.search(pattern):
        return False
    return True


def validate_and_compile_regex(
    pattern: str,
) -> Tuple[
    Optional[bounded_regex.Pattern],
    Optional[Literal["unsafe_regex", "invalid_syntax"]],
]:
    """Validate and compile a runtime regex without exposing compiler details.

    This is the single Python admission path used by both the live custom-rule
    loader and the internal validation endpoint.
    """
    if not is_safe_regex(pattern):
        return None, "unsafe_regex"
    try:
        return bounded_regex.compile(pattern), None
    except bounded_regex.error:
        return None, "invalid_syntax"


def redact_evidence(value: str, rule_type: str) -> str:
    """脱敏命中证据：密钥类全脱敏 + 哈希；其它类型保留首尾并附哈希指纹。

    始终不返回原始完整值，满足「evidence 脱敏/哈希」红线。
    """
    if not value:
        return ""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    if rule_type == "secret" or len(value) <= 4:
        return f"<REDACTED sha256:{digest}>"
    masked = value[:2] + "*" * max(2, len(value) - 4) + value[-2:]
    return f"{masked} (sha256:{digest})"


def runtime_failure_finding(
    rule: CompiledRule,
    reason: str,
    finding_type: str = "regex_timeout",
) -> SecurityFinding:
    """Return a content-free runtime failure with action-specific semantics.

    An incomplete scan is an inspection anomaly: it is recorded and never
    blocks (only an action configured as "block" may interrupt traffic). Mask
    rules additionally mark that masking could not be guaranteed.
    """
    evidence = f"<REDACTED {reason}>"
    if rule.action == "mask":
        category = (
            "custom_scan_incomplete"
            if finding_type == "custom_scan_incomplete"
            else "custom_regex_timeout"
        )
        return SecurityFinding(
            type=finding_type,
            category=category,
            severity="medium",
            evidence_kind="runtime",
            evidence_reason="脱敏扫描未完成，无法保证脱敏，已按原文放行并告警；不是已确认攻击",
            counts_as_security_finding=False,
            matched_text_preview=evidence,
            rule_id=rule.rule_id,
            confidence=1.0,
            rule_name=rule.rule_name,
            rule_type="regex",
            action="audit",
            matched_location="content[unavailable]",
            redacted_evidence=evidence,
            triage={"mask_unavailable": True, "reason": reason, "confidence_kind": "inspection_failure_fact"},
        )
    return SecurityFinding(
        type="engine_runtime",
        category="engine_scan_incomplete",
        severity="low",
        matched_text_preview=evidence,
        rule_id=rule.rule_id,
        confidence=1.0,
        rule_name=rule.rule_name,
        rule_type="regex",
        action="audit",
        counts_as_security_finding=False,
        matched_location="content[unavailable]",
        redacted_evidence=evidence,
        triage={"reason": reason},
    )


def _regex_match_value(rule: CompiledRule, match: Any) -> Tuple[str, Tuple[int, int]]:
    named_groups = match.groupdict()
    pii_shape = _PII_VALUE_SHAPES.get(_pii_match_kind(rule))
    if rule.rule_id == "rule_g_email" and named_groups.get("email_local") is not None:
        local = named_groups["email_local"]
        raw = local + match.group(0)
        start, end = match.span("email_local")[0], match.span(0)[1]
    elif pii_shape is not None and pii_shape.fullmatch(match.group(0)):
        # Province/year/IIN capture groups are regex structure, not the value
        # to validate or mask. A complete numeric match takes precedence.
        raw, (start, end) = match.group(0), match.span(0)
    elif match.groups() and match.group(1) is not None:
        raw, (start, end) = match.group(1), match.span(1)
    else:
        raw, (start, end) = match.group(0), match.span(0)
    return raw, (start, end)


_MAX_KEY_ONLY_SCAN = 200
# 第二遍只扫首处之后的这段区间。取舍：区间之外的真实值不再找（保留首处并降一档），
# 换来标准库 re 也能由区间长度界定耗时。
_KEY_ONLY_WINDOW = 256 * 1024


@dataclass
class _KeyOnlyCandidate:
    """首遍命中只有字段名：持有要替换的 finding 与重新取命中所需的上下文。"""
    finding: SecurityFinding
    rule: CompiledRule
    pattern: Any
    text: str            # pattern 实际扫描的文本（keyword 规则是归一化视图）
    scan: str            # 原文
    first: Any
    span_of: Any         # match -> 命中在原文里的 (start, end)
    view: Optional[NormalizedText] = None


def _key_only_candidate(
    finding: SecurityFinding, rule: CompiledRule, pattern: Any, text: str, scan: str, first: Any,
    view: Optional[NormalizedText] = None,
) -> Optional[_KeyOnlyCandidate]:
    if rule.action == "mask":
        return None  # mask 规则本就逐处命中，不需要选代表
    if view is not None:
        def span_of(match: Any) -> Tuple[int, int]:
            return view.source_span(*match.span())
    else:
        def span_of(match: Any) -> Tuple[int, int]:
            return _regex_match_value(rule, match)[1]
    start, end = span_of(first)
    if not match_is_key_only(scan, start, end):
        return None
    return _KeyOnlyCandidate(finding, rule, pattern, text, scan, first, span_of, view)


def _find_valued_match(candidate: _KeyOnlyCandidate, *, wall_deadline: float, cpu_deadline: float) -> Any:
    """首处只有字段名时，在首处之后 _KEY_ONLY_WINDOW 区间内找第一处带真实值的命中。

    - 只选 match_has_real_value 为真的命中：没有赋值号的单纯提及不算。
    - 只在所有规则首遍跑完后、用整包剩余预算调用；预算用尽则不扫，绝不影响任何规则的首遍。
    - 超时、预算用尽或任何扫描异常一律返回 first，处置（block 等）不变。
    - 找不到则返回 first（由证据降级压低告警级别）。
    - 取舍：区间之外的真实值不再找。此时首处会被降一档，原因文字“未见真实值”与事实不完全相符，
      换来的是第二遍耗时有界（标准库 re 也无法中途打断，只能靠区间长度限定）。
    """
    first = candidate.first
    kwargs: dict = {"pos": first.end(), "endpos": min(len(candidate.text), first.end() + _KEY_ONLY_WINDOW)}
    if candidate.rule.rule_type == "regex":  # 只有 regex 模块的 finditer 支持 timeout
        remaining = wall_deadline - time.monotonic()
        if remaining <= 0:
            return first
        kwargs["timeout"] = remaining
    try:
        # 200 处上限：区间内最多看这么多处命中，超过就放弃、保留首处（只是少降级，不丢命中）。
        for index, found in enumerate(candidate.pattern.finditer(candidate.text, **kwargs)):
            if index >= _MAX_KEY_ONLY_SCAN:
                break
            if time.monotonic() >= wall_deadline or time.thread_time() >= cpu_deadline:
                break
            start, end = candidate.span_of(found)
            if match_has_real_value(candidate.scan, start, end):
                return found
    except (TimeoutError, MemoryError, RecursionError):
        return first
    return first


def _overwrite_finding(target: SecurityFinding, source: SecurityFinding) -> None:
    for name in type(target).model_fields:
        setattr(target, name, getattr(source, name))


def finding_from_regex_match(
    rule: CompiledRule,
    match: Any,
) -> SecurityFinding:
    raw, (start, end) = _regex_match_value(rule, match)
    return _custom_finding(rule, raw, start, end)


def finding_from_keyword_match(
    rule: CompiledRule,
    match: Any,
    view: NormalizedText,
) -> SecurityFinding:
    """关键字在 keyword_view 上命中：证据取归一化后的命中词，位置映射回原文。"""
    start, end = view.source_span(*match.span())
    return _custom_finding(rule, match.group(0), start, end)


def _custom_finding(rule: CompiledRule, raw: str, start: int, end: int) -> SecurityFinding:
    evidence = redact_evidence(raw, rule.rule_type)
    return SecurityFinding(
        type="custom",
        category=rule.category,
        severity=rule.severity,
        matched_text_preview=evidence,
        rule_id=rule.rule_id,
        confidence=0.9,
        rule_name=rule.rule_name,
        rule_type=rule.rule_type,
        action=rule.action,
        matched_location=f"content[{start}:{end}]",
        redacted_evidence=evidence,
        raw_evidence=raw,
    )


class CustomRuleSet:
    """编译并持有一组自定义规则，对内容执行匹配。

    构造时即编译正则并做 ReDoS 防护：不安全或无法编译的规则进入 skipped，
    不影响其余规则（坏规则不拖垮整组）。
    """

    def __init__(self, rules: List[CompiledRule]):
        # Instance scoped: replacing a tenant's rule pack also discards its cache.
        # Retain only digests of complete, clean scans, never text or findings.
        self._clean_scans = OrderedDict()
        self._clean_scan_lock = threading.Lock()
        self.runtime_failure_counts: Counter[Tuple[str, str]] = Counter()
        self.active_rules: List[Tuple[CompiledRule, Any]] = []
        self.skipped: List[CompiledRule] = []
        for rule in rules:
            if not rule.enabled:
                continue
            if rule.rule_type == "regex":
                self._compile_regex(rule)
            elif rule.rule_type == "keyword":
                self._compile_keyword(rule)
            elif rule.rule_type == "field_name":
                self._compile_field_name(rule)
            else:
                # 其它类型（secret/edm/file_fingerprint）后续阶段实现
                self.skipped.append(rule)

    def _compile_regex(self, rule: CompiledRule) -> None:
        source = (
            RULE_G_EMAIL_REGEX if rule.rule_id == "rule_g_email" else rule.regex or ""
        )
        pattern, error_code = validate_and_compile_regex(source)
        if pattern is None:
            logger.warning("skip regex rule %s: %s", rule.rule_id, error_code)
            self.skipped.append(rule)
            return
        self.active_rules.append((rule, pattern))

    def _compile_keyword(self, rule: CompiledRule) -> None:
        # 关键词匹配器：把多个关键词合成为「转义后字面量」的择一正则，复用既有
        # active_rules 扫描 + redact_evidence 脱敏 + SecurityFinding 统一链路。
        # 字面量无 ReDoS 风险，故不套 is_safe_regex，仅 try/except 兜编译语法。
        # 关键字与正文做同样的归一化（NFKC、去零宽、折叠紧挨汉字的空白；英文单词间
        # 空格保留），在 keyword_view 上匹配，命中位置映射回原文。
        keywords = [normalized for k in (rule.keywords or []) if k and (normalized := normalize_keyword(k))]
        if not keywords:
            logger.warning("skip empty keyword rule %s", rule.rule_id)
            self.skipped.append(rule)
            return
        synthesized = "(?:" + "|".join(re.escape(k) for k in keywords) + ")"
        try:
            pattern = re.compile(synthesized, re.IGNORECASE)
        except re.error as exc:
            logger.warning("skip uncompilable keyword rule %s: %s", rule.rule_id, exc)
            self.skipped.append(rule)
            return
        self.active_rules.append((rule, pattern))

    def _compile_field_name(self, rule: CompiledRule) -> None:
        # 字段名匹配器：键检测——匹配 `字段名:` / `字段名=`（JSON "k":、表单 k=、
        # 散文 k: v）。前导 \b + 尾随可选引号 + 分隔符，避免 mypassword/passwordless
        # 等子串误报，区分 field_name=键 与 keyword=裸值。同样合成字面量正则。
        names = [n for n in (rule.field_names or []) if n]
        if not names:
            logger.warning("skip empty field_name rule %s", rule.rule_id)
            self.skipped.append(rule)
            return
        synthesized = r"\b(?:" + "|".join(re.escape(n) for n in names) + r")[\"']?\s*[:=]"
        try:
            pattern = re.compile(synthesized, re.IGNORECASE)
        except re.error as exc:
            logger.warning("skip uncompilable field_name rule %s: %s", rule.rule_id, exc)
            self.skipped.append(rule)
            return
        self.active_rules.append((rule, pattern))

    def _record_runtime_failure(
        self,
        rule: CompiledRule,
        reason: str,
        stats: Optional[AttemptStats] = None,
    ) -> None:
        key = (rule.rule_id, reason)
        self.runtime_failure_counts[key] += 1
        stats = stats or AttemptStats()
        # 新增字段只追加在行尾，保持既有字段顺序/格式。
        logger.warning(
            "regex runtime failure rule_id=%s reason=%s count=%d action=%s"
            " cpu_ms=%.1f wall_ms=%.1f retried=%d",
            rule.rule_id,
            reason,
            self.runtime_failure_counts[key],
            rule.action,
            stats.cpu_seconds * 1000.0,
            stats.wall_seconds * 1000.0,
            1 if stats.retried else 0,
        )

    def _run_regex_rule(
        self,
        rule: CompiledRule,
        pattern: Any,
        scan: str,
        pii_kind: Optional[str],
        numeric_metadata: Any,
        cpu_budget: float,
        wall_timeout: float,
    ) -> Tuple[str, Any]:
        """执行单条正则规则；可重复调用（重试时从头扫描）。

        返回 ("findings", list) / ("limit", None) / ("match", Match|None)。
        wall_timeout 传给 regex（墙钟）；cpu_budget 约束 Python 校验阶段的 CPU 时间。
        """
        if rule.action == "mask" or pii_kind or rule.category in PRECISE_CATALOG_CATEGORIES:
            rule_findings: List[SecurityFinding] = []
            cpu_deadline = time.thread_time() + cpu_budget
            # catalog 辅助校验使用墙钟 deadline，按放宽后的墙钟上限给出。
            candidate_deadline = time.monotonic() + wall_timeout
            for match in pattern.finditer(scan, timeout=wall_timeout):
                # regex's timeout does not bound Python validation
                # work between candidates. Keep both budgets bounded.
                if time.thread_time() >= cpu_deadline:
                    raise TimeoutError
                if not catalog_candidate_has_required_terms(
                    rule.category, match.group(0), deadline=candidate_deadline
                ):
                    continue
                if pii_kind:
                    raw, span = _regex_match_value(rule, match)
                    if pii_kind == "email":
                        if is_git_remote_reference(scan, *span):
                            continue
                        if rule.rule_id == "rule_g_email" and (
                            is_public_service_email(raw) or is_non_mailbox_at_reference(raw)
                        ):
                            continue
                    else:
                        if not is_complete_pii_token(scan, *span):
                            continue
                        if span in (numeric_metadata or ()):
                            continue
                        if pii_kind == "id_card_cn" and not validate_id_card_cn(raw):
                            continue
                        if pii_kind == "bank_card_cn" and not validate_bank_card(raw):
                            continue
                if len(rule_findings) >= MAX_REGEX_MASK_MATCHES:
                    return "limit", None
                rule_findings.append(finding_from_regex_match(rule, match))
                if rule.action != "mask":
                    break
            return "findings", rule_findings
        return "match", pattern.search(scan, timeout=wall_timeout)

    @staticmethod
    def _resolve_key_only_candidates(
        candidates: List[_KeyOnlyCandidate], rule_budget: float, pack_wall_deadline: float, pack_cpu_deadline: float,
    ) -> None:
        """第二遍：所有规则首遍跑完后，用整包剩余预算为“首处只有字段名”的命中选带真实值的代表。

        预算不够就跳过，保留首处（只是少降一档）。
        """
        for candidate in candidates:
            if time.monotonic() >= pack_wall_deadline or time.thread_time() >= pack_cpu_deadline:
                return
            better = _find_valued_match(
                candidate,
                wall_deadline=min(pack_wall_deadline, time.monotonic() + rule_budget),
                cpu_deadline=pack_cpu_deadline,
            )
            if better is candidate.first:
                continue
            replacement = (
                finding_from_keyword_match(candidate.rule, better, candidate.view) if candidate.view is not None
                else finding_from_regex_match(candidate.rule, better)
            )
            _overwrite_finding(candidate.finding, replacement)

    def match(self, content: str) -> List[SecurityFinding]:
        if not content or len(content) > MAX_SCAN_LEN:
            return self._match_uncached(content)
        digest = hashlib.sha256(content.encode('utf-8')).digest()
        now = time.monotonic()
        with self._clean_scan_lock:
            expires = self._clean_scans.get(digest, 0)
            if expires > now:
                self._clean_scans.move_to_end(digest)
                return []
            self._clean_scans.pop(digest, None)
        findings = self._match_uncached(content)
        if not findings:
            with self._clean_scan_lock:
                self._clean_scans[digest] = time.monotonic() + 30.0
                self._clean_scans.move_to_end(digest)
                while len(self._clean_scans) > 256:
                    self._clean_scans.popitem(last=False)
        return findings

    def _match_uncached(self, content: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        if not content:
            return findings
        if len(content) > MAX_SCAN_LEN:
            if not self.active_rules:
                return findings
            guard_rule = next(
                (rule for rule, _pattern in self.active_rules if rule.action == "mask"),
                self.active_rules[0][0],
            )
            return [
                runtime_failure_finding(
                    guard_rule,
                    "custom_scan_limit",
                    finding_type="custom_scan_incomplete",
                )
            ]
        scan = content
        # A 10 MiB accepted message cannot use the same budget as a short prompt.
        # Scale bounded work by size, retaining strict per-rule and pack ceilings.
        size_factor = min(20, max(1, (len(scan) + 65535) // 65536))
        rule_budget = min(MAX_REGEX_MATCH_CEILING_SECONDS, MAX_REGEX_MATCH_SECONDS * size_factor)
        pack_budget = min(MAX_REGEX_RULESET_CEILING_SECONDS, MAX_REGEX_RULESET_SECONDS * size_factor)
        # 预算按本线程 CPU 时间记账：等 GIL 不消耗预算。
        pack_cpu_start = time.thread_time()
        # 整包墙钟上限：到顶后未跑的规则记 regex_budget_exhausted，已在跑的不打断。
        pack_wall_start = time.monotonic()
        pack_wall_max = env_float("SECURITY_CUSTOM_REGEX_PACK_WALL_MAX_SECONDS", 3.0, 0.1, 30.0)
        # 熔断：同一次 match 中任一规则重试后仍失败，其余规则不再重试。
        retry_enabled = True
        numeric_metadata = None
        keyword_scan: Optional[NormalizedText] = None
        # 预算紧张时可执行（block/mask）规则先拿预算：一条重的 audit 规则不能把
        # 后面的拦截/脱敏规则挤成 regex_budget_exhausted。只改执行顺序，产出仍按
        # 规则包原序拼接，预算充足时结果与原先逐条一致。
        per_rule: List[List[SecurityFinding]] = [[] for _ in self.active_rules]
        execution_order = sorted(
            range(len(self.active_rules)),
            key=lambda index: (0 if self.active_rules[index][0].action in _ENFORCING_ACTIONS else 1, index),
        )
        pack_wall_deadline = pack_wall_start + pack_wall_max
        pack_cpu_deadline = pack_cpu_start + pack_budget
        candidates: List[_KeyOnlyCandidate] = []

        for index in execution_order:
            rule, pattern = self.active_rules[index]
            out = per_rule[index]
            if rule.rule_type == "regex":
                pack_used = time.thread_time() - pack_cpu_start
                remaining = pack_budget - pack_used
                pack_wall_used = time.monotonic() - pack_wall_start
                if remaining <= 0 or pack_wall_used >= pack_wall_max:
                    exhausted = AttemptStats(cpu_seconds=pack_used, wall_seconds=pack_wall_used)
                    self._record_runtime_failure(rule, "regex_budget_exhausted", exhausted)
                    out.append(runtime_failure_finding(rule, "regex_budget_exhausted"))
                    continue
                pii_kind = _pii_match_kind(rule)
                if pii_kind in {"phone_cn", "bank_card_cn"} and numeric_metadata is None:
                    numeric_metadata = non_pii_numeric_spans(scan)
                stats = AttemptStats()
                try:
                    kind, payload = run_with_cpu_budget(
                        lambda cpu_budget, wall_timeout: self._run_regex_rule(
                            rule, pattern, scan, pii_kind, numeric_metadata,
                            cpu_budget, wall_timeout,
                        ),
                        min(rule_budget, remaining),
                        stats,
                        allow_retry=retry_enabled,
                    )
                except TimeoutError:
                    if stats.retried:
                        retry_enabled = False
                    self._record_runtime_failure(rule, "regex_timeout", stats)
                    out.append(runtime_failure_finding(rule, "regex_timeout"))
                    continue
                if kind == "limit":
                    self._record_runtime_failure(rule, "regex_match_limit", stats)
                    out.append(runtime_failure_finding(rule, "regex_match_limit"))
                    continue
                if kind == "findings":
                    out.extend(payload)
                    continue
                m = payload
            elif rule.rule_type == "keyword":
                if keyword_scan is None:
                    keyword_scan = keyword_view(scan)
                m = pattern.search(keyword_scan.text)
                if m:
                    finding = finding_from_keyword_match(rule, m, keyword_scan)
                    out.append(finding)
                    candidate = _key_only_candidate(finding, rule, pattern, keyword_scan.text, scan, m, keyword_scan)
                    if candidate:
                        candidates.append(candidate)
                continue
            else:
                m = pattern.search(scan)
            if not m:
                continue
            finding = finding_from_regex_match(rule, m)
            out.append(finding)
            candidate = _key_only_candidate(finding, rule, pattern, scan, scan, m)
            if candidate:
                candidates.append(candidate)
        self._resolve_key_only_candidates(
            candidates, rule_budget, pack_wall_start + pack_wall_max, pack_cpu_start + pack_budget,
        )
        for rule_findings in per_rule:
            findings.extend(rule_findings)
        return findings


# 例外（误报豁免）动作降级排序：例外只能放松（降级），不能收紧（升级）
_ACTION_RANK = {"allow": 0, "audit": 1, "alert": 1, "mask": 2, "block": 3, "quarantine": 3}


# 改名后带后缀的规则编号：例外写旧编号时按别名对全部带后缀的编号生效，已建例外不失效。
# 文件类型“禁止”命中自 2.9.22 起带类型（file-policy-blocked-type:exe，见 file_inspector）。
_LEGACY_RULE_ID_PREFIXES = {"file-policy-blocked-type": "file-policy-blocked-type:"}


def _exception_rule_matches(exception_rule_id: str, finding: SecurityFinding) -> bool:
    finding_rule_ids = {rule_id for rule_id in (finding.rule_id, finding.source_rule_id) if rule_id}
    if exception_rule_id in finding_rule_ids:
        return True
    prefix = _LEGACY_RULE_ID_PREFIXES.get(exception_rule_id)
    return bool(prefix) and any(rule_id.startswith(prefix) for rule_id in finding_rule_ids)


class CompiledException(BaseModel):
    """规则包中的单条例外（control-plane 编译产物的引擎侧映射）。

    例外用于客户复核确认的误报豁免：把命中 finding 的动作降级（block→audit/allow），
    finding 仍保留并标注 exception_id，供安全事件展示「已豁免」，绝不丢弃。

    红线： finding（=True）永不被例外降级，即便例外精确指向其 rule_id。
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    exception_id: str
    scope_type: str = "tenant"
    scope_ref: str = ""
    include_children: bool = False
    rule_id: str = ""            # 指定则按 rule_id 精确匹配；为空且 scope_type=tenant 则 catch-all
    decision: str = "audit"      # 仅接受 allow / audit（编译期已校验，引擎侧再兜底）
    reason: str = ""
    expires_at: str = ""         # RFC3339；空值表示永久

    def expiry_time(self) -> Optional[datetime]:
        if not self.expires_at:
            return None
        value = self.expires_at.strip()
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError("exception expires_at must be RFC3339") from exc
        if parsed.tzinfo is None:
            raise ValueError("exception expires_at must include a timezone")
        return parsed.astimezone(timezone.utc)


class ExceptionSet:
    """持有一组内容例外，对 findings 执行运行期降级（纵深防御第 2 层）。

    scope 闸（先判该例外在当前请求上下文是否"在作用域内"）：
    - scope_type=project：须调用方透传 project_id 且 scope_ref==project_id；
    - scope_type=user：须调用方透传 user_id 且 scope_ref==user_id；
    - scope_type=key_v1：仅匹配 PrincipalContext 中的稳定 key_id；
    - scope_type=actor_department_v1：仅匹配 authenticated actor 的部门；
      include_children=true 时才匹配其祖先部门；
    - 未知 scope：始终不匹配（失败关闭）。

    rule 闸（作用域内再判是否命中该 finding）：
    - exc.rule_id 非空：仅命中 rule_id 完全一致的 finding（作用域不限）；
    - exc.rule_id 为空且 scope_type 为资源/主体 scope：该作用域内 catch-all；
    - 其它（无 rule_id 且非上述作用域）：不匹配。

    rule_id 精确例外与资源/主体作用域例外可降级 builtin/custom/file finding；
    租户级广域 catch-all 仍只作用 custom/file。project/user 沿用旧 context
    字段；版本化 Key/actor 部门 scope 只消费 PrincipalContext，并要求可信级别
    与 tenant 一致。任一所需上下文缺失时均不生效。
    """

    def __init__(self, exceptions: List[CompiledException]):
        self.exceptions: List[CompiledException] = list(exceptions or [])
        self._entries = []
        for exception in self.exceptions:
            try:
                expires_at = exception.expiry_time()
            except ValueError:
                expires_at = datetime.min.replace(tzinfo=timezone.utc)
            self._entries.append((exception, expires_at))

    def _match(
        self,
        finding: SecurityFinding,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
        principal: Optional[PrincipalContext] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[CompiledException]:
        now = datetime.now(timezone.utc)
        for exc, expires_at in self._entries:
            if expires_at is not None and expires_at <= now:
                continue
            if exc.scope_type not in {
                "tenant",
                "project",
                "user",
                "rule",
                "key_v1",
                "actor_department_v1",
            }:
                continue
            # scope 闸：确定该例外在当前请求上下文是否"在作用域内"
            if exc.scope_type == "project":
                if not (project_id and exc.scope_ref == project_id):
                    continue
            elif exc.scope_type == "user":
                if not (user_id and exc.scope_ref == user_id):
                    continue
            elif exc.scope_type == "key_v1":
                if not (
                    principal is not None
                    and tenant_id
                    and principal.tenant_id == tenant_id
                    and principal.trust_level in {"key_bound", "authenticated"}
                    and principal.key_id
                    and exc.scope_ref == principal.key_id
                ):
                    continue
            elif exc.scope_type == "actor_department_v1":
                if not (
                    principal is not None
                    and tenant_id
                    and principal.tenant_id == tenant_id
                    and principal.trust_level == "authenticated"
                    and principal.actor_user_id
                ):
                    continue
                direct_match = exc.scope_ref in principal.actor_department_ids
                descendant_match = (
                    exc.include_children
                    and exc.scope_ref in principal.actor_department_ancestor_ids
                )
                if not (direct_match or descendant_match):
                    continue
            # tenant/rule 及通过上下文校验的 scope 进入 rule 闸。
            # 有 rule_id 则须精确匹配；无 rule_id 仅资源/主体 scope 视为 catch-all。
            if exc.rule_id:
                if _exception_rule_matches(exc.rule_id, finding):
                    return exc
                continue
            if exc.scope_type in {
                "tenant",
                "project",
                "user",
                "key_v1",
                "actor_department_v1",
            }:
                return exc
        return None

    def apply(
        self,
        findings: List[SecurityFinding],
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
        principal: Optional[PrincipalContext] = None,
        tenant_id: Optional[str] = None,
    ) -> List[SecurityFinding]:
        if not self.exceptions:
            return findings
        for f in findings:
            # (1) 管理员建的例外一律生效（2.9.22 设计 D1）：凭据、证件号等“不可降级”
            #     只约束引擎的自动降级（编码流量降级、AI 复核、证据降级），不约束例外。
            # (2) 不碰 llm_judge 影子意见
            if f.type == "llm_judge":
                continue
            exc = self._match(
                f,
                project_id,
                user_id,
                principal,
                tenant_id,
            )
            if exc is None:
                continue
            # (3) 类型闸：仅"租户级广域 catch-all（无 rule_id）"保持 custom/file，
            #     避免一条广域例外降级整租户内置检测；rule_id 精确例外与
            #     资源/主体作用域例外均可作用于 builtin（P1-A 误报闭环）。
            if not exc.rule_id and exc.scope_type == "tenant" and f.type not in {"custom", "file"}:
                continue
            # (4) 引擎侧兜底：例外 decision 只接受 allow / audit
            if exc.decision not in {"allow", "audit"}:
                continue
            # (5) custom/file：只放松不收紧（严格低于才改）；builtin（初始 action 空）：命中例外即写入放松动作，
            #     供 _raw_action 的 _exempt 识别（decision 已限 allow/audit，不会收紧）。
            current_rank = _ACTION_RANK.get(f.action, 0) if f.action else _ACTION_RANK["block"]
            if _ACTION_RANK.get(exc.decision, 0) < current_rank:
                f.action = exc.decision
            # 命中例外即标注（即便未改动 action），供安全事件展示「已豁免」
            f.exception_id = exc.exception_id
        return findings
