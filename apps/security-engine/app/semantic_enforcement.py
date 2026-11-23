"""语义裁判拦截闸门：拦不拦只由控制台策略的「智能分析命中时」决定。

策略选「拦截」后，语义 finding 只有同时满足以下条件才保留 block：
- 所在阶段在控制台「智能分析拦截阶段」里（semantic_block_stages，缺省只输入；输出侧语义不运行）；
- 本次请求语义分析 completed（任一窗口超时/容量饱和/不可用即视为未完成）；
- 裁判自身置信度 >= semantic_block_min_confidence（控制台语义设置，默认 0.85）；
- 防护模式（security_audit_only=false）。
任一不满足降为记录并告警，原因写进 finding（triage + evidence_reason）。
裁判故障一律 fail-open：只在已配置拦截时给运行遥测补一句「放行」说明，绝不拦业务。
"""
from __future__ import annotations

import math
from typing import Any, List

SEMANTIC_JUDGE_CATEGORIES = frozenset({
    "semantic_jailbreak",
    "semantic_roleplay",
    "semantic_instruction_override",
    "semantic_exfil_induce",
    "semantic_harassment",
    "semantic_threat",
    "semantic_hate",
})
# 上下文裁判（jjdguard-context-judge-v1，input_contract=context-v1）只判 attack/normal，
# 不给细分类别；引擎统一映射为该类别、置信度固定 0.9（confidence_basis=policy_mapping_not_probability）。
# 它的结论视为同时命中全部语义裁判能力：页面上绑定任一语义能力并选拦截即可拦截它。
SEMANTIC_CONTEXT_CATEGORY = "prompt_input_semantic_risk"
DEFAULT_SEMANTIC_BLOCK_MIN_CONFIDENCE = 0.85
SEMANTIC_BLOCK_MIN_CONFIDENCE_RANGE = (0.5, 1.0)
SEMANTIC_RUN_STATUS_KEY = "semantic_run_status"

_CATEGORY_CN = {
    "semantic_jailbreak": "语义越狱",
    "semantic_roleplay": "角色扮演绕过",
    "semantic_instruction_override": "指令覆盖",
    "semantic_exfil_induce": "数据外泄诱导",
    "semantic_harassment": "语义骚扰",
    "semantic_threat": "语义威胁",
    "semantic_hate": "语义仇恨",
    SEMANTIC_CONTEXT_CATEGORY: "上下文语义攻击",
}
_FAIL_OPEN_NOTES = {
    "semantic_timeout": "分析超时放行",
    "semantic_capacity_overflow": "分析容量饱和放行",
    "semantic_unavailable": "分析不可用放行",
}


def normalize_block_min_confidence(raw: Any) -> float:
    """非法或越界的阈值一律回到默认值，绝不因为配置错把阈值放宽。"""
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_SEMANTIC_BLOCK_MIN_CONFIDENCE
    low, high = SEMANTIC_BLOCK_MIN_CONFIDENCE_RANGE
    if not math.isfinite(value) or not low <= value <= high:
        return DEFAULT_SEMANTIC_BLOCK_MIN_CONFIDENCE
    return value


def is_context_judge_verdict(finding) -> bool:
    """上下文裁判给出的攻击结论；Tier-1 快速分类同名类别的输出不算（它不是裁判结论）。"""
    triage = getattr(finding, "triage", None) or {}
    return (
        getattr(finding, "type", "") == "semantic_attack"
        and getattr(finding, "category", "") == SEMANTIC_CONTEXT_CATEGORY
        and triage.get("source") != "tier1"
    )


def policy_match_categories(finding) -> frozenset:
    """策略绑定时该 finding 可命中的能力类别。"""
    category = getattr(finding, "category", "")
    if is_context_judge_verdict(finding):
        return frozenset({category}) | SEMANTIC_JUDGE_CATEGORIES
    return frozenset({category})


def _finite_confidence(value):
    """裁判置信度只接受有限实数；NaN/inf/None/字符串一律视为无效（绝不能被当作达到阈值）。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _enforceable(finding) -> bool:
    return finding.category in SEMANTIC_JUDGE_CATEGORIES or is_context_judge_verdict(finding)


def stamp_semantic_run_status(findings, status: str, reason: str) -> None:
    """把整次请求的语义完成度写进语义 finding，指纹缓存重放时据此判断能否拦截。"""
    for finding in findings:
        if getattr(finding, "type", "") == "semantic_attack":
            finding.triage = {
                **finding.triage,
                SEMANTIC_RUN_STATUS_KEY: status,
                **({"semantic_run_reason": reason} if reason else {}),
            }


def _append_reason(finding, note: str) -> None:
    if note not in (finding.evidence_reason or ""):
        finding.evidence_reason = (
            (finding.evidence_reason + "；") if finding.evidence_reason else ""
        ) + note


def _block_requested(policies, principal, stage: str) -> bool:
    for policy in getattr(policies, "policies", ()):
        if not policy.enabled or getattr(policy, "semantic_action", "audit") != "block":
            continue
        if policy.subject_binding is not None and not policy.subject_binding.matches(principal):
            continue
        if any(cap.category in SEMANTIC_JUDGE_CATEGORIES or cap.category == SEMANTIC_CONTEXT_CATEGORY
               for cap in policy.stage_capabilities(stage)):
            return True
    return False


_STAGE_CN = {"input": "输入", "agent": "智能体", "output": "输出"}


def _downgrade_reason(finding, *, stage: str, audit_only: bool, threshold: float,
                      block_stages=frozenset({"input"})):
    status = str(finding.triage.get(SEMANTIC_RUN_STATUS_KEY) or "")
    if stage not in block_stages:
        return ("stage_not_enabled",
                f"智能分析拦截未对{_STAGE_CN.get(stage, stage)}阶段开启，本次记录并告警")
    if not _enforceable(finding):
        return "category_not_enforceable", "该语义类别不支持拦截，本次记录并告警"
    if status != "completed":
        detail = str(finding.triage.get("semantic_run_reason") or status or "unknown")
        return "semantic_incomplete", f"分析未完成（{detail}），按放行处理并记录告警"
    if audit_only:
        return "not_protect_mode", "非防护模式，智能分析命中只记录并告警"
    confidence = _finite_confidence(getattr(finding, "confidence", None))
    if confidence is None:
        return ("confidence_invalid",
                f"置信度无效（{getattr(finding, 'confidence', None)!r}），不能判断是否达到阈值，记录并告警")
    if confidence < threshold:
        note = f"置信度低于阈值（{confidence:.2f} < {threshold:.2f}），记录并告警"
        if finding.triage.get("confidence_basis") == "policy_mapping_not_probability":
            note += (f"；上下文裁判置信度为固定映射值 {confidence:.1f}，不是概率，"
                     "阈值不高于该值才会拦截")
        return "confidence_below_threshold", note
    return None


def apply_semantic_enforcement(findings: List[Any], *, policies, principal, stage: str,
                               runtime) -> List[Any]:
    """只降不升：策略要求拦截的语义 finding 不满足安全条件时降为 audit。"""
    threshold = normalize_block_min_confidence(
        getattr(runtime, "semantic_block_min_confidence", DEFAULT_SEMANTIC_BLOCK_MIN_CONFIDENCE)
    )
    audit_only = bool(getattr(runtime, "audit_only", True))
    block_stages = getattr(runtime, "semantic_block_stages", None) or frozenset({"input"})
    block_requested = None
    for finding in findings:
        kind = getattr(finding, "type", "")
        if kind == "semantic_telemetry":
            if block_requested is None:
                block_requested = _block_requested(policies, principal, stage)
            note = _FAIL_OPEN_NOTES.get(finding.category)
            if block_requested and note:
                finding.triage = {**finding.triage, "semantic_enforcement": "fail_open"}
                _append_reason(finding, f"已配置智能分析拦截，{note}（fail-open）")
            continue
        if (kind != "semantic_attack" or (finding.action or "").lower() != "block"
                or getattr(finding, "counts_as_security_finding", True) is False):
            # 已被后续环节降为观察的意见不参与决策，也不能被标成「已拦截」。
            continue
        downgrade = _downgrade_reason(finding, stage=stage, audit_only=audit_only,
                                      threshold=threshold, block_stages=block_stages)
        confidence = _finite_confidence(getattr(finding, "confidence", None))
        common = {
            "semantic_category": finding.category,
            # 无效置信度记为 None（JSON null），不把 NaN 写进事件
            "semantic_confidence": round(confidence, 4) if confidence is not None else None,
            "semantic_block_min_confidence": threshold,
        }
        if downgrade is None:
            finding.triage = {**finding.triage, **common, "semantic_enforcement": "blocked"}
            cn = _CATEGORY_CN.get(finding.category, finding.category)
            _append_reason(
                finding,
                f"智能分析高置信拦截：{cn}，置信度 {confidence:.2f} ≥ 阈值 {threshold:.2f}",
            )
            continue
        code, note = downgrade
        finding.action = "audit"
        finding.triage = {
            **finding.triage, **common,
            "semantic_enforcement": "downgraded",
            "semantic_enforcement_reason": code,
        }
        _append_reason(finding, note)
    return findings
