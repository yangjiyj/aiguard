"""告警级别的证据降级：只降不升，每次降级写明原因。

告警级别默认等于命中策略的级别（见 PolicySet.apply）。证据明显变弱时降一档：
1. 凭据类命中只有字段名，赋值号后是空值、变量引用或占位符；
2. AI 复核判定为疑似误报。
示例、文档和防御性引用已由检测器标为 observation（不计入告警），这里不重复处理。
已由检测器主动降过级（带 severity_downgrade_reason）的命中不再降。
"""
from __future__ import annotations

import re
from typing import List, Optional

SEVERITY_ORDER = ("low", "medium", "high", "critical")
SEVERITY_INDEX = {level: index for index, level in enumerate(SEVERITY_ORDER)}
KEY_ONLY_REASON = "只命中字段名，未见真实值"
TRIAGE_REASON = "AI 复核判定为疑似误报"
AI_REVIEW_ELIGIBLE_MARK = "ai_review_downgrade_eligible"
EVIDENCE_REASONS = frozenset({KEY_ONLY_REASON, TRIAGE_REASON})
KEY_ONLY_MARK = "credential_key_only"

# 左边界：字母数字紧贴在前面时不算字段名（bypass、compass），下划线前缀（DB_PASSWORD）与驼峰（dbPassword）算。
_CREDENTIAL_KEY = re.compile(
    r"(?:(?<![A-Za-z0-9])|(?<=[a-z])(?=[A-Z]))"
    r"(?i:pass(?:word|wd)?|pwd|secret(?:[_ -]?key)?|token|api[_ -]?key|access[_ -]?key(?:[_ -]?id)?|"
    r"private[_ -]?key|credential|aws[_ -]?secret)[\"']?[ \t]*[=:：]?[ \t]*$"
)
_SEPARATOR_AFTER = re.compile(r"^[\"']?[ \t]*[=:：]")
_ASSIGNMENT_VALUE = re.compile(r"^[\"']?[ \t]*[=:：]?[ \t]*[\"']?(?P<value>[^\s\"',;]*)")
_VARIABLE_REF = re.compile(
    r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%|\{\{.*|os\.environ.*|os\.getenv.*|"
    r"process\.env\..*|getenv\(.*|env\(.*)$"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:|changeme|change_me|example|placeholder|redacted|<.*|\*+|x{3,}|your[_-].*|.*_here|null|none|todo|\.\.\.)$"
)
_CONTENT_SPAN = re.compile(r"^content\[(\d+):(\d+)\]$")
_VALUE_WINDOW = 64


def _lower(severity: str) -> str:
    if severity not in SEVERITY_INDEX:
        return severity
    return SEVERITY_ORDER[max(SEVERITY_INDEX[severity] - 1, 0)]


def _assignment_value(matched: str, following: str):
    """matched 是单行、以凭据字段名（可带赋值号）结尾，且有赋值号时，返回赋值号后的值；否则返回 None。"""
    matched = matched or ""
    if "\n" in matched or "\r" in matched:
        return None  # 多行命中里可能夹着真实值，不判定
    if not _CREDENTIAL_KEY.search(matched):
        return None
    following = following or ""
    if not re.search(r"[=:：]", matched[-8:]) and not _SEPARATOR_AFTER.match(following):
        return None  # 没有赋值号，只是文中提到字段名
    m = _ASSIGNMENT_VALUE.match(following)
    return (m.group("value") if m else "").strip()


def _is_empty_or_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.match(value) or _VARIABLE_REF.match(value))


def assignment_value(matched: str, following: str) -> Optional[str]:
    """公开入口：matched 以凭据字段名（可带赋值号）结尾时返回赋值号后的值，否则返回 None。"""
    return _assignment_value(matched, following)


def credential_value_is_absent(matched: str, following: str) -> bool:
    """matched 以凭据字段名加赋值号结尾，且 following 开头的值为空、变量引用或占位符。"""
    value = _assignment_value(matched, following)
    return value is not None and _is_empty_or_placeholder(value)


def credential_value_is_present(matched: str, following: str) -> bool:
    """matched 以凭据字段名加赋值号结尾，且 following 开头有真实值（非空、非变量引用、非占位符）。"""
    value = _assignment_value(matched, following)
    return value is not None and not _is_empty_or_placeholder(value)


def match_is_key_only(content: str, start: int, end: int) -> bool:
    """content[start:end] 是只有字段名的凭据命中：赋值号后是空值、变量引用或占位符。"""
    if not content or not (0 <= start < end <= len(content)):
        return False
    return credential_value_is_absent(content[start:end], content[end:end + _VALUE_WINDOW])


def match_has_real_value(content: str, start: int, end: int) -> bool:
    """正向判断：content[start:end] 是凭据字段名加赋值号，且赋值号后有真实值。单纯提及字段名不算。"""
    if not content or not (0 <= start < end <= len(content)):
        return False
    return credential_value_is_present(content[start:end], content[end:end + _VALUE_WINDOW])


def annotate_key_only_findings(findings: List, content: str) -> List:
    """在原文上判定“只有字段名”，结果写进 triage 标记，使 raw_findings 与缓存重放无需原文。"""
    for finding in findings:
        matched = finding.raw_evidence or ""
        span = _CONTENT_SPAN.match(finding.matched_location or "")
        if not matched or not span:
            continue
        start, end = int(span.group(1)), int(span.group(2))
        if end > len(content or "") or content[start:end] != matched:
            continue
        if match_is_key_only(content, start, end):
            finding.triage = {**finding.triage, KEY_ONLY_MARK: True}
    return findings


def severity_for_action(finding) -> str:
    """处置动作按策略配置：证据降级压低的告警级别，动作判断时取降级前的级别。"""
    triage = finding.triage or {}
    if triage.get("severity_downgrade_reason") in EVIDENCE_REASONS:
        before = triage.get("severity_before_downgrade")
        if before in SEVERITY_INDEX:
            return before
    return finding.severity


def _downgrade_reason(finding) -> str:
    triage = finding.triage
    if triage.get(KEY_ONLY_MARK) is True:
        return KEY_ONLY_REASON
    # AI 复核降级只作用于重放必返回 409 的命中（标记由引擎按同一条件写入），保证直连与重放一致。
    if triage.get(AI_REVIEW_ELIGIBLE_MARK) is True and "likely_false_positive" in (
        triage.get("verdict"), triage.get("advisory_verdict"),
    ):
        return TRIAGE_REASON
    return ""


def apply_evidence_downgrades(findings: List) -> List:
    """判定只看 triage 标记（字段名、AI 复核资格）与复核结论，不再读原文。"""
    for finding in findings:
        if not finding.counts_as_security_finding or finding.cannot_downgrade():
            continue
        if finding.triage.get("severity_downgrade_reason"):
            continue
        reason = _downgrade_reason(finding)
        lowered = _lower(finding.severity)
        if not reason or lowered == finding.severity:
            continue
        finding.triage = {**finding.triage, "severity_downgrade_reason": reason,
                          "severity_before_downgrade": finding.severity}
        finding.severity = lowered
    return findings
