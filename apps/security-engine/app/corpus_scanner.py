"""训练语料扫描：只组合敏感数据类检测器，给出命中位置和替换后的文本。

规格第 5.3 节：
- 只跑内置个人信息、密钥、sensitive_data、data_leak，以及租户自定义规则里的正则规则；
  不跑注入、越狱、内容安全、语义和隐写，也不走策略、例外和误报压制。
- 同一个值出现多次时全部替换。不用 `_dedupe_findings`（它会丢掉重复位置），只做重叠合并。
- 不用 `_mask_content`（它受策略驱动）；替换文本固定为 `[类型中文名]`。
- 结果只含类型、中文名、字符下标和严重度，不含原值和上下文。
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass

from app.corpus_labels import FALLBACK_LABEL, corpus_label
from app.custom_rules import CustomRuleSet
from app.detectors.encoded_content import lexical_text
from app.detectors.engine import SecurityFinding, engine

_LOCATION = re.compile(r"content\[(\d+):(\d+)\]")
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_LABEL_UNSAFE = re.compile(r"[\[\]\r\n\t\x00-\x1f]")
_MAX_LABEL_CHARS = 40


@dataclass
class CorpusSpan:
    start: int
    end: int
    type: str
    label: str
    severity: str

    def as_dict(self) -> dict:
        return {"type": self.type, "label": self.label, "start": self.start,
                "end": self.end, "severity": self.severity}


@dataclass
class CorpusItemResult:
    spans: list[CorpusSpan]
    masked_text: str
    incomplete: bool


_rule_set_lock = threading.Lock()
_rule_set_cache: tuple[object, CustomRuleSet] | None = None


def corpus_rule_set(custom_rules) -> CustomRuleSet:
    """把租户规则包里的正则规则改成「报告全部命中」后重新编译。

    运行时规则只有 action=mask 时才逐个收集命中，其余动作只报第一处；语料副本需要全部位置，
    所以这里把动作统一视为 mask。关键词、字段名规则不参与（规格只用正则类）。
    结果按规则包对象缓存，规则包热更新后自动重建。
    """
    global _rule_set_cache
    with _rule_set_lock:
        if _rule_set_cache is not None and _rule_set_cache[0] is custom_rules:
            return _rule_set_cache[1]
    rules = [
        rule.model_copy(update={"action": "mask"})
        for rule, _pattern in getattr(custom_rules, "active_rules", [])
        if rule.rule_type == "regex"
    ]
    derived = CustomRuleSet(rules)
    with _rule_set_lock:
        _rule_set_cache = (custom_rules, derived)
    return derived


def _span(finding: SecurityFinding) -> tuple[int, int] | None:
    match = _LOCATION.fullmatch(finding.matched_location or "")
    if not match:
        return None
    start, end = int(match.group(1)), int(match.group(2))
    return (start, end) if end > start else None


def _custom_label(finding: SecurityFinding) -> str:
    name = _LABEL_UNSAFE.sub("", finding.rule_name or "").strip()[:_MAX_LABEL_CHARS]
    if name:
        return name
    label = corpus_label(finding.category)
    return label or FALLBACK_LABEL


def _is_ascii_word(char: str) -> bool:
    return char.isascii() and (char.isalnum() or char == "_")


def _expand_repeats(text: str, spans: list[CorpusSpan]) -> list[CorpusSpan]:
    """补上同一个值的其余出现位置（data_leak 等检测器每条规则只报第一处）。

    值以 ASCII 字母数字开头或结尾时要求边界也不是 ASCII 字母数字，避免把手机号替换进更长的数字串。
    """
    seen = {(span.start, span.end) for span in spans}
    extra: list[CorpusSpan] = []
    values: dict[str, CorpusSpan] = {}
    for span in spans:
        values.setdefault(text[span.start:span.end], span)
    for value, template in values.items():
        if len(value) < 2:
            continue
        check_left = _is_ascii_word(value[0])
        check_right = _is_ascii_word(value[-1])
        position = text.find(value)
        while position >= 0:
            end = position + len(value)
            left_ok = not check_left or position == 0 or not _is_ascii_word(text[position - 1])
            right_ok = not check_right or end == len(text) or not _is_ascii_word(text[end])
            if left_ok and right_ok and (position, end) not in seen:
                seen.add((position, end))
                extra.append(CorpusSpan(position, end, template.type, template.label, template.severity))
            position = text.find(value, position + 1)
    return spans + extra


def _merge_overlaps(spans: list[CorpusSpan]) -> list[CorpusSpan]:
    """重叠的命中合并成一处替换；类型取严重度最高者，同级取更长的那条。"""
    merged: list[tuple[CorpusSpan, CorpusSpan]] = []  # (合并后的区间, 决定类型的命中)
    for span in sorted(spans, key=lambda item: (item.start, -item.end)):
        if merged and span.start < merged[-1][0].end:
            current, winner = merged[-1]
            current.end = max(current.end, span.end)
            if (_SEVERITY_RANK.get(span.severity, 0), span.end - span.start) > (
                _SEVERITY_RANK.get(winner.severity, 0), winner.end - winner.start
            ):
                winner = span
            merged[-1] = (current, winner)
            continue
        merged.append((CorpusSpan(span.start, span.end, span.type, span.label, span.severity), span))
    result = []
    for current, winner in merged:
        severity = max((current.severity, winner.severity), key=lambda value: _SEVERITY_RANK.get(value, 0))
        result.append(CorpusSpan(current.start, current.end, winner.type, winner.label, severity))
    return result


def scan_item(text: str, custom_rules) -> CorpusItemResult:
    view = lexical_text(text)
    builtin: list[SecurityFinding] = []
    builtin.extend(engine._detect_regex_pii(view))
    builtin.extend(engine._detect_secrets(view))
    builtin.extend(engine._dict_findings_to_objects(engine.sensitive_data.detect(view)))
    builtin.extend(engine._dict_findings_to_objects(engine.data_leak.detect(view)))

    spans: list[CorpusSpan] = []
    for finding in builtin:
        location = _span(finding)
        if location is None:
            continue
        spans.append(CorpusSpan(location[0], location[1], finding.category,
                                corpus_label(finding.category), finding.severity))

    incomplete = False
    if text:
        custom = engine._filter_invalid_builtin_rule_pii(corpus_rule_set(custom_rules).match(text), text)
        for finding in custom:
            if finding.matched_location == "content[unavailable]" or not finding.counts_as_security_finding:
                # 自定义规则超时、超出命中上限或扫描长度上限：这一条没有扫完整。
                incomplete = True
                continue
            location = _span(finding)
            if location is None:
                continue
            spans.append(CorpusSpan(location[0], location[1], finding.category or "custom",
                                    _custom_label(finding), finding.severity))

    spans = _merge_overlaps(_expand_repeats(text, spans))
    parts: list[str] = []
    cursor = 0
    for span in spans:
        parts.append(text[cursor:span.start])
        parts.append(f"[{span.label}]")
        cursor = span.end
    parts.append(text[cursor:])
    return CorpusItemResult(spans=spans, masked_text="".join(parts), incomplete=incomplete)


def scan_batch(items) -> tuple[list[dict], str]:
    """在同一份规则包快照上扫描一批文本，返回 (结果列表, 规则包版本)。"""
    custom_rules, _policies, _exceptions, _file_policy, _reply, version = engine.snapshot_rule_pack_state()
    results = []
    for item in items:
        outcome = scan_item(item.text, custom_rules)
        results.append({
            "id": item.id,
            "findings": [span.as_dict() for span in outcome.spans],
            "masked_text": outcome.masked_text,
            "incomplete": outcome.incomplete,
        })
    return results, version
