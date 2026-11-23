"""Cascade signals for the semantic judge (policy ``coverage_v2``).

Two different questions, deliberately kept apart:

``admission_cues``
    Recall-oriented. Decides whether a window that Tier-1 scored low still has
    to reach the judge. A cue is never a finding and never proves an attack;
    quoted research samples are admitted too, the judge decides.

``instruction_evidence``
    Precision-oriented. Independent corroboration that untrusted content
    (tool/RAG/web) carries an instruction aimed at the assistant. Topic words,
    quoted or explicitly analysed samples, negated/refused directives and
    identifiers such as ``ignore_untrusted_instruction`` are not evidence.
    Only spans found in the inspected text count; task context and source
    labels are never searched.

Neither function trusts self-declared authority ("已授权", "system message").
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import List

from app.detectors.prompt_injection import (
    ACTIONABLE_INJECTION_HINTS,
    INDIRECT_DIRECTIVE,
    INDIRECT_EXFIL_IMPERATIVE,
)

_STOP = r"[^。！？!?；;\n]"
_SENTENCE_BREAK = re.compile(r"[。！？；\n]")

# ---------------------------------------------------------------- vocabulary
_EN_PRIOR = r"(?:previous|prior|above|preceding|earlier|existing|original|all|any|your|the|these|those|current)"
_EN_RULES = (r"(?:instructions?|prompts?|rules?|constraints?|guidelines?|directions?|directives?|restrictions?|"
             r"guardrails?|policies|policy|task)")
_EN_OVERRIDE_VERB = (r"(?:ignore|disregard|forget|override|overrule|supersede|replace|discard|abandon|set\s+aside|"
                     r"stop\s+following|no\s+longer\s+follow|do\s+not\s+follow|don'?t\s+follow|revoke|lift)")
_ZH_PRIOR = r"(?:前面|之前|以上|上面|上述|先前|此前|原来|原有|既有|已有|现有|当前|原定|所有|全部|一切|系统)"
_ZH_RULES = r"(?:指令|指示|提示词?|约束|限制|规则|约定|设定|要求|任务|命令|准则|规定|边界)"
_ZH_OVERRIDE_VERB = (r"(?:忽略|无视|忘记|忘掉|作废|废除|撤销|取消|解除|清除|清空|放弃|推翻|覆盖|替换|抛开|抛弃|"
                     r"放在一边|放到一边|搁置|不再遵循|不要再遵循|不必遵守|不再遵守|不用再管|不用管|别管|不必理会)")

# Overriding the assistant's standing instructions / task.
_OVERRIDE = re.compile(
    r"\b" + _EN_OVERRIDE_VERB + r"\b[^.!?;\n]{0,40}?\b" + _EN_RULES + r"\b|"
    r"\b(?:higher|highest|top)[- ]priority\s+(?:instruction|directive|command|message|order)s?\b|"
    r"\b(?:treat|use|regard)\b[^.!?;\n]{0,40}\bas\s+(?:a\s+)?(?:system|admin(?:istrator)?|developer)\s+"
    r"(?:command|instruction|message|prompt)s?\b|"
    r"\b(?:above|previous|prior|preceding)\s+(?:content|text|instructions?|message)\s+(?:is|are)\s+"
    r"(?:not\s+important|irrelevant|void|cancell?ed)\b|"
    r"\binstead,?\s+(?:answer|respond|reply|output|say|print)\b|"
    + _ZH_OVERRIDE_VERB + _STOP + r"{0,12}?" + _ZH_RULES + r"|"
    + _ZH_PRIOR + r"的?(?:说明的|提到的|下达的|设定的|收到的)?" + _ZH_RULES + _STOP + r"{0,8}?"
    r"(?:全部|都|一律|统统)?(?:解除|取消|作废|忽略|无视|失效|不算|不再有效|放在一边|放到一边|不重要)|"
    r"(?:更高|最高)优先级(?:的)?(?:指令|命令|指示|消息)|"
    r"(?:当作|当成|视为|作为)(?:最高)?(?:系统|管理员|开发者)(?:命令|指令|消息|提示)|"
    r"以上(?:内容|文字|文本|信息)(?:都|全都)?(?:不重要|无效|作废)",
    re.I,
)
# Forcing the assistant's reply to attacker-chosen text (admission only: users
# legitimately constrain their own replies).
_FORCED_OUTPUT = re.compile(
    r"(?:直接|不加解释地?|原样|逐字|一字不差地?|照原文)(?:输出|照抄|复述|回复|回答|说|打印)\s*[:：]|"
    r"(?:只|仅)(?:回复|回答|输出)\s*|"
    r"(?:把|将)(?:回答|回复|输出)(?:限定|固定)为|"
    r"\b(?:repeat|output|print|say|reply\s+with|respond\s+with)\s+(?:exactly|verbatim|only)\b",
    re.I,
)
# A message addressed to the reading assistant, carrying its own agenda.
_ADDRESSED = re.compile(
    r"\b(?:hi|hello|hey|dear|attention|note\s+to)\s*,?\s+(?:the\s+)?(?:ai|assistant|agent|model|chatbot|copilot|llm)\b|"
    r"\b(?:ai|assistant|agent|model|llm)\s*[,:]\s*(?:you\s+must|please|now|first|immediately)\b|"
    r"\bbefore\s+(?:completing|finishing|doing|answering|replying|responding|continuing)\b[^\n]{0,60}"
    r"\b(?:you\s+must|please\s+first|first\s*[:,])|"
    r"\byou\s+must\b[^\n]{0,40}\bbefore\s+(?:completing|finishing|answering|replying|responding|anything)\b|"
    r"\[\s*(?:priority|urgent|important|system|admin)\s+(?:message|notice|instruction|override)\s*\]|"
    r"(?:致|给)(?:AI|人工智能|助手|模型|智能体)[:：，,]|"
    r"(?:AI|助手|模型|智能体)[，,:：]\s*(?:你必须|请先|请立即|立即)|"
    r"在(?:完成|继续|回答|回复)(?:任何)?(?:其他|原|当前)?(?:任务|问题)?之前" + _STOP + r"{0,20}(?:你必须|必须先|请先)",
    re.I,
)
# Disclosing protected context or moving it to an unauthorised party.
_SECRET_EXFIL = re.compile(
    r"\b(?:reveal|disclose|print|output|dump|expose|leak|recite|show|repeat)\b[^.!?;\n]{0,40}?"
    r"\b(?:hidden|system|internal|developer|secret|initial)\s+(?:instructions?|prompts?|configuration|config|context|settings)\b|"
    r"\b(?:provide|send|forward|give|transmit|hand|post|upload|email)\b[^.!?;\n]{0,40}?"
    r"\b(?:unauthori[sz]ed|external|third[- ]party|outside)\s+"
    r"(?:recipients?|party|parties|address|server|endpoint|contacts?|accounts?)\b|"
    r"(?:披露|泄露|透露|输出|打印|复述|给出|展示|提供|说出|吐出)" + _STOP + r"{0,12}?"
    r"(?:隐藏|内部|系统|开发者|初始)的?(?:系统)?(?:指令|提示词?|配置|设定|上下文|规则)|"
    r"(?:交给|发送给|发给|提供给|转发给|传给|发到|上传到|外发给?)" + _STOP + r"{0,12}?(?:外部|未授权|未经授权|第三方|陌生|私人)|"
    r"(?:输出|复述|回忆|背诵)" + _STOP + r"{0,10}(?:训练(?:集|数据)|其他用户的?(?:聊天|对话))|"
    r"\b(?:recite|reproduce|output|repeat)\b[^.!?;\n]{0,30}\btraining\s+(?:data|set|corpus)\b",
    re.I,
)
# Switching the assistant into an unrestricted persona / around its safety layer.
_PERSONA_BYPASS = re.compile(
    r"\b(?:enter|become|switch\s+(?:to|into)|act\s+as|you\s+are\s+now|adopt)\b[^.!?;\n]{0,30}?"
    r"\b(?:unrestricted|uncensored|unfiltered|jailbroken|unbounded|no[- ]limits?|DAN)\b|"
    r"\b(?:bypass|circumvent|disable|turn\s+off|evade)\b[^.!?;\n]{0,30}?"
    r"\b(?:safety|security|content)\s*(?:boundar(?:y|ies)|filters?|policies|policy|guardrails?|checks?|restrictions?)\b|"
    r"\bagree\s+to\s+(?:execute|obey|follow)\s+any\b|"
    r"(?:进入|切换到|切换为|扮演|成为|变成|现在你是)" + _STOP + r"{0,10}?(?:不受约束|不受限|无限制|没有(?:任何)?限制|无审查|越狱|没有底线)|"
    r"绕过" + _STOP + r"{0,8}?(?:安全|边界|限制|审查|防护|策略|过滤)|"
    r"(?:承诺|保证)(?:会)?执行(?:后续|之后|接下来)?(?:的)?任何",
    re.I,
)
# Claimed authority, addressed to the reader of untrusted content.
_PRIVILEGE_CLAIM = re.compile(
    r"我是" + _STOP + r"{0,8}?(?:最高权限|超级管理员|管理员|root|admin|系统管理员|开发者)|"
    r"(?:系统通知|开发者调试模式|管理员消息|系统消息)[，,:：]|"
    r"\b(?:i\s+am|this\s+is)\s+(?:the\s+)?(?:system\s+administrator|administrator|admin|root|developer)\b|"
    r"\b(?:admin(?:istrator)?|system|developer)\s+(?:message|override|notice)\s*:",
    re.I,
)
_DECODE_DIRECTIVE = re.compile(
    r"(?:解码|译码|还原)(?:后|之后|并|再)?" + _STOP + r"{0,6}(?:按|照|执行|遵循|处理)|"
    r"\bdecode\b[^.!?\n]{0,30}\b(?:follow|execute|obey|act\s+on|carry\s+out|do\s+what)\b",
    re.I,
)
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")

# ------------------------------------------------ reference / negation framing
_PAIRS = {"“": "”", "「": "」", "『": "』"}
_TAGGED = re.compile(r"<(quoted?|sample|example|payload)>.{1,2000}?</\1>|```.{1,2000}?```", re.S | re.I)
_ASCII_QUOTE = re.compile(r"\"[^\"\n]{1,800}\"|`[^`\n]{1,800}`")
_REFERENCE_FRAME = re.compile(
    r"样例|示例|例子|举了|引用|原文|记录了|这句|话术|载荷|样本|分析|解释|说明|评估|判断|识别|归类|分类|检测器|培训|教材|研究|复盘|案例|"
    r"\b(?:example|sample|quote[sd]?|quoted|payload|analy[sz]e|explain|classify|identify|evaluate|assess|detector|"
    r"training|research|incident|lesson)\b",
    re.I,
)
# Colon-introduced samples need an explicit analysis verb in their introducer.
_ANALYSIS_INTRO = re.compile(
    r"(?:分析|解释|评估|判断|识别|归类|分类|说明(?:为什么|为何|原因)|是否)[^。！？!?\n]{0,40}[:：]\s*$|"
    r"\b(?:analy[sz]e|explain|classify|identify|evaluate|assess|determine\s+whether)\b[^.!?\n]{0,60}:\s*$",
    re.I,
)
_EXECUTE_FRAME = re.compile(
    r"执行|照做|遵循|按(?:它|其|此)(?:处理|执行)|照着做|"
    r"\b(?:execute|follow|obey|carry\s+out|act\s+on)\s+(?:it|this|them|the\s+(?:above|quoted|following))\b",
    re.I,
)
_NEGATED_PREFIX = re.compile(
    r"(?:不(?:要求|需要|要|用|必|会|能|得|应该?|可以?|准)?|禁止|请勿|切勿|无需|未|没有|拒绝|绝不|别|"
    r"\bnever|\bnot|\bno|\bwithout|\bdo\s+not|\bdon'?t|\bmust\s+not|\bshould\s+not|\brefuse\s+to|\bwill\s+not|\bwon'?t)"
    r"\s*(?:再|去|要|to)?\s*$",
    re.I,
)


def _negated(text: str, start: int) -> bool:
    clause = re.split(r"[。！？!?；;\n,，:：]", text[max(0, start - 24):start])[-1]
    return bool(_NEGATED_PREFIX.search(clause))


def _live_execute_frame(text: str) -> bool:
    return any(not _negated(text, m.start()) for m in _EXECUTE_FRAME.finditer(text))


def _quote_spans(text: str):
    spans, stack = [], []
    for index, char in enumerate(text):
        if char in _PAIRS:
            stack.append((char, index))
        elif stack and char == _PAIRS[stack[-1][0]]:
            _open, begin = stack.pop()
            if not stack:
                spans.append((begin, index + 1))
    spans.extend(m.span() for m in _TAGGED.finditer(text))
    spans.extend(m.span() for m in _ASCII_QUOTE.finditer(text))
    return spans


def _quoted_reference(text: str, start: int, end: int) -> bool:
    """True when [start,end) is a sample the surrounding text quotes or analyses."""
    for q_start, q_end in _quote_spans(text):
        if q_start <= start and end <= q_end:
            before = text[max(0, q_start - 120):q_start]
            after = text[q_end:q_end + 80]
            if _live_execute_frame(before[-40:]) or _live_execute_frame(after[:40]):
                return False
            if _REFERENCE_FRAME.search(before) or _REFERENCE_FRAME.search(after):
                return True
    # "判断下列话术是否诱导越权：<sample>" — the sample block runs to a blank line.
    block = text[max(0, start - 240):start].split("\n\n")[-1]
    for colon in re.finditer(r"[:：]\s*(?:\n|$)", block):
        intro = block[:colon.end()]
        if _ANALYSIS_INTRO.search(intro) and not _live_execute_frame(block[colon.end():]):
            return True
    return False


def _identifier(text: str, start: int, end: int) -> bool:
    """policy.action=ignore_untrusted_instruction is a field value, not a sentence."""
    before = text[start - 1:start] if start else ""
    after = text[end:end + 1]
    return bool(before in ("_", ".", "=", "/") and before) or after in ("_", "=") or "_" in text[start:end]


@dataclass(frozen=True)
class Evidence:
    kind: str
    start: int
    end: int
    decoded: bool = False


_EVIDENCE_PATTERNS = (
    ("instruction_override", _OVERRIDE),
    ("addressed_directive", _ADDRESSED),
    ("secret_exfil", _SECRET_EXFIL),
    ("persona_bypass", _PERSONA_BYPASS),
    ("privilege_claim", _PRIVILEGE_CLAIM),
    ("legacy_actionable", ACTIONABLE_INJECTION_HINTS),
    ("legacy_addressed", INDIRECT_DIRECTIVE),
    ("legacy_exfil", INDIRECT_EXFIL_IMPERATIVE),
)
_ADMISSION_EXTRA = (
    ("forced_output", _FORCED_OUTPUT),
    ("decode_directive", _DECODE_DIRECTIVE),
)


def _decoded_segments(text: str):
    for match in _BASE64.finditer(text):
        raw = match.group()
        try:
            data = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = data.decode("utf-8", errors="ignore")
        if len(decoded) < 6:
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in decoded) / len(decoded)
        if printable >= 0.85:
            yield match, decoded


def _scan(text: str, *, decoded: bool, span=None) -> List[Evidence]:
    found = []
    for kind, pattern in _EVIDENCE_PATTERNS:
        for match in pattern.finditer(text):
            # One directive lives in one sentence; legacy grammars may span two.
            if (_SENTENCE_BREAK.search(match.group()) or _quoted_reference(text, match.start(), match.end())
                    or _negated(text, match.start()) or _identifier(text, match.start(), match.end())):
                continue
            start, end = span.span() if span is not None else match.span()
            found.append(Evidence(kind, start, end, decoded))
            break
    return found


def instruction_evidence(text: str) -> List[Evidence]:
    """Unquoted, non-negated directive spans aimed at the assistant, located in ``text``."""
    if not text:
        return []
    evidence = _scan(text, decoded=False)
    for match, decoded in _decoded_segments(text):
        if _quoted_reference(text, match.start(), match.end()):
            continue
        evidence.extend(_scan(decoded, decoded=True, span=match))
    return evidence


def admission_cues(text: str) -> List[str]:
    """Reasons a low Tier-1 score must not be the only basis for skipping the judge."""
    if not text:
        return []
    cues = [kind for kind, pattern in _EVIDENCE_PATTERNS + _ADMISSION_EXTRA if pattern.search(text)]
    for _match, decoded in _decoded_segments(text):
        cues.extend("encoded_" + kind for kind, pattern in _EVIDENCE_PATTERNS if pattern.search(decoded))
    return sorted(set(cues))
