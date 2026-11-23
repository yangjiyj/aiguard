"""Local evidence context for lexical candidates; never a whole-request allowlist.

These scores describe rule evidence strength, not calibrated attack probability.
Only the matched clause/quoted span is interpreted. Other occurrences are scanned.
"""
import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from operator import attrgetter, itemgetter
from app.detectors.text_structure import code_context

BOUNDARY = re.compile(r"[。！？!?；;\r\n]|\.(?=\s|$)")
REFUSAL = re.compile(r"(?:禁止|不应|不得|不要|请勿|拒绝|不能|不会|不允许|"
                     r"cannot|must\s+not|should\s+not|do\s+not|never|"
                     r"refuse(?:s|d)?(?:\s+(?:the\s+)?requests?)?(?:\s+to)?)\s*", re.I)
DIRECTIVE = re.compile(r"(?:请(?!勿)|帮我|教我|教你|给我|告诉我|立即|马上|"
                       r"please|help\s+me|how\s+to|now\s+|^(?:实施|执行|制造|生成|设计|出售|销售|贩卖))", re.I)
EXECUTE_QUOTE = re.compile(r"(?:请.{0,12}(?:执行|照做|遵循)|"
                           r"(?:执行|照做|遵循|照着|按照|复制).{0,12}(?:样例|示例|指令|内容)|"
                           r"(?:样例|示例|指令|内容).{0,12}(?:执行|照做)|"
                           r"(?:execute|follow|obey|run)\b)", re.I)
REFERENCE = re.compile(r"(?:样例|示例|例子|研究说明|分析|解释|评估|文档|日志|"
                       r"单元测试|测试用例|回归测试|审查|如何处置|怎么处理|"
                       r"(?:反馈|报告|记录).{0,15}(?:收到|遇到|出现)|"
                       r"\b(?:example|sample|fixture|analy[sz]e|explain|evaluate|documentation|log)\b)", re.I)
BARE_REFERENCE_INTRO = re.compile(
    r"(?:样例|示例|例子|研究说明|分析|解释|评估|文档|日志|"
    r"\b(?:example|sample|fixture|analy[sz]e|explain|evaluate|documentation|log)\b)",
    re.I,
)
QUOTE = re.compile(r"“[^”\n]{1,400}”|「[^」\n]{1,400}」|『[^』\n]{1,400}』|"
                   r'\"[^\"\n]{1,400}\"|\x27[^\x27\n]{1,400}\x27|'
                   r"`[^`\n]{1,400}`")

def sentence(content, start, end):
    left = 0
    right = len(content)
    for boundary in BOUNDARY.finditer(content):
        if boundary.end() <= start:
            left = boundary.end()
        elif boundary.start() >= end:
            right = boundary.start()
            break
    return content[left:right], start-left, end-left

def has_live_directive(text):
    for clause in re.split(r"[,，]|(?:但是|但|然而|不过)", text):
        for match in DIRECTIVE.finditer(clause):
            if not REFUSAL.search(clause[max(0, match.start() - 20):match.start()]):
                return True
    return False

def refusal_reason(content, start, end):
    local, a, _ = sentence(content, start, end)
    prefix = re.split(r"[,，]|(?:但是|但|然而|不过)", local[:a])[-1]
    if REFUSAL.search(prefix[-40:]) and not has_live_directive(local):
        return "local_refusal"
    return ""


_CLAUSE_BREAK = re.compile(r"[,，]|(?:但是|但|然而|不过)")
# A clause break is at most two characters and none starts with 是、而、过, so splitting only the last 80
# characters before a span leaves the same last 40 characters of its clause as splitting the whole sentence.
_REFUSAL_LOOKBACK = 80


class SentenceIndex:
    """sentence(), refusal_reason(), quoted_reference_reason() and documented_reference_reason() for many spans
    of one text, without rescanning it from the start.

    Boundaries are found once and looked up by bisection, and each sentence is sliced and judged once, so
    every keyword occurrence of a long text costs about the same. Results equal the module functions of the same
    names on the same text.
    """

    def __init__(self, content):
        self.content = content
        self.stops = [match.start() for match in BOUNDARY.finditer(content)]
        self._texts = {}
        self._judged = {}

    def bounds(self, start, end):
        """(left, right) of the sentence holding content[start:end]: after the last boundary ending at or
        before ``start``, up to the first boundary at or after ``end``. Every boundary is one character."""
        index = bisect_left(self.stops, start)
        left = self.stops[index - 1] + 1 if index else 0
        index = bisect_left(self.stops, end, index)
        return left, self.stops[index] if index < len(self.stops) else len(self.content)

    def text(self, left, right):
        key = (left, right)
        text = self._texts.get(key)
        if text is None:
            text = self._texts[key] = self.content[left:right]
        return text

    def sentence(self, start, end):
        left, right = self.bounds(start, end)
        return self.text(left, right), start - left, end - left

    def judge(self, name, bounds, judge):
        """``judge(sentence text)``, computed once per name and sentence."""
        key = (name, bounds)
        if key not in self._judged:
            self._judged[key] = judge(self.text(*bounds))
        return self._judged[key]

    def refusal_reason(self, start, end):
        bounds = self.bounds(start, end)
        clause = _CLAUSE_BREAK.split(self.content[max(bounds[0], start - _REFUSAL_LOOKBACK):start])[-1]
        if REFUSAL.search(clause[-40:]) and not self.judge("live_directive", bounds, has_live_directive):
            return "local_refusal"
        return ""

    def quoted_reference_reason(self, start, end, context):
        """quoted_reference_reason() with ``context``. Quotes are disjoint and in text order, so only the last one
        opening before the span can hold it; 150 characters on either side of it are read."""
        quotes = context.quotes
        index = bisect_left(quotes, start, key=_QUOTE_START) - 1
        if index >= 0:
            a, b = quotes[index]
            if end < b:
                # Execution requests are in text order, so the last one is the only one to compare.
                if context.following_execution and context.following_execution[-1] >= b:
                    return ""
                left, right = self.bounds(a, b)
                outside = self.content[max(left, a - 150):a] + self.content[b:min(right, b + 150)]
                if REFERENCE.search(outside) and not has_quote_execution(outside):
                    return "quoted_rule_reference"
        return fenced_reference_reason(self.content, start, end, context=context)

    def documented_reference_reason(self, start, end):
        """documented_reference_reason(): the 120 characters before the span, and the sentence judged once."""
        bounds = self.bounds(start, end)
        if (BARE_REFERENCE_INTRO.search(self.content[max(bounds[0], start - 120):start])
                and not self.judge("quote_execution", bounds, has_quote_execution)):
            return "documented_rule_reference"
        return ""


_EXEC_VERB = re.compile(r"执行|照做|遵循|照着|按照|运行|execute|follow|obey|run",re.I)
_NEGATED_EXEC = re.compile(
    r"(?:不|不要|请勿|禁止|不应|不得|不能|不会|不允许|无需|无须|拒绝)"
    r"(?:直接|实际|真正|立即|马上|擅自|再|去){0,2}\s*$|"
    r"(?:do\s+not|don't|never|must\s+not|should\s+not|cannot|not\s+to)\s+(?:actually\s+|directly\s+)?$",
    re.I)
_DOUBLE_NEGATIVE_EXEC = re.compile(r"不能不|不得不|不要(?:禁止|阻止|拒绝)|不准不")
_BACKREF_EXEC = re.compile(
    r"(?:请|立即|马上|现在|务必|必须|然后|接着)(?:你|助手)?(?:直接|立即|马上|先)?"
    r"(?:执行|照做|遵循|运行).{0,12}(?:上述|以上|上面|这个|该|前述).{0,8}(?:样例|示例|指令|代码)|"
    r"(?:please|now|then)\s+(?:execute|follow|obey|run).{0,20}(?:above|this|that|quoted).{0,12}(?:sample|example|instruction|code)",
    re.I)

_EXEC_CLAUSE_BREAK = re.compile(r"[，,。;；\r\n]|但是|然而|不过|但")


def _execution_is_negated(text,position):
    # Only the last 40 characters of the clause count; splitting the last 80 finds them (see _REFUSAL_LOOKBACK).
    before=_EXEC_CLAUSE_BREAK.split(text[max(0,position-_REFUSAL_LOOKBACK):position])[-1][-40:]
    if _DOUBLE_NEGATIVE_EXEC.search(before):
        return False
    return bool(_NEGATED_EXEC.search(before))

def has_quote_execution(text):
    for match in EXECUTE_QUOTE.finditer(text):
        for verb in _EXEC_VERB.finditer(match.group()):
            if not _execution_is_negated(text,match.start()+verb.start()):
                return True
    return False

@dataclass(frozen=True)
class ReferenceContext:
    quotes: tuple
    code: object
    following_execution: tuple

def prepare_reference_context(content):
    # Bound optional context analysis; never infer an exemption from partial data.
    if len(content)>131072:
        return ReferenceContext((),None,())
    quotes=tuple((m.start(),m.end()) for m in QUOTE.finditer(content))
    code=code_context(content)
    protected=list(quotes)+([(f.start,f.end) for f in code.fences if f.closed] if code else [])
    outside=list(content)
    for a,b in protected:
        outside[a:b]=[" "]*(b-a)
    outside="".join(outside)
    commands=[]
    for match in _BACKREF_EXEC.finditer(outside):
        verb=_EXEC_VERB.search(match.group())
        if verb and not _execution_is_negated(outside,match.start()+verb.start()):
            commands.append(match.start())
    return ReferenceContext(quotes,code,tuple(commands))

_FENCE_START = attrgetter("start")
_QUOTE_START = itemgetter(0)


def fenced_reference_reason(content,start,end,*,context=None):
    ctx=context or prepare_reference_context(content)
    if not ctx.code:
        return ""
    fences=ctx.code.fences
    # Fences are disjoint and in text order: only the last one opening at or before ``start`` can hold the span.
    index=bisect_right(fences,start,key=_FENCE_START)-1
    if index<0:
        return ""
    fence=fences[index]
    if not (fence.closed and end<=fence.end):
        return ""
    # Execution requests are in text order, so the last one is the only one to compare.
    if ctx.following_execution and ctx.following_execution[-1]>=fence.end:
        return ""
    intro=content[max(fences[index-1].end if index else 0,fence.start-256):fence.start]
    # A filename such as sample.py is not proof of a reference task.
    intro=re.sub(r"(?im)^\s*(?:代码文件|文件名|filename|code file)\s*[:：].*$","",intro)
    if REFERENCE.search(intro) and not has_quote_execution(intro):
        return "quoted_rule_reference"
    return ""

def quoted_reference_reason(content,start,end,*,context=None):
    ctx=context or prepare_reference_context(content)
    # Locate the whole quote first. Sentence punctuation inside it must not cut
    # off the closing delimiter or the reporting/analysis context.
    for a,b in ctx.quotes:
        if a<start and end<b:
            if any(position>=b for position in ctx.following_execution):
                return ""
            local,qa,qb=sentence(content,a,b)
            prefix,suffix=local[:qa],local[qb:]
            outside=prefix[-150:]+suffix[:150]
            if REFERENCE.search(outside) and not has_quote_execution(outside):
                return "quoted_rule_reference"
    return fenced_reference_reason(content,start,end,context=ctx)


def documented_reference_reason(content, start, end):
    """Recognize an explicitly introduced bare rule/token example."""
    local, a, _ = sentence(content, start, end)
    prefix = local[:a]
    if BARE_REFERENCE_INTRO.search(prefix[-120:]) and not has_quote_execution(local):
        return "documented_rule_reference"
    return ""

def observation(finding, reason, label=None):
    """Keep the finding as evidence that does not count as a security event.

    ``label`` is the Chinese reason shown to administrators; old reason codes
    without a label keep their historical evidence text unchanged.
    """
    finding["counts_as_security_finding"] = False
    finding["action"] = "allow"
    finding["evidence_kind"] = "contextual"
    finding["evidence_reason"] = ("留证原因：" + label) if label else ("局部上下文仅支持引用/描述线索：" + reason)
    finding["triage"] = dict(finding.get("triage", {}), disposition="observation",
                              disposition_reason=reason, confidence_kind="heuristic_rule_score")
    return finding


# Evidence-local prevention/reference handling. These are not request allowlists:
# later occurrences and executable payload requests are independently inspected.
_DEFENSIVE_CONTEXT = re.compile(
    r"防止|防范|防护|防御|预防|反诈|禁毒|禁止|不要|不得|不应|请勿|阻止|反对|"
    r"严禁|切勿|不可|杜绝|谨防|警惕|反恐|防骗|防诱骗|防拐|"
    r"确保不会|避免|输出转义|(?P<disable>禁用\s*(?:XML\s*)?(?:XXE|外部实体))|检测规则|"
    r"检测[^。\n]{0,40}(?:测试|清单)|(?:防护|防御)单元测试|"
    r"\b(?:prevent|mitigat|defen[cs]|protect|forbid)\w*\b|\bprohibit(?:ing)?\b|"
    r"\b(?:do\s+not|must\s+not|should\s+not|never)\s+(?!stop\b|refuse\b|detect\b|prevent\b|protect\b)", re.I)
_LIVE_PAYLOAD = re.compile(
    r"窃取|外传|\b(?:steal|exfiltrate)\b|"
    r"(?:生成|编写|构造|创建|制作|执行|运行|给我|提供).{0,65}(?:攻击载荷|注入载荷|payload|exploit)|"
    r"\b(?:generate|craft|build|create|execute|run|give|provide)\b.{0,65}\b(?:payload|exploit)\b|"
    r"(?:绕过|无视|忽略).{0,20}(?:防护|防御|检测|安全|授权|认证|登录)|"
    r"\b(?:bypass|ignore|disable)\b.{0,30}\b(?:protection|detection|safety|authentication|authorization)\b|"
    r"(?:^|[\n`])\s*(?:curl|wget|rm\s+-|Invoke-WebRequest)\b", re.I)
_LIVE_NEGATED = re.compile(
    r"(?:禁止|不要|不得|不能|不准)[^，,。；;！!？?]{0,12}来\s*$|"
    r"(?:禁止|不要|不得|阻止|防止|不应|不能)(?:\s|任何|该|这个|用户|模型|智能体|插件|工具|商业机密|被|数据|凭据|密钥|非法|未授权|再|去|窃取|或|以及|和){0,8}$|"
    r"\b(?:not|never|prevent)(?:\s+(?:the|a|plugin|tool|model|user|any|from|credentials|data|being|steal|or|and))*\s*$",
    re.I)
# "禁用 XXE / 外部实体" is prevention wording only when it plainly asks for or
# requires turning entities off; when unsure, the finding keeps counting.
# - It needs a cue before "禁用" in the same clause ("如何", "请", "应该"...;
#   a line break ends the clause for the cue) or a nominal "禁用…的配置 /
#   设置 / 解析器 / 代码 / 写法".
# - Any negation or state word before "禁用" in the same clause ("没", "未能",
#   "忘", "已", "目标", "服务器"...), however far back and across line breaks,
#   cancels it, as does "禁用…后 / 了" followed by evasion ("绕过", "bypass").
# - A clause start out of reach of _DISABLE_LOOKBACK cancels it too.
_DISABLE_CUE = re.compile(r"如何|怎么|怎样|(?<![响对相反供适回])应(?!用|对)|需要|要|请|务必|确保|是否|必须")
_DISABLE_NOMINAL = re.compile(r"\s*的\s*(?:[A-Za-z]+\s*){0,2}(?:配置|设置|解析器|代码|写法)")
_DISABLE_NEGATION = re.compile(r"[没未不无非忘尚已]|目标|对方|服务器|站点|对端")
_DISABLE_EVASION = re.compile(r"\s*(?:之后|以后|后|了)[^。！？!?；;]{0,60}?(?:绕过|绕开|突破|规避|bypass)", re.I)
_DISABLE_CLAUSE_END = re.compile(r"[，,：:；;。！!？?]")
_DISABLE_LOOKBACK = 80
_ADVERSATIVE = re.compile(r"但是|然而|不过|然后|但|\b(?:but|however|then|instead)\b", re.I)
_SCAN_CONTEXT = 240


def bounded_sentence(content, start, end, context=_SCAN_CONTEXT):
    offset = max(0, start-context)
    return sentence(content[offset:min(len(content), end+context)], start-offset, end-offset)


def scan_window(content, start, end):
    """(offset, text) that covered_sentences() reads around content[start:end]."""
    offset = max(0, start - _SCAN_CONTEXT)
    return offset, content[offset:min(len(content), end + _SCAN_CONTEXT)]


def covered_sentences(content, spans):
    """(absolute_start, text) of the sentence(s) the matched spans fall in.

    Sentences end at 。！？!?；; newlines and ". "; commas and colons do not
    end a sentence. Only a bounded window around the spans is examined.
    """
    left = min(a for a, _ in spans)
    right = max(b for _, b in spans)
    offset, window = scan_window(content, left, right)
    rel_left, rel_right = left - offset, right - offset
    start, end = 0, len(window)
    for boundary in BOUNDARY.finditer(window):
        if boundary.end() <= rel_left:
            start = boundary.end()
        elif boundary.start() >= rel_right:
            end = boundary.start()
            break
    return offset + start, window[start:end]


def _inside_keyword(start, end, keyword_spans):
    return any(a <= start and end <= b for a, b in keyword_spans)


_QUESTION = re.compile(r"[？?]|有哪些|是什么|为什么|怎么|如何|吗|哪些|什么|哪里|\b(?:how|what|why|which)\b", re.I)
_CLAUSE = re.compile(r"[，,：:]")


def has_live_payload(text, patterns=(), keyword_spans=(), base=0):
    """An attack demand (payload, steal, bypass login...) that is not negated.

    A family demand lying wholly inside the rule's own keyword is the topic
    ("正则回溯攻击", "未授权访问"), not a new demand; attack payload demands
    ("窃取", "生成…载荷") always count.
    """
    for pattern in (_LIVE_PAYLOAD, *patterns):
        for live in pattern.finditer(text):
            if pattern is not _LIVE_PAYLOAD and _inside_keyword(base + live.start(), base + live.end(), keyword_spans):
                continue
            prefix = re.split(r"[,，:：]", text[max(0, live.start()-24):live.start()])[-1]
            if not _LIVE_NEGATED.search(prefix):
                return True
    return False


def _disabling_is_prevention(content, start, end):
    """Whether "禁用 XXE / 外部实体" at content[start:end] plainly asks for disabling."""
    before = content[max(0, start - _DISABLE_LOOKBACK):start]
    pieces = _DISABLE_CLAUSE_END.split(before)
    if len(pieces) == 1 and start > _DISABLE_LOOKBACK:
        return False
    clause = pieces[-1]
    after = content[end:end + _DISABLE_LOOKBACK]
    if _DISABLE_NEGATION.search(clause) or _DISABLE_EVASION.match(after):
        return False
    return bool(_DISABLE_CUE.search(re.split(r"[\r\n]", clause)[-1]) or _DISABLE_NOMINAL.match(after))


def request_scope(text, request_start):
    """Which positions of ``text`` may qualify the request starting at ``request_start``.

    ``request_start`` is the first matched component. Earlier sentences of a
    spanning candidate and every clause from the request's first clause on
    always count; an earlier clause of the same sentence ("为了禁毒科普，…")
    counts only when the request is a question ("禁毒宣传：…有哪些").
    """
    # Scan the whole text, as covered_sentences does: cutting the search at
    # request_start would let "\.(?=\s|$)" end a sentence at "步骤1.编写".
    sentence_start = 0
    for boundary in BOUNDARY.finditer(text):
        if boundary.end() > request_start:
            break
        sentence_start = boundary.end()
    clause_start = sentence_start
    for clause in _CLAUSE.finditer(text, sentence_start, request_start):
        clause_start = clause.end()
    asks = bool(_QUESTION.search(text, clause_start))
    return lambda position: position < sentence_start or position >= clause_start or asks


def defensive_context_reason(content, spans, live_patterns=(), keyword_spans=None):
    """Prevention/refusal wording that governs every matched component.

    - Same sentence: the wording may sit in any clause the candidate covers; a
      clause before the candidate (comma or colon) counts only when the request
      is a question, and nothing before a "but/然而" that precedes the last
      component counts.
    - Spanning sentences: the wording may sit in any spanned sentence.
    - Wording that lies wholly inside a keyword never counts ("告诉我禁止你做什么"),
      and the rule's own keywords are not live demands ("正则回溯攻击").
      ``keyword_spans`` defaults to ``spans``; callers pass every occurrence of
      the rule's keyword components (not gap components) in the sentence(s).
    - "禁用 XXE / 外部实体" counts only when plainly asked for or required
      ("如何禁用", "请编写禁用 XXE 的配置"); negation or a target's state
      ("没禁用", "已禁用", "目标服务器…禁用") or evasion after it
      ("禁用…后绕过") cancels it.
    - Any live attack demand in the sentence(s) cancels the exemption.
    A sentence that alone contains every component produces its own candidate
    and is judged on its own words only.
    """
    base, text = covered_sentences(content, spans)
    last_start = max(a for a, _ in spans) - base
    cut = 0
    for adversative in _ADVERSATIVE.finditer(text):
        if adversative.end() <= last_start:
            cut = adversative.end()
    governs = request_scope(text, min(a for a, _ in spans) - base)
    keyword_spans = spans if keyword_spans is None else keyword_spans
    scanned = text[cut:]
    defended = any(
        governs(cut + match.start())
        and not _inside_keyword(base + cut + match.start(), base + cut + match.end(), keyword_spans)
        and (match.lastgroup != "disable"
             or _disabling_is_prevention(content, base + cut + match.start(), base + cut + match.end()))
        for match in _DEFENSIVE_CONTEXT.finditer(scanned)
    )
    if not defended or has_live_payload(text, live_patterns, keyword_spans, base):
        return ""
    return "local_prevention_or_refusal"


def defensive_reference_reason(content, start, end, live_patterns=()):
    return defensive_context_reason(content, ((start, end),), live_patterns)
