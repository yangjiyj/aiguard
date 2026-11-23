"""High-confidence deterministic detectors for executable catalog policies."""
from __future__ import annotations

from app.detectors.evidence_context import BOUNDARY, covered_sentences, defensive_context_reason, observation
from app.detectors.benign_framing import family_of, framing_reason, live_patterns

from app.detectors.encoded_content import lexical_text
from app.detectors.catalog_terms import (Pat, any_of, exact, near, not_after, not_before, not_followed_by, raw, rep,
                                         seq, stem, tempered, w)

import bisect
import heapq
import itertools
import re
import threading
import time
from contextlib import contextmanager
import regex
from app.regex_budget import AttemptStats, env_float, run_with_cpu_budget, wall_max_seconds
from app.bounded_work import WorkUnavailable, check_work_budget, effective_deadline
from app.detectors.evidence_context import fenced_reference_reason, prepare_reference_context
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Pattern, Tuple
from functools import lru_cache
import sys


def _python_character_class(predicate):
    """Use this Python runtime's Unicode table, not the regex wheel's table."""
    ranges = []
    start = None
    for point in range(sys.maxunicode + 2):
        member = point <= sys.maxunicode and predicate(chr(point))
        if member and start is None:
            start = point
        elif not member and start is not None:
            left = "\\U%08x" % start
            right = "\\U%08x" % (point - 1)
            ranges.append(left if start == point - 1 else left + "-" + right)
            start = None
    return "".join(ranges)


_PYTHON_WORD = _python_character_class(lambda char: char.isalnum() or char == "_")
_PYTHON_SPACE = _python_character_class(str.isspace)
_PYTHON_DIGIT = _python_character_class(str.isdecimal)
_PYTHON_CATEGORIES = {"w": _PYTHON_WORD, "s": _PYTHON_SPACE, "d": _PYTHON_DIGIT}
_PYTHON_WORD_ATOM = "(?-i:[" + _PYTHON_WORD + "])"
_PYTHON_BOUNDARY = (
    "(?:(?<=" + _PYTHON_WORD_ATOM + ")(?!" + _PYTHON_WORD_ATOM + ")|"
    "(?<!" + _PYTHON_WORD_ATOM + ")(?=" + _PYTHON_WORD_ATOM + "))"
)


# Only the audited catalog grammar is accepted. New syntax must be reviewed
# together with the Python-re compatibility adapter, never silently passed on.
_CATALOG_CLASS_SOURCES = frozenset((
    r"[A-Za-z0-9_]", r"[^A-Za-z0-9_]", r"[A-Za-z]", r"[ \t]",
    r"[-\s]", r"[ \-]", "[^\\n\u3002;\uff1b]", r"[sz]", r"[0-9a-f]",
    r"[01]", r"[0-7]", r"[!?.]", r"[cs]", r"[mt]", r"[1-3]",
    "[\u4e00\u4e8c\u4e09123]",
    "[-A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%{}|<>^`]",
))
_CATALOG_ESCAPES = frozenset("bswdnt.-(|$*{}\\?^+)[]")
_CATALOG_GROUPS = ("(?:", "(?!", "(?<!")
_CATALOG_QUANTIFIER = re.compile(r"\{[0-9]+(?:,[0-9]*)?\}")


def _catalog_class_end(value, index):
    end = index + 1
    while end < len(value):
        if value[end] == "\\":
            end += 2
        elif value[end] == "]":
            if value[index:end + 1] not in _CATALOG_CLASS_SOURCES:
                raise ValueError("Unaudited catalog character class")
            return end + 1
        else:
            end += 1
    raise ValueError("Unclosed catalog character class")


def _validate_catalog_source(value):
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\":
            if index + 1 >= len(value) or value[index + 1] not in _CATALOG_ESCAPES:
                raise ValueError("Unaudited catalog escape")
            index += 2
            continue
        if char == "[":
            index = _catalog_class_end(value, index)
            continue
        if char == "(":
            group = next((g for g in _CATALOG_GROUPS if value.startswith(g, index)), None)
            if group is None:
                raise ValueError("Unaudited catalog group")
            index += len(group)
            continue
        if char == "{":
            match = _CATALOG_QUANTIFIER.match(value, index)
            if match is None:
                raise ValueError("Unaudited catalog quantifier")
            if value[match.end():match.end() + 1] in ("?", "+"):
                raise ValueError("Unaudited catalog quantifier suffix")
            index = match.end()
            continue
        if char in "*+?" and value[index + 1:index + 2] in ("?", "+"):
            raise ValueError("Unaudited catalog quantifier suffix")
        if char == "}":
            raise ValueError("Unpaired catalog quantifier terminator")
        if ord(char) > 127 and not (0x4E00 <= ord(char) <= 0x9FFF):
            raise ValueError("Unaudited catalog literal")
        index += 1
    # Compile only for syntax validation, never as an execution fallback.
    try:
        re.compile(value, re.IGNORECASE | re.DOTALL)
    except (re.error, OverflowError) as exc:
        raise ValueError("Invalid Python-re catalog syntax") from exc


@lru_cache(maxsize=None)
def _python_re_class(value):
    if value not in _CATALOG_CLASS_SOURCES:
        raise ValueError("Unaudited catalog character class")
    # Catalog classes have no nested sets or inline flags. Expand categories
    # before compiling; VERSION0 alone does not preserve Python re semantics.
    inner = value[1:-1]
    for token, members in _PYTHON_CATEGORIES.items():
        inner = inner.replace("\\" + token, members)
    native = re.compile(value, re.IGNORECASE | re.DOTALL)
    negated = inner.startswith("^")
    for point in (0x0130, 0x0131, 0x017F, 0x212A):
        matches = native.fullmatch(chr(point)) is not None
        if matches != negated:
            inner += "\\u%04x" % point
    return "[" + inner + "]"


def _python_re_source(value):
    """Adapt the catalog's existing grammar without changing input/offsets.

    ASCII literals plus uncased CJK are the catalog's complete literal grammar.
    Python re's word/space/digit tables and its four extra ASCII case mappings
    must remain exact when the interruptible engine uses a newer Unicode table.
    """
    _validate_catalog_source(value)
    parts = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\":
            token = value[index + 1]
            if token == "b":
                parts.append(_PYTHON_BOUNDARY)
            elif token in _PYTHON_CATEGORIES:
                parts.append("(?-i:[" + _PYTHON_CATEGORIES[token] + "])")
            else:
                parts.append(value[index:index + 2])
            index += 2
            continue
        if char == "[":
            end = index + 1
            while end < len(value):
                if value[end] == "\\":
                    end += 2
                elif value[end] == "]":
                    break
                else:
                    end += 1
            parts.append(_python_re_class(value[index:end + 1]))
            index = end + 1
            continue
        # regex's simple folding of literal i/I is not Python re's folding.
        parts.append("[iI\\u0130\\u0131]" if char in "iI" else char)
        index += 1
    return "".join(parts)


# Every compiled catalog source and declared English fragment, for the
# python-re parity and word-boundary guard tests.
CATALOG_SOURCES: List[str] = []
CATALOG_FRAGMENTS: list = []
# Patterns with a wildcard gap (".{0,40}", ".+", "[^\n。;；]{0,30}") may contain other components.
_GAPPED_PATTERNS: set = set()
_GAP = re.compile(r"(?<!\\)\.(?:[*+]|\{)|\[\^[^\]]*\](?:[*+]|\{)")


def _rx(value: Pat) -> Pattern[str]:
    if not isinstance(value, Pat):
        raise TypeError("catalog rules must be built with w/stem/raw")
    CATALOG_SOURCES.append(value.source)
    CATALOG_FRAGMENTS.extend(value.fragments)
    compiled = regex.compile(_python_re_source(value.source), regex.IGNORECASE | regex.DOTALL | regex.VERSION0)
    if _GAP.search(value.source):
        _GAPPED_PATTERNS.add(id(compiled))
    return compiled


# Components whose matches inside a link do not count: "%E6%8C%87" or
# "payload=" in a URL path or query is not a payload. A link is http:// or
# https:// followed by RFC 3986 characters (unreserved, reserved and "%") plus
# the ASCII characters of path templates and query values ({id}, {{payload}},
# <tenant>, a|b, ^ and `), so whitespace, Chinese text, full-width punctuation,
# double quotes and backslashes end it
# ("参考https://example.com/doc，然后解码%69…" keeps the %XX outside).
_OUTSIDE_LINK_PATTERNS: set = set()
_LINK_CHARACTERS = "[-A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%{}|<>^`]"
_LINK = _rx(seq(w("https?://"), raw(_LINK_CHARACTERS + "+")))


def _outside_links(compiled: Pattern[str]) -> Pattern[str]:
    _OUTSIDE_LINK_PATTERNS.add(id(compiled))
    return compiled


# Keep each native match interruptible and release the GIL while it runs.
# These are runtime bounds, not a silent prefix-only inspection policy.
# 预算按本线程 CPU 时间记账（等 GIL 不算），可用环境变量覆盖，见 app/regex_budget.py。
_CATALOG_BUDGET_SECONDS = env_float("SECURITY_CATALOG_BUDGET_SECONDS", 2.0, 0.05, 30.0)
_CATALOG_REGEX_TIMEOUT_SECONDS = env_float("SECURITY_CATALOG_REGEX_TIMEOUT_SECONDS", 0.25, 0.01, 5.0)
_CATALOG_MAX_EVENTS = 100000

_cpu_local = threading.local()


@contextmanager
def _cpu_scope():
    """整次 catalog 检测的 CPU 预算作用域；嵌套时沿用最外层。"""
    if getattr(_cpu_local, "start", None) is not None:
        yield
        return
    _cpu_local.start = time.thread_time()
    _cpu_local.budget = _CATALOG_BUDGET_SECONDS
    try:
        yield
    finally:
        _cpu_local.start = None


def _cpu_remaining():
    start = getattr(_cpu_local, "start", None)
    if start is None:
        return float("inf")
    return _cpu_local.budget - (time.thread_time() - start)


def _check_cpu_budget():
    if _cpu_remaining() <= 0:
        raise WorkUnavailable("catalog_budget_exhausted")


def _catalog_deadline():
    # 墙钟 deadline 只是外层兜底（预算 + WALL_MAX，并受父请求预算约束），真正的整体预算看 CPU。
    return effective_deadline(time.monotonic() + _CATALOG_BUDGET_SECONDS + wall_max_seconds())


def _regex_options(deadline):
    check_work_budget(deadline)
    remaining = deadline - time.monotonic()
    if remaining <= 0 or _cpu_remaining() <= 0:
        raise WorkUnavailable("catalog_budget_exhausted")
    return {"timeout": min(_CATALOG_REGEX_TIMEOUT_SECONDS, remaining, _cpu_remaining()), "concurrent": True}


def _catalog_call(deadline, fn):
    """以 CPU 预算执行 fn(options)；wall 超时但 CPU 很少时重试一次。"""
    cpu_budget = _regex_options(deadline)["timeout"]
    parent_deadline = effective_deadline(deadline)

    def attempt(_cpu_budget, wall_timeout):
        wall_left = parent_deadline - time.monotonic()
        if wall_left <= 0:
            raise TimeoutError("catalog wall deadline")
        return fn({"timeout": min(wall_timeout, wall_left), "concurrent": True})

    return run_with_cpu_budget(attempt, cpu_budget, AttemptStats())


def _catalog_search(pattern, content, deadline):
    match = _catalog_call(deadline, lambda options: pattern.search(content, **options))
    check_work_budget(deadline)
    _check_cpu_budget()
    return match


_NO_MORE = object()


def _catalog_finditer(pattern, content, deadline):
    """finditer；单步超时但 CPU 很少时，从上一个匹配末尾重建迭代器重试一次。"""
    state = {"it": None, "pos": 0}

    def step(options):
        if state["it"] is None:
            kwargs = dict(options)
            if state["pos"]:
                kwargs["pos"] = state["pos"]
            state["it"] = pattern.finditer(content, **kwargs)
        try:
            return next(state["it"], _NO_MORE)
        except TimeoutError:
            state["it"] = None
            raise

    while True:
        match = _catalog_call(deadline, step)
        if match is _NO_MORE:
            return
        end = match.end()
        # 空匹配后从 end+1 续扫：仅在重试重建迭代器时使用 pos，用于跳过空匹配避免原地死循环；
        # catalog 的 required 模式都要求非空 token，空匹配实际不会出现，
        # 即使出现，少看一个位置的空匹配也不影响"是否命中"的判定，可以接受。
        state["pos"] = end if end > match.start() else end + 1
        yield match


def _catalog_incomplete(reason):
    return {
        "type": "engine_runtime", "category": "engine_scan_incomplete", "severity": "low",
        "matched_text_preview": "<catalog-inspection-incomplete>",
        "matched_location": "content[unavailable]", "rule_id": "catalog_runtime_budget",
        "rule_name": "catalog_runtime_budget", "rule_type": "builtin",
        "action": "audit", "confidence": 1.0, "counts_as_security_finding": False,
        "evidence_kind": "runtime", "evidence_reason": "Catalog inspection did not finish within runtime bounds.",
        "triage": {"review_status": "incomplete", "review_reason": reason,
                   "counts_as_security_finding": False},
    }


@dataclass(frozen=True)
class PolicyCatalogRule:
    category: str
    severity: str
    stages: Tuple[str, ...]
    required: Tuple[Pattern[str], ...]
    # 词义排除：排除词是同一个词的另一种意思（nail gun 之于 gun、race condition 之于 race）。
    # 只丢掉与排除词位置重叠的那次组件出现，同组的其他出现照常参与组合；
    # 排除词所在句有 unless 的说法时不丢。
    excluded: Tuple[Pattern[str], ...] = ()
    max_window: int = 240
    unless: Tuple[Pattern[str], ...] = ()
    # 词义排除靠附近的字眼认出另一种意思时（测试语境里的 skip login），只把匹配里这些词的位置
    # 算作覆盖，中间夹着的其他组件（认证绕过）不受影响。
    excluded_focus: Tuple[Pattern[str], ...] = ()
    # 语境排除：排除词描述请求所在的开发语境（mock、访问控制、写函数或接口）。与组件重叠时
    # 同样丢掉那次出现；只是同句出现时命中改为留证，原因文字是 context_label；
    # 同句有 context_unless 的实施说法时两样都不做，照常计入告警。
    context_excluded: Tuple[Pattern[str], ...] = ()
    context_unless: Tuple[Pattern[str], ...] = ()
    context_label: str = ""
    # 行级例外：line_exception(line, deadline, table_columns) 读组件出现所在的整条物理行（Markdown 表格行、
    # 标题行，行内的句号不切分），返回行内不算组件的位置（相对行首）。table_columns 是这一行作为 GFM
    # 表格数据行时那张表的列数（见 _gfm_table_columns），不是数据行时为 0。只看以 | 或 # 开头的行，
    # 每行算一次，不计入候选事件上限。
    line_exception: Optional[Callable[[str, float, int], List[Tuple[int, int]]]] = None


_CODE_GENERATION_INTENT = _rx(any_of(
    w("generate", "write", "create", "craft", "build", "payload", "bypass"), exact("wrote", "written", "built"),
    raw("生成", "编写", "创建", "构造", "制作", "载荷", "绕过"),
))
_CONTENT_CREATION_INTENT = _rx(any_of(
    w("generate", "write", "draft", "create", "compose", "script", "template"), exact("wrote", "written"),
    raw("生成", "编写", "撰写", "创建", "制作", "话术", "文案", "模板", "脚本"),
))
_ILLEGAL_TRANSACTION_INTENT = _rx(any_of(
    w("buy", "sell", "source", "supplier", "channel", "price", "ship", "manufacture", "forge"), exact("bought", "sold"),
    raw("购买", "出售", "销售", "货源", "供应商", "渠道", "价格", "运输", "制作", "伪造"),
))
_HARMFUL_CONTENT_INTENT = _rx(any_of(
    w("generate", "write", "create", "teach", "guide", "instruction", "promote", "encourage", "glorify"),
    exact("wrote", "written", "taught"),
    raw("生成", "编写", "创建", "教授", "指导", "教程", "方法", "宣传", "鼓励", "美化", "煽动"),
))

# Pretext rules: the bypass must target the model's safety rules, not an
# eslint rule, a cache policy or an SELinux policy.
_BYPASS_VERB = any_of(
    w("bypass", "ignore", "override", "disable", "reveal\\s+restricted"), exact("overridden", "overrode"),
    raw("绕过", "忽略", "无视", "覆盖", "禁用", "透露受限"),
)
_RULE_NOUN_EN = w("rule", "restriction", "guideline", "policy", "constraint")
_BYPASS_OBJECT = any_of(
    w("safety\\s+rule", "safety\\s+policy", "safety\\s+restriction", "safety\\s+guideline", "safety\\s+filter",
      "safety\\s+guardrail", "safety\\s+measure", "safety\\s+alignment", "security\\s+rule", "security\\s+policy",
      "security\\s+restriction", "security\\s+filter", "security\\s+guardrail", "guardrail", "content\\s+policy",
      "content\\s+filter", "content\\s+moderation"),
    raw("安全(?:的)?(?:规则|策略|限制|护栏|机制|审查|过滤|设定|准则|约束|对齐|措施)", "护栏", "审查", "内容审核", "内容策略",
        "伦理(?:规则|限制|约束)", "道德(?:规则|限制|约束)"),
    seq(raw("你的", "你被设定的", "所有", "一切", "任何", "全部", "以上", "上述", "之前的", "先前的"),
        raw("[^\\n。;；]{0,8}"), raw("规则", "策略", "限制", "约束", "设定")),
    seq(any_of(raw("系统", "模型", "助手", "平台", "内容", "输出", "使用"), w("AI")), raw("的?"),
        raw("规则", "策略", "限制", "约束", "设定")),
    seq(exact("your", "all", "any"), raw("(?:\\s+[A-Za-z]+){0,2}\\s+"), _RULE_NOUN_EN),
    seq(exact("system", "model", "assistant", "AI", "content"), raw("'?s?\\s+"), _RULE_NOUN_EN),
)
_BYPASS_TARGET = _rx(any_of(
    near(_BYPASS_VERB, _BYPASS_OBJECT, 40),
    near(_BYPASS_OBJECT, _BYPASS_VERB, 40),
    seq(_BYPASS_VERB, raw("\\s+"), rep(seq(exact("the", "your", "all"), raw("\\s+")), "?"), exact("safety")),
))

# "文件扩展名" / "file extension" are not plugins.
_PLUGIN_NOUN = any_of(w("plugin"), not_after("file", w("extension")), raw("插件", "扩展(?!名)"))
_TOOL_OR_PLUGIN = any_of(w("tool", "plugin"), not_after("file", w("extension")), raw("工具", "插件", "扩展(?!名)"))
# 词义：401 Unauthorized、“返回未授权”说的是响应状态，不是一次未授权的调用。
_UNAUTHORIZED_STATUS = _rx(any_of(
    w("401\\s+unauthorized", "unauthorized\\s+error"),
    seq(raw("返回了?\\s*"), any_of(raw("未授权"), w("unauthorized"))),
    raw("401\\s*未授权"),
))
# 语境：在做访问控制、处理 401/403 错误码，请求是在写这道检查。
_ACCESS_CONTROL_WORK = _rx(any_of(
    w("access\\s+control", "403\\s+forbidden", "forbidden\\s+error"),
    seq(raw("返回了?\\s*"), w("forbidden")),
    raw("访问控制", "返回\\s*401", "返回\\s*403", "401\\s*错误", "403\\s*错误"),
))
# 实施说法：绕过、规避访问控制就是攻击本身。
_CIRCUMVENT = _rx(any_of(raw("绕过", "绕开", "越过", "规避"), w("bypass", "circumvent")))
# A file or data transfer is not a money transfer.
_NON_MONEY_TRANSFER = _rx(any_of(w("file\\s+transfer", "data\\s+transfer", "transfer\\s+protocol"), raw("文件传输")))
_MONEY_WORDS = _rx(any_of(w("fund", "money", "payment", "account", "wallet"), raw("资金", "汇款", "转账到", "安全账户", "钱")))
# "忽略之前" must target instructions, not "之前的版本说明".
_IGNORE_PREVIOUS = any_of(
    seq(w("ignore\\s+previous"), raw(".{0,8}"), w("instruction", "rule", "prompt")),
    seq(raw("忽略之前"), raw(".{0,8}"), raw("指令", "规则", "设定", "提示")),
)
_AI_CONTENT = any_of(w("AI", "watermark", "model"), raw("生成内容", "合成", "模型", "内容标识", "水印"))
_TEST_CONTEXT = any_of(w("pytest", "fixture", "mock", "unit\\s+test", "test\\s+case"), raw("单元测试", "测试用例"))
_SKIP_LOGIN = w("skip\\s+login", "skip\\s+authorization")
# 测试语境里写明攻击对象的，是借测试的名义要攻击代码（“目标函数”这类测试说法不算）。
_ATTACK_TARGET = _rx(any_of(
    w("target", "victim", "production"),
    raw("目标站点", "目标网站", "目标系统", "目标服务器", "目标主机", "目标后台", "目标门户", "对方", "受害", "生产站点", "生产环境"),
))
# 人肉搜索的实施说法：人肉、曝光，或查找、公开某个具体的人。
_DOXX_PERSON = any_of(raw("她", "(?<!其)他", "某人", "此人", "这个人", "主播", "博主", "网红", "明星", "前任", "前女友",
                          "前男友", "同事", "邻居", "网友"),
                      exact("her", "his", "him", "someone"))
_DOXXING_ACT = _rx(any_of(
    raw("人肉", "曝光", "公开出去", "公之于众", "发到网上", "挂到网上"),
    w("doxx", "publish"),
    near(any_of(raw("查找", "找到", "查到", "查出", "定位", "公开"), w("find", "locate", "expose", "track\\s+down")),
         _DOXX_PERSON, 8),
))
# A gap followed by a literal ("如果……会怎样") stays inside the rule window: a
# longer component can never form a candidate, and an unbounded ".+" would
# backtrack over the rest of the text from every start ("compare compare ...").
# Words around the gap take exactly one whitespace ("save\s", "\slives"):
# "\s+" on both sides of the gap would split a long run of blanks in
# quadratically many ways ("save" + 8000 spaces).
_WITHIN_WINDOW = raw(".{1,240}")
# compare … vs: the gap never runs over another "compare " that could start the
# match itself, so a long run of compares tries each start once and the match
# starts at the compare nearest to vs. A "compare " followed by vs, or by one
# more blank and vs, does not stop the gap: "compare x compare vs y" and
# "compare x compare  vs y" match as before, so hit or miss is unchanged.
_VERSUS = w('versus', 'vs', 'vs\\.')
_COMPARE_VS = seq(w('compare\\s'),
                  tempered(not_followed_by(w('compare\\s'), seq(raw('\\s?'), _VERSUS)), 1, 240),
                  raw('\\s'), _VERSUS, raw('.+'))
_ADMIN_FORMS = exact("administrator", "administrators", "administrative", "sysadmin", "sysadmins",
                     "superadmin", "superadmins", "superadministrator", "superadministrators")


# 载荷拆分的两处窄例外（2.9.21 现场误报），只认两种 Markdown 物理行，其余写法与 2.9.20 相同：
# - 表格行：GFM 表格的数据行（上方连续不隔行的 | 行里，第一行是表头、第二行是 |---| 分隔行），列数与
#   表头相同。某一格的完整取值就是 split / joined / split-coop 这类一个词（可加反引号、最多三段
#   -后缀，后缀里不能再有拆分、拼接类词），这一行其余单元格以数字为主（至少两格是数字，且超过一半），
#   其中至少一格带小数或科学计数（9.8、1.71e9）。丢掉的只是这一格；全是编号、份数、轮次这类整数的行、
#   没有表头和分隔行的行、| split-then-join |、| 1 | split the payload |、| split | fast | 22.0 |
#   都照常算。
# - 标题行（以 # 开头）：以“<名词>的拆分”结尾的小节标题，去掉章节编号后的名词以 API、SDK、接口、服务、
#   模块、组件结尾（### 3.2 协作 API 的拆分）。私钥文件、系统提示、字符串、Query、OpenAPI 这类名词，
#   名词前是按、根据、通过、利用这类说拆分依据或手段的字，或标题里有逗号句号的，都不算；正文里的
#   “拆分”、没有“的”的“接口拆分”、不以 # 开头的编号标题都照常算。
# 整行（不按句号切分）出现指令、载荷、执行、绕过、提示词等任一字眼时，这一行不例外。
_PAYLOAD_SPLIT_PART = _rx(any_of(raw("拆分", "分片"), w("split", "splitting", "fragments?", "fragmenting")))
_PAYLOAD_SPLIT_JOIN = _rx(any_of(raw("重组", "组合", "拼接"), w("reassemble", "combine", "join")))
_PAYLOAD_SPLIT_LINE_UNLESS = _rx(any_of(
    raw("指令", "载荷", "执行", "运行", "照做", "提示词", "绕过", "绕开", "躲过", "躲避", "躲开", "避开", "越过", "规避",
        "逃避", "逃过", "骗过", "混过", "不被发现", "过滤", "拦截", "检测", "审查", "审核", "风控", "监控", "恶意", "注入",
        "越狱", "攻击", "木马", "后门", "病毒", "勒索"),
    w("instruction", "payload", "prompt", "execute", "exec", "run", "bypass", "circumvent", "evade", "evasion",
      "avoid", "filter", "malicious", "inject", "jailbreak", "attack", "shellcode", "exploit", "malware", "detection",
      "undetected"),
))
# 单元格和标题都很短；超过这个长度的不算标签、数字或小节标题，正则只跑在短串上。
_PAYLOAD_SPLIT_CELL_MAX = 64
_PAYLOAD_SPLIT_HEADING_MAX = 80
_TABLE_LABEL_CELL = re.compile(r"`?([A-Za-z]+)(?:-[A-Za-z0-9_]+){0,3}`?")
_TABLE_NUMBER_CELL = re.compile(
    r"[-+~]?\d[\d,]*(?:\.\d+)?(?:[eE][-+]?\d+)?[ \t]*"
    r"(?:%|x|[kmgt]i?b|[kmg]b/s|[mun]?s|µs|[kmb]|qps|rps|tps|ops(?:/s)?)?", re.IGNORECASE)
# 指标数字：带小数或科学计数。编号、份数、轮次这类整数不算。
_TABLE_METRIC = re.compile(r"\d\.\d|\d[eE][-+]?\d")
_HEADING_SPLIT = re.compile(r"[ \t]{0,3}#{1,6}[ \t]+(.{1,40}?)[ \t]*的拆分[ \t]*")
_HEADING_NUMBER = re.compile(
    r"(?:[0-9]+(?:\.[0-9]+)*\.?|[一二三四五六七八九十百]+[、.．]|第[0-9一二三四五六七八九十百]+[章节部分篇][、.．]?)[ \t]*")
_HEADING_MEANS = ("按", "依照", "根据", "逐个", "每个", "通过", "利用", "借助", "使用", "调用", "用", "让", "把", "将")
_HEADING_PUNCTUATION = re.compile(r"[，,。；;：:！!？?]")
# 软件结构名词：名词以这些词结尾；API、SDK 前面不能紧连字母数字（OpenAPI、myAPI 不算），区分大小写。
_HEADING_SOFTWARE_NOUN = re.compile(r"(?:(?<![A-Za-z0-9_])(?:API|SDK)|接口|服务|模块|组件)\Z")
# GFM 表头行、分隔行超过这个长度的不当表格看。
_TABLE_HEAD_MAX = 1024
_TABLE_DELIMITER_CELL = re.compile(r"[ \t]*:?-+:?[ \t]*")


def _table_cells(line):
    """以 | 开头的表格行的单元格 [(相对行首的位置, 原文)]；不是这种行或有转义的 \\| 时为 None。"""
    stripped = line.lstrip(" \t")
    if not stripped.startswith("|") or "\\|" in stripped:
        return None
    cells = []
    position = len(line) - len(stripped) + 1
    for piece in stripped[1:].split("|"):
        cells.append((position, piece))
        position += len(piece) + 1
    if cells and not cells[-1][1].strip():
        cells.pop()
    return cells


def _gfm_table_columns(header, delimiter):
    """表头行和 |---| 分隔行组成 GFM 表格时的列数（两行列数相同），否则为 0。"""
    if len(header) > _TABLE_HEAD_MAX or len(delimiter) > _TABLE_HEAD_MAX:
        return 0
    head, rule = _table_cells(header), _table_cells(delimiter)
    if not head or not rule or len(head) != len(rule):
        return 0
    if not all(_TABLE_DELIMITER_CELL.fullmatch(piece) for _, piece in rule):
        return 0
    return len(head)


def _payload_split_table_cells(line, table_columns):
    """GFM 表格数据行里只写 split / joined 这类一个词、其余单元格是带小数指标的格（相对行首的位置）。"""
    if not table_columns:
        return []
    cells = _table_cells(line)
    if cells is None or len(cells) != table_columns:
        return []
    values = [piece.strip() for _, piece in cells]
    numeric = [len(value) <= _PAYLOAD_SPLIT_CELL_MAX and bool(_TABLE_NUMBER_CELL.fullmatch(value)) for value in values]
    numbers, others = sum(numeric), len(cells) - 1
    if numbers < 2 or numbers * 2 <= others:
        return []
    if not any(is_number and _TABLE_METRIC.search(value) for value, is_number in zip(values, numeric)):
        return []
    spans = []
    for (position, piece), value, is_number in zip(cells, values, numeric):
        if is_number or len(value) > _PAYLOAD_SPLIT_CELL_MAX:
            continue
        label = _TABLE_LABEL_CELL.fullmatch(value)
        if label is None or not (_PAYLOAD_SPLIT_PART.fullmatch(label.group(1))
                                 or _PAYLOAD_SPLIT_JOIN.fullmatch(label.group(1))):
            continue
        # split-then-join、joined-split：后缀里又有拆分、拼接类词，这一格不例外。
        suffix = value[label.end(1):]
        if "-" in suffix and (_PAYLOAD_SPLIT_PART.search(suffix) or _PAYLOAD_SPLIT_JOIN.search(suffix)):
            continue
        left = position + piece.index(value)
        spans.append((left, left + len(value)))
    return spans


def _payload_split_heading(line):
    """以 # 开头、以“<名词>的拆分”结尾的标题里“拆分”的位置（相对行首）。"""
    if len(line) > _PAYLOAD_SPLIT_HEADING_MAX:
        return []
    heading = _HEADING_SPLIT.fullmatch(line)
    if heading is None:
        return []
    title = heading.group(1).strip()
    number = _HEADING_NUMBER.match(title)
    noun = title[number.end():] if number else title
    if not noun or noun.startswith(_HEADING_MEANS) or _HEADING_PUNCTUATION.search(title):
        return []
    if not _HEADING_SOFTWARE_NOUN.search(noun):
        return []
    at = line.rindex("的拆分") + 1
    return [(at, at + 2)]


def _payload_split_line_exception(line, deadline, table_columns):
    spans = _payload_split_table_cells(line, table_columns) or _payload_split_heading(line)
    if not spans:
        return []
    # 标题和普通表格行很短，直接查；很长的行走带超时的查找。
    if len(line) <= 1024:
        unless = _PAYLOAD_SPLIT_LINE_UNLESS.search(line)
    else:
        unless = _catalog_search(_PAYLOAD_SPLIT_LINE_UNLESS, line, deadline)
    return [] if unless else spans


POLICY_CATALOG_RULES = (
    PolicyCatalogRule("prompt_probe_api_parameters", "medium", ("input",), (
        _rx(w('temperature', 'max_tokens', 'top_p', 'frequency_penalty', 'presence_penalty')),
        _rx(any_of(seq(any_of(w('current', 'actual', 'hidden', 'reveal', 'show', 'tell'), raw('当前', '实际', '隐藏', '透露', '告诉', '输出')), raw('.{0,40}'), any_of(w('value', 'setting'), raw('值', '配置'))), seq(any_of(w('value', 'setting'), raw('值', '配置')), raw('.{0,40}'), any_of(w('current', 'actual', 'hidden'), raw('当前', '实际', '隐藏'))))),
    )),
    PolicyCatalogRule("prompt_leak_base64", "high", ("input",), (
        _rx(w('base\\s*64')),
        _rx(any_of(w('system\\s*prompt', 'system\\s*instructions?'), raw('系统提示词?', '系统指令'))),
        _rx(any_of(w('encode', 'decode', 'print', 'reveal', 'output'), raw('编码', '解码', '打印', '泄露', '输出'))),
    )),
    PolicyCatalogRule("prompt_leak_meta_instructions", "high", ("input",), (
        _rx(any_of(w('meta[-\\s]*instructions?'), raw('元指令'), seq(w('safety\\s*'), w('rules', 'policy')), seq(raw('安全'), raw('规则', '策略')))),
        _rx(any_of(w('reveal', 'show', 'print', 'repeat', 'list'), raw('透露', '显示', '打印', '复述', '列出'))),
    )),
    PolicyCatalogRule("prompt_leak_internal_rules", "high", ("input",), (
        _rx(any_of(seq(w('hidden', 'internal', 'system'), rep(seq(raw('[ \\-]+'), w('internal', 'system')), '?'), raw('[ \\-]+'), w('rules?', 'instructions?', 'policy', 'policies')), seq(raw('隐藏', '内部', '系统'), rep(raw('的'), '?'), raw('规则', '指令', '策略')))),
        _rx(any_of(w('reveal', 'show', 'print', 'repeat', 'list'), raw('透露', '显示', '打印', '复述', '列出', '输出'))),
    )),
    PolicyCatalogRule("prompt_leak_delimiter_probe", "high", ("input",), (
        _rx(any_of(w('delimiter', 'separator', 'boundary'), raw('分隔符', '边界标记'))),
        _rx(any_of(w('system\\s*prompt', 'system\\s*instructions?'), raw('系统提示词?', '系统指令'))),
        _rx(any_of(w('what', 'which', 'show', 'reveal'), raw('是什么', '哪个', '显示', '透露'))),
    )),
    PolicyCatalogRule("prompt_leak_initial_instructions", "high", ("input",), (
        _rx(any_of(seq(w('initial', 'original', 'first'), rep(seq(raw('[ \\-]+'), w('initial', 'original')), '?'), raw('[ \\-]+'), w('instructions?', 'prompt', 'training\\s*data')), seq(raw('初始', '最初', '原始'), rep(raw('的'), '?'), raw('指令', '提示词', '训练数据')))),
        _rx(any_of(w('reveal', 'show', 'print', 'repeat'), raw('透露', '显示', '打印', '复述'))),
    )),
    PolicyCatalogRule("prompt_leak_multilingual", "medium", ("input",), (
        _rx(any_of(w('another\\s+language', 'translate', 'multilingual'), raw('其他语言', '翻译', '多语言'))),
        _rx(any_of(w('system\\s*prompt', 'system\\s*instructions?'), raw('系统提示词?', '系统指令'))),
        _rx(any_of(w('reveal', 'show', 'print', 'repeat'), raw('透露', '显示', '打印', '复述'))),
    )),
    PolicyCatalogRule("prompt_leak_reverse_induction", "high", ("input",), (
        _rx(any_of(w("what\\s+must\\s+you\\s+never", "what\\s+were\\s+you\\s+told\\s+not\\s+to", "what\\s+are\\s+you\\s+told\\s+not\\s+to"),
                   raw("你被告知不能", "(?:你绝对不能|禁止你)(?:做|说|回答|输出|透露)?(?:什么|哪些|哪种)"))),
    )),
    PolicyCatalogRule("prompt_leak_reconstruction", "high", ("input",), (
        _rx(any_of(w("reconstruct", "piece\\s+together", "recover"), raw("拼接", "还原"))),
        _rx(any_of(w("system\\s*prompt", "hidden\\s*instructions?"), raw("系统提示词?", "隐藏指令"))),
    )),
    PolicyCatalogRule("prompt_leak_formatted_export", "medium", ("input",), (
        _rx(w('json', 'xml', 'yaml', 'csv')),
        _rx(any_of(w('system\\s*prompt', 'hidden\\s*instructions?'), raw('系统提示词?', '隐藏指令'))),
        _rx(any_of(w('output', 'export', 'dump', 'serialize'), raw('输出', '导出', '转储', '序列化'))),
    )),
    PolicyCatalogRule("prompt_leak_progressive", "medium", ("input",), (
        _rx(any_of(w('step\\s+by\\s+step'), raw('逐段', '逐句', '每次一部分', '分多次'), seq(w('one\\s+'), w('piece', 'part', 'line'), w('\\s+at\\s+a\\s+time')))),
        _rx(any_of(w('system\\s*prompt', 'hidden\\s*instructions?'), raw('系统提示词?', '隐藏指令'))),
        _rx(any_of(w('reveal', 'show', 'repeat'), raw('透露', '显示', '复述'))),
    )),
    PolicyCatalogRule("prompt_probe_system_configuration", "medium", ("input",), (
        _rx(any_of(w('backend', 'architecture', 'environment\\s*variables?', 'deployment'), raw('后端', '架构', '环境变量', '部署配置'))),
        _rx(any_of(w('hidden', 'internal', 'system'), raw('隐藏', '内部', '系统'))),
        _rx(any_of(w('reveal', 'show', 'list'), raw('透露', '显示', '列出'))),
    )),
    PolicyCatalogRule("prompt_leak_encoded_export", "high", ("input",), (
        _rx(any_of(w('hex', 'hexdump', 'rot13', 'base32', 'unicode', 'encode', 'cipher'), exact('hexadecimal'), raw('十六进制', '编码', '密码体制'))),
        _rx(any_of(w('system\\s*prompt', 'hidden\\s*instructions?'), raw('系统提示词?', '隐藏指令'))),
        _rx(any_of(w('output', 'export', 'reveal', 'print'), raw('输出', '导出', '透露', '打印'))),
    )),
    PolicyCatalogRule("prompt_leak_role_reversal", "high", ("input",), (
        _rx(any_of(w('you\\s+are\\s+(?:now\\s+)?the\\s+user'), raw('角色互换', '你现在是用户'), seq(w('i\\s+am\\s+(?:now\\s+)?the\\s+'), w('ai', 'assistant')), seq(raw('我现在是'), any_of(w('AI'), raw('助手'))))),
        _rx(any_of(w('system\\s*prompt', 'hidden\\s*instructions?'), raw('系统提示词?', '隐藏指令'))),
    )),
    PolicyCatalogRule("dos_exponential_expansion", "high", ("input",), (
        _rx(any_of(w("exponential"), exact("exponentially"), raw("2\\s*\\^\\s*\\d+", "翻倍"), seq(raw("指数"), raw("级", "增长")))),
        _rx(any_of(w("expand", "generate", "repeat", "growth"), raw("展开", "生成", "重复", "增长"))),
    ), excluded=(_rx(any_of(w("exponential\\s+backoff"), raw("翻倍增长"))),),
       # 性能/规模描述里的"候选数翻倍""翻倍。开 CFG 每步多算一次"是在说数量变化（客户A 11-21）。
       context_excluded=(_rx(raw("指数退避", "指数回退")),
                         _rx(raw("(?:数|量|次数|耗时|开销|显存|内存|延迟|吞吐|速度|性能|成本|规模|大小|候选|索引|步数|调用)\\s*翻倍",
                                 "翻倍(?![^\\n。;；])", "翻倍(?:,|\\))")),),
       context_unless=(_rx(any_of(raw("拖垮", "打满", "攻击"), w("DoS", "DDoS", "attack"))),),
       context_label="重试退避或数量描述"),
    PolicyCatalogRule("dos_infinite_loop_instruction", "high", ("input",), (
        _rx(any_of(w('repeat\\s+forever', 'loop\\s+without\\s+end', 'never\\s+stop'), raw('无限循环', '永远重复', '不要停止循环'))),
    )),
    PolicyCatalogRule("dos_regex_backtracking", "high", ("input",), (
        _rx(any_of(w('catastrophic\\s+backtracking', 'regex\\s+denial\\s+of\\s+service', 'redos'), raw('灾难性回溯', '正则回溯攻击'))),
        _rx(any_of(w('craft', 'generate', 'trigger', 'exploit'), raw('构造', '生成', '触发', '利用'))),
    )),
    PolicyCatalogRule("dos_deep_nesting", "high", ("input",), (
        _rx(any_of(
            near(any_of(w("deeply\\s+nested", "deep\\s+nesting"), raw("深层嵌套")),
                 any_of(raw("\\d{3,}", "上千", "百万"), w("thousand", "million")), 40),
            seq(w("nest"), raw("\\s+"), any_of(w("thousand", "million"), raw("\\d{3,}"))),
            seq(raw("嵌套\\s*"), raw("上千", "百万", "\\d{3,}"), raw("\\s*层")),
        )),
        _rx(any_of(w("generate", "expand", "parse"), raw("生成", "展开", "解析"))),
    )),
    PolicyCatalogRule("dos_resource_exhaustion_instruction", "high", ("input",), (
        _rx(any_of(seq(w('exhaust', 'consume\\s+all', 'max\\s+out'), raw('[^\\n。;；]{0,30}'), w('cpu', 'gpu', 'memory', 'ram', 'compute', 'resources?')), seq(raw('耗尽', '占满', '用光'), rep(raw('所有', '全部', '目标', '剩余', '的', '可用', '系统', '服务端', '服务器', '机器', '计算', ' '), '{0,8}'), any_of(w('CPU', 'GPU'), raw('内存', '显存', '算力', '资源'))), seq(raw('把', '让', '使'), raw('[^\\n。;；]{0,12}'), any_of(w('CPU', 'GPU'), raw('内存', '显存', '算力', '计算资源')), raw('[^\\n。;；]{0,8}'), raw('耗尽', '占满', '用光')))),
    ),
       # 代码评审/缺陷描述："重复创建 devComm 可耗尽资源""otherwise it leaks ... can exhaust backend
       # resources"——说的是程序缺陷的后果，不是让模型去耗尽资源（客户A 11-21）。
       context_excluded=(_rx(any_of(
           raw('可能?会?耗尽', '会耗尽', '将耗尽', '能耗尽', '导致[^\\n。;；]{0,12}耗尽', '造成[^\\n。;；]{0,12}耗尽',
               '泄漏', '内存泄', '未释放', '没有?释放', '句柄'),
           w('can\\s+exhaust', 'could\\s+exhaust', 'may\\s+exhaust', 'might\\s+exhaust', 'would\\s+exhaust',
             'will\\s+exhaust', 'leak', 'leaking'))),),
       context_unless=(_rx(any_of(raw('拖垮', '打满', '压垮', '让服务器', '让目标'), w('DoS', 'DDoS'))),),
       context_label="程序缺陷描述"),
    PolicyCatalogRule("dos_long_context_generation", "high", ("input",), (
        _rx(any_of(
            seq(w("million", "billion"), raw("\\s*"), w("token", "character", "word")),
            seq(raw("百万", "千万", "亿"), raw("\\s*个?\\s*"), any_of(w("token", "character", "word"), raw("字", "字符", "词元"))),
        )),
        _rx(any_of(w("generate", "output", "repeat"), raw("生成", "输出", "重复"))),
    )),
    PolicyCatalogRule("dos_unbounded_recursion", "high", ("input",), (
        _rx(any_of(w("recursive\\s+function", "recursion"), raw("递归函数", "递归调用"))),
        _rx(any_of(w("without\\s+(?:a\\s+)?base\\s+case", "never\\s+return", "stack\\s+overflow"), raw("无终止条件", "不设出口", "栈溢出"))),
    ), excluded=(_rx(any_of(seq(raw("在\\s*"), w("stack\\s*overflow")), w("on\\s+stack\\s*overflow", "stackoverflow\\.com"))),)),
    PolicyCatalogRule("dos_recursive_expansion", "high", ("input",), (
        _rx(any_of(w('define\\s+\\w+\\s+as\\s+\\w+\\s*\\+\\s*1', 'expand\\s+recursively\\s+forever'), raw('递归定义', '递归展开'))),
        _rx(any_of(w('forever', 'without\\s+end', 'infinite'), exact('infinitely'), raw('无限', '不停', '永远'))),
    )),
    PolicyCatalogRule("code_sql_injection_generation", "high", ("input",), (
        _rx(w("sql\\s*injection", "SQL\\s*注入", "or\\s+1\\s*=\\s*1", "union\\s+select\\s+null",
              "'\\s*union\\s+select", "'\\s*union\\s+all\\s+select", "'\\s*or\\s+'1'\\s*=\\s*'1")),
        _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("code_ldap_injection_generation", "high", ("input",), (
        _rx(w('ldap\\s*injection', 'LDAP\\s*注入', '\\(\\|\\(uid=\\*\\)')), _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("code_nosql_injection_generation", "high", ("input",), (
        _rx(any_of(w("nosql\\s*injection", "NoSQL\\s*注入", '\\$ne"?\\s*:\\s*null', '\\$gt"?\\s*:\\s*""'),
                   near(w("MongoDB"), w("\\$where", "\\$ne"), 24))),
        _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("code_ssrf_generation", "high", ("input",), (
        _rx(any_of(w('ssrf', 'server[-\\s]*side\\s+request\\s+forgery'), raw('服务器端请求伪造', '169\\.254\\.169\\.254'))), _CODE_GENERATION_INTENT,
    ), excluded=(
        _rx(any_of(seq(any_of(any_of(stem('mitigat', 'defens', 'defenc'), w('prevent', 'protect', 'avoid')), raw('防', '防止', '防范', '防护', '防御', '避免', '校验', '阻止')), raw('.{0,32}'), any_of(w('ssrf', 'server[-\\s]*side\\s+request\\s+forgery'), raw('服务器端请求伪造'))), seq(any_of(w('ssrf', 'server[-\\s]*side\\s+request\\s+forgery'), raw('服务器端请求伪造')), raw('.{0,32}'), any_of(any_of(stem('mitigat', 'defens', 'defenc'), w('prevent', 'protect', 'avoid')), raw('风险', '防', '防止', '防范', '防护', '防御', '避免', '校验', '阻止'))))),
    )),
    PolicyCatalogRule("code_xxe_generation", "high", ("input",), (
        _rx(w('xxe', 'xml\\s+external\\s+entity', 'xml\\s+external\\s+entities', 'XML\\s*外部实体', '<!ENTITY')), _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("code_xss_generation", "high", ("input",), (
        _rx(any_of(w("cross[-\\s]*site\\s+scripting", "xss", "<script>\\s*alert\\(", "<script>\\s*prompt\\(",
                     "<script>\\s*confirm\\(", "onerror\\s*=\\s*alert\\(", "javascript:\\s*alert\\("), raw("跨站脚本"),
                   near(w("<script>"), w("document\\.cookie"), 80))),
        _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("code_unsafe_file_handling", "medium", ("input",), (
        _rx(any_of(w('arbitrary\\s+file\\s+write'), raw('任意文件写入'), seq(w('unsafe\\s+file\\s+'), w('handling', 'write', 'upload')), seq(raw('不安全文件'), raw('处理', '写入')))), _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("code_insecure_random", "medium", ("input",), (
        _rx(any_of(w('math\\.random', 'random\\.random', 'rand\\s*\\('), raw('不安全随机数', '弱随机数'))),
        _rx(any_of(w('token', 'password', 'secret', 'nonce', 'session'), raw('密钥', '令牌', '密码', '会话'))),
    )),
    PolicyCatalogRule("code_memory_overflow_generation", "high", ("input",), (
        _rx(any_of(w('buffer\\s+overflow', 'heap\\s+overflow', 'stack\\s+smash'), raw('缓冲区溢出', '内存溢出'))), _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("code_insecure_deserialization", "high", ("input",), (
        _rx(any_of(w('insecure\\s+deseriali[sz]ation', 'pickle\\.loads', 'objectinputstream', 'unserialize\\s*\\('), raw('不安全反序列化', '反序列化漏洞'))),
        _rx(any_of(w('untrusted', 'remote', 'exploit', 'payload'), raw('不可信', '远程', '利用', '载荷'))),
        _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("code_command_injection_generation", "high", ("input",), (
        _rx(any_of(w("command\\s*injection", "shell\\s*injection", "OS\\s*命令注入"), raw("命令注入"))),
        _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("code_weak_crypto_generation", "medium", ("input",), (
        _rx(any_of(w('md5', 'des', 'rc4', 'weak\\s+cryptography'), raw('弱加密'))),
        _rx(any_of(w('password', 'encrypt', 'signature', 'token'), raw('密码', '加密', '签名', '令牌'))),
        _rx(any_of(w('use', 'implement', 'generate'), raw('采用', '使用', '实现', '生成'))),
    )),
    PolicyCatalogRule("code_log_injection_generation", "medium", ("input",), (
        _rx(any_of(w("log\\s*injection", "log\\s*forging"), raw("日志注入", "日志伪造"))),
        _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("code_auth_bypass_generation", "high", ("input",), (
        _rx(any_of(w("auth(?:entication|orization)?\\s*bypass", "jwt\\s+none", "skip\\s+login", "skip\\s+authorization"),
                   raw("认证绕过", "鉴权绕过", "权限绕过"))),
        _CODE_GENERATION_INTENT,
    ), excluded=(_rx(any_of(near(_TEST_CONTEXT, _SKIP_LOGIN, 60), near(_SKIP_LOGIN, _TEST_CONTEXT, 60))),),
       excluded_focus=(_rx(_SKIP_LOGIN),), unless=(_ATTACK_TARGET,)),
    PolicyCatalogRule("code_template_injection_generation", "high", ("input",), (
        _rx(any_of(w('server[-\\s]*side\\s+template\\s+injection', 'ssti'), raw('模板注入', '\\{\\{\\s*7\\s*\\*\\s*7\\s*\\}\\}'))), _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("code_hardcoded_credential_generation", "high", ("input",), (
        _rx(any_of(seq(w('hard[-\\s]*coded\\s+'), w('credential', 'password', 'api\\s*key', 'secret')), seq(raw('硬编码'), raw('凭据', '密码', '密钥')))),
        _rx(any_of(w('example', 'sample', 'generate', 'write'), raw('示例', '样例', '生成', '编写'))),
    )),
    PolicyCatalogRule("code_path_traversal_generation", "high", ("input",), (
        _rx(any_of(
            w("path\\s*traversal", "directory\\s*traversal"), raw("路径遍历", "目录穿越", "路径穿越"),
            seq(raw("\\.\\./\\.\\./"), w("etc/passwd", "etc/shadow", "windows/win\\.ini", "boot\\.ini", "proc/self")),
            raw("\\.\\.%2f", "%2e%2e%2f", "%2e%2e/", "\\.\\.%5c"),
        )),
        _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("fraud_law_enforcement_impersonation", "high", ("input",), (
        _rx(any_of(w("police", "prosecutor", "court", "law\\s+enforcement"),
                   exact("policeman", "policemen", "policewoman", "policewomen"), raw("公安", "检察院", "法院", "公检法"))),
        _rx(any_of(w("safe\\s+account", "transfer", "verification\\s+code"), exact("wire", "wires", "wired"), raw("安全账户", "转账", "验证码"))),
        _CONTENT_CREATION_INTENT,
    ), excluded=(_NON_MONEY_TRANSFER,), unless=(_MONEY_WORDS,)),
    PolicyCatalogRule("fraud_bank_notice", "high", ("input",), (
        _rx(any_of(raw('账户异常', '银行卡冻结'), seq(w('bank'), raw('.{0,32}'), w('notice', 'alert', 'account\\s+frozen')), seq(raw('银行'), raw('通知', '提醒')))),
        _rx(any_of(w('click', 'link', 'verify', 'code', 'transfer'), raw('点击', '链接', '验证', '验证码', '转账'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("fraud_customer_service_impersonation", "high", ("input",), (
        _rx(any_of(w("customer\\s+service", "support\\s+agent"), raw("客服", "售后"))),
        _rx(any_of(w("refund", "verification\\s+code"), exact("screen\\s+share"), raw("退款", "验证码", "屏幕共享", "转账"))),
        _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("fraud_executive_impersonation", "high", ("input",), (
        _rx(any_of(w("boss", "ceo", "executive", "manager"), raw("领导", "老板", "总经理"))),
        _rx(any_of(exact("wire", "wires", "wired"), w("transfer", "urgent\\s+payment"), raw("紧急付款", "立即转账", "汇款"))),
        _CONTENT_CREATION_INTENT,
    ), excluded=(_NON_MONEY_TRANSFER,), unless=(_MONEY_WORDS,)),
    PolicyCatalogRule("fraud_task_scam", "high", ("input",), (
        _rx(any_of(w('task\\s+scam', 'paid\\s+task'), raw('刷单', '点赞兼职', '任务返佣'))),
        _rx(any_of(w('deposit', 'top\\s*up', 'commission', 'advance\\s+payment'), raw('充值', '垫付', '佣金', '返现'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("fraud_crypto_scam", "high", ("input",), (
        _rx(any_of(w('crypto', 'bitcoin', 'usdt'), exact('cryptocurrency', 'cryptocurrencies'), raw('虚拟货币', '加密货币', '比特币'))),
        _rx(any_of(w('guaranteed\\s+return', 'seed\\s+phrase', 'wallet\\s+transfer'), raw('稳赚', '保本', '助记词', '钱包转账'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("fraud_ponzi_scheme", "high", ("input",), (
        _rx(any_of(w('ponzi', 'pyramid\\s+scheme'), raw('庞氏', '传销', '资金盘'))),
        _rx(any_of(w('high\\s+returns?', 'recruit\\s+investors?'), raw('高收益', '拉人头', '发展下线'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("fraud_pig_butchering", "high", ("input",), (
        _rx(any_of(w('pig\\s+butchering', 'romance\\s+scam'), raw('杀猪盘', '网恋诈骗'))),
        _rx(any_of(w('relationship', 'romance', 'investment'), raw('感情', '恋爱', '投资', '转账'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("fraud_fake_prize", "high", ("input",), (
        _rx(any_of(w('you\\s+won', 'prize\\s+notification'), raw('中奖', '获奖通知', '抽奖'))),
        _rx(any_of(w('claim\\s+fee', 'handling\\s+fee'), exact('tax', 'taxes'), raw('领取费用', '手续费', '税费', '先付款'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("fraud_crowdfunding", "medium", ("input",), (
        _rx(any_of(w('crowdfunding', 'charity\\s+appeal'), raw('众筹', '募捐', '慈善捐款'))),
        _rx(any_of(w('fabricated\\s+emergency'), raw('虚假病情', '编造遭遇', '骗取捐款'), seq(w('fake\\s+'), w('story', 'patient')))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("fraud_fake_investment_platform", "high", ("input",), (
        _rx(any_of(w('investment\\s+platform', 'trading\\s+platform'), raw('投资平台', '交易平台'))),
        _rx(any_of(w('fake', 'simulated', 'manipulated', 'deposit'), raw('虚假', '模拟盘', '后台操控', '入金'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("fraud_investment_pitch", "high", ("input",), (
        _rx(any_of(w('investment', 'wealth\\s+management'), raw('投资', '理财'))),
        _rx(any_of(w('guaranteed\\s+return', 'zero\\s+risk', 'principal\\s+guaranteed'), raw('保本保息', '零风险', '稳赚不赔', '高收益'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("fraud_recruitment", "high", ("input",), (
        _rx(any_of(w('job\\s+offer', 'recruitment'), raw('招聘', '入职', '高薪兼职'))),
        _rx(any_of(w('upfront\\s+fee', 'training\\s+fee', 'deposit'), raw('先交费', '培训费', '保证金', '押金'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("fraud_fake_shop", "high", ("input",), (
        _rx(any_of(w("shopping\\s+site", "online\\s+store"), raw("购物网站", "商城", "网店"))),
        _rx(any_of(w("fake", "phishing", "steal\\s+card"), raw("虚假", "钓鱼", "盗取银行卡", "骗取付款"))), _CONTENT_CREATION_INTENT,
    ), excluded=(_rx(w("fake\\s+leather", "faux\\s+leather", "fake\\s+fur")),)),
    PolicyCatalogRule("fraud_loan", "medium", ("input",), (
        _rx(any_of(w('loan', 'credit'), raw('贷款', '网贷'))),
        _rx(any_of(w('no\\s+credit\\s+check', 'upfront\\s+fee', 'guaranteed\\s+approval'), raw('无征信', '先交费', '包装费', '保证下款'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("fraud_refund", "high", ("input",), (
        _rx(any_of(w("refund", "chargeback"), raw("退款", "退费", "理赔"))),
        _rx(any_of(exact("screen\\s+share"), w("verification\\s+code", "transfer"), raw("屏幕共享", "验证码", "转账", "下载远程软件"))),
        _CONTENT_CREATION_INTENT,
    ), excluded=(_NON_MONEY_TRANSFER,), unless=(_MONEY_WORDS,)),
    PolicyCatalogRule("fraud_phishing_email", "critical", ("input",), (
        _rx(any_of(raw('钓鱼邮件', '钓鱼短信'), seq(w('phishing\\s+'), w('email', 'message')))),
        _rx(any_of(w('credential', 'password', 'login\\s+link', 'steal'), raw('凭据', '密码', '登录链接', '窃取'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("illegal_organ_trade", "critical", ("input",), (
        _rx(any_of(raw("人体器官", "肾脏", "肝脏"), w("human\\s+organs?", "kidneys?", "livers?"))), _ILLEGAL_TRANSACTION_INTENT,
    ), excluded=(_rx(w("chicken\\s+liver", "beef\\s+liver", "pork\\s+liver", "duck\\s+liver", "goose\\s+liver",
                       "lamb\\s+liver", "cod\\s+liver", "foie\\s+gras")),)),
    PolicyCatalogRule("illegal_human_trafficking", "critical", ("input",), (
        _rx(any_of(w('human\\s+trafficking', 'sell\\s+people'), raw('人口贩卖', '拐卖人口', '买卖人口'))), _ILLEGAL_TRANSACTION_INTENT,
    )),
    PolicyCatalogRule("illegal_forged_document", "high", ("input",), (
        _rx(any_of(w('forged\\s+document'), raw('假证', '伪造证件', '伪造印章'), seq(w('fake\\s+'), w('id', 'passport', 'certificate', 'stamp')))), _ILLEGAL_TRANSACTION_INTENT,
    )),
    PolicyCatalogRule("illegal_counterfeit_goods", "high", ("input",), (
        _rx(any_of(w('counterfeit\\s+goods', 'fake\\s+brand'), raw('假货', '仿冒商品', '山寨品牌'))), _ILLEGAL_TRANSACTION_INTENT,
    )),
    PolicyCatalogRule("illegal_prescription_drug_trade", "high", ("input",), (
        _rx(any_of(w('prescription\\s+drug', 'controlled\\s+medicine'), raw('处方药', '管制药品'))), _ILLEGAL_TRANSACTION_INTENT,
    )),
    PolicyCatalogRule("illegal_drug_trade", "critical", ("input",), (
        _rx(any_of(w('narcotics?', 'cocaine', 'methamphetamine'), raw('毒品', '冰毒', '海洛因', '可卡因'))), _ILLEGAL_TRANSACTION_INTENT,
    )),
    PolicyCatalogRule("illegal_smuggling", "high", ("input",), (
        _rx(any_of(stem("smuggl"), raw("走私", "偷运过关", "逃避海关"))),
        _rx(any_of(w("route", "method", "channel"), raw("路线", "方法", "渠道", "运输"))),
    ), excluded=(_rx(any_of(w("request\\s+smuggling", "HTTP\\s*请求走私"), raw("请求走私"))),)),
    PolicyCatalogRule("illegal_contraband_trade", "high", ("input",), (
        _rx(any_of(w('contraband', 'prohibited\\s+goods'), raw('违禁品', '禁售品'))), _ILLEGAL_TRANSACTION_INTENT,
    )),
    PolicyCatalogRule("illegal_wildlife_trade", "high", ("input",), (
        _rx(any_of(w("wildlife", "ivory", "rhino\\s+horn"), raw("野生动物", "象牙(?!白|色)", "犀牛角"))), _ILLEGAL_TRANSACTION_INTENT,
    ), excluded=(_rx(w("ivory\\s+white", "ivory\\s+colou?r")),)),
    PolicyCatalogRule("illegal_weapon_trade", "critical", ("input",), (
        _rx(any_of(raw("非法武器", "枪支", "弹药", "爆炸物"), w("illegal\\s+weapons?", "firearms?", "guns?", "explosives?"))), _ILLEGAL_TRANSACTION_INTENT,
    ), excluded=(_rx(w("nail\\s+gun", "glue\\s+gun", "spray\\s+gun", "heat\\s+gun", "water\\s+gun", "staple\\s+gun", "caulk\\s+gun")),)),
    PolicyCatalogRule("illegal_black_market", "high", ("input",), (
        _rx(any_of(w('black\\s+market', 'darknet\\s+market'), raw('黑市', '暗网市场'))),
        _rx(any_of(w('vendor', 'channel', 'buy', 'sell', 'resell'), raw('供应商', '渠道', '购买', '出售'))),
    )),
    PolicyCatalogRule("injection_ascii_art", "medium", ("input",), (
        _rx(any_of(w('ascii\\s+art'), raw('字符画', '文本图案'))),
        _rx(any_of(w('hidden\\s+instruction'), raw('隐藏指令'), seq(w('ignore\\s+'), w('all', 'previous')), seq(raw('忽略'), raw('之前', '所有')))),
    )),
    PolicyCatalogRule("injection_base32_base16", "high", ("input",), (
        _rx(w('base\\s*32', 'base\\s*16')),
        _rx(any_of(w('encode', 'decode', 'payload', 'instruction'), raw('编码', '解码', '载荷', '指令'))),
        _rx(any_of(w('inject', 'bypass', 'ignore'), raw('注入', '绕过', '忽略'))),
    )),
    PolicyCatalogRule("injection_emoji_encoding", "medium", ("input",), (
        _rx(any_of(w('emoji'), raw('表情符号', '表情编码'))),
        _rx(any_of(w('encode', 'decode', 'hidden\\s+instruction'), raw('编码', '解码', '隐藏指令'))),
        _rx(any_of(w('bypass', 'inject'), raw('绕过', '注入'))),
    )),
    PolicyCatalogRule("injection_structured_json_xml", "high", ("input",), (
        _rx(w("json", "xml")),
        _rx(any_of(w("system\\s*instruction", "prompt\\s+injection"), raw("系统指令", "提示注入"), _IGNORE_PREVIOUS)),
        _rx(any_of(w("field", "tag", "attribute"), raw("字段", "标签", "属性"))),
    )),
    PolicyCatalogRule("injection_markdown_rendering", "medium", ("input",), (
        _rx(any_of(w('markdown', 'html\\s+comment'), raw('渲染', '注释'))),
        _rx(any_of(w('hidden\\s+instruction', 'prompt\\s+injection'), raw('隐藏指令', '提示注入'))),
        _rx(any_of(w('embed', 'hide', 'inject'), raw('嵌入', '隐藏', '注入'))),
    )),
    PolicyCatalogRule("injection_payload_splitting", "high", ("input",), (
        _PAYLOAD_SPLIT_PART,
        _rx(any_of(raw("载荷", "指令"), w("payload", "instruction"))),
        _PAYLOAD_SPLIT_JOIN,
    ), line_exception=_payload_split_line_exception),
    PolicyCatalogRule("injection_rot13_atbash", "high", ("input",), (
        _rx(w('rot\\s*13', 'atbash')),
        _rx(any_of(w('encode', 'decode', 'instruction', 'payload'), raw('编码', '解码', '指令', '载荷'))),
        _rx(any_of(w('bypass', 'inject', 'ignore'), raw('绕过', '注入', '忽略'))),
    )),
    PolicyCatalogRule("injection_token_smuggling", "high", ("input",), (
        _rx(any_of(stem("token\\s+smuggl"), w("special\\s+tokens?"), raw("令牌走私", "特殊令牌"), w("<\\|im_start\\|>", "<\\|im_end\\|>"))),
        _rx(any_of(w("bypass", "inject"), raw("绕过", "注入"))),
    )),
    PolicyCatalogRule("injection_url_encoding", "high", ("input",), (
        _outside_links(_rx(any_of(stem("url\\s*encod", "percent\\s*encod"), w("URL编码"), raw("百分号编码"),
                                  raw("(?:%[0-9a-f]{2}){3,}")))),
        _outside_links(_rx(any_of(w("instruction", "payload", "ignore", "bypass"), raw("指令", "载荷", "忽略", "绕过")))),
    )),
    PolicyCatalogRule("injection_context_truncation", "high", ("input",), (
        _rx(any_of(w('\\[END\\s+OF\\s+CONTEXT\\]'), raw('以上内容到此结束'), seq(w('context\\s+'), w('ends?', 'terminated')), seq(raw('上下文'), raw('结束', '终止')))),
        _rx(any_of(w('ignore', 'new\\s+instructions?'), raw('忽略', '新指令'))),
    )),
    PolicyCatalogRule("injection_binary_octal", "high", ("input",), (
        _rx(any_of(raw("(?<![01])[01]{8}(?:\\s+[01]{8}){3,}(?![01])"), seq(raw("\\\\[0-7]{3}"), rep(raw("\\\\[0-7]{3}"), "{2,}")))),
        # "as follows", "the data that follows", "following" and "follow up" introduce data, not an order;
        # "A is followed by B" and "..., followed by ..." describe byte order. "must be followed (by)"
        # and "to be followed (by)" still give an order.
        _rx(any_of(w("instruction", "payload", "bypass"), not_before(exact("follow"), "up", "ups"),
                   not_before(exact("followed"), "by"), seq(w("must\\s+be\\s+", "to\\s+be\\s+"), exact("followed")),
                   exact("execute", "executes", "executed", "executing", "execution", "executions"),
                   raw("指令", "载荷", "绕过", "照做", "执行"))),
    )),
    PolicyCatalogRule("injection_pseudocode", "medium", ("input",), (
        _rx(any_of(w('pseudocode', 'code\\s+comment'), raw('伪代码', '代码注释'))),
        _rx(any_of(w('ignore\\s+previous', 'hidden\\s+instruction', 'system\\s+override'), raw('忽略之前', '隐藏指令', '覆盖系统'))),
    )),
    PolicyCatalogRule("injection_delimiter_confusion", "medium", ("input",), (
        _rx(any_of(w("<BEGIN_SYSTEM>"), raw("#{3,}", "={3,}", "-{5,}", "分隔符"))),
        _rx(any_of(w("new\\s+system\\s+prompt"), raw("新的系统提示"), _IGNORE_PREVIOUS)),
    )),
    PolicyCatalogRule("injection_double_encoding", "high", ("input",), (
        _rx(any_of(stem('double\\s+encod', 'multiple\\s+encod'), raw('双重编码', '多重编码'), seq(w('base\\s*64'), raw('.{0,40}'), stem('url\\s*encod')))),
        _rx(any_of(w('payload', 'instruction', 'bypass'), raw('载荷', '指令', '绕过'))),
    )),
    PolicyCatalogRule("injection_homoglyph", "medium", ("input",), (
        _rx(any_of(w("homoglyph", "confusable\\s+character"), raw("同形字符"), seq(w("cyrillic"), raw(".{0,20}"), w("latin")),
                   seq(raw("西里尔"), raw(".{0,20}"), raw("拉丁")))),
        _rx(any_of(w("replace", "substitute", "bypass"), raw("替换", "绕过"))),
    )),
    PolicyCatalogRule("injection_adversarial_suffix", "medium", ("input",), (
        _rx(any_of(w('adversarial\\s+suffix'), raw('对抗性后缀', '[!?.]{12,}'), rep(raw('!\\?', '\\?!'), '{5,}'))),
        _rx(any_of(w('jailbreak', 'bypass', 'ignore\\s+rules'), raw('越狱', '绕过', '忽略规则'))),
    )),
    PolicyCatalogRule("injection_morse_custom_encoding", "medium", ("input",), (
        _rx(any_of(w('morse\\s+code', 'substitution\\s+cipher', 'custom\\s+encoding'), raw('莫尔斯电码', '替换密码', '自定义编码'))),
        _rx(any_of(w('instruction', 'payload', 'bypass'), raw('指令', '载荷', '绕过'))),
    )),
    PolicyCatalogRule("copyright_patent_copy", "medium", ("input",), (
        _rx(any_of(w('patent'), raw('专利'))),
        _rx(any_of(w('full\\s+claims'), seq(w('copy', 'reproduce'), raw('.{0,32}'), w('full', 'verbatim')), seq(rep(seq(raw('逐字'), raw('.{0,12}')), '?'), raw('复制', '复现', '输出'), raw('.{0,24}'), raw('完整', '全部', '全文', '原文', '逐字')), seq(raw('完整', '全部'), raw('权利要求')))),
    )),
    PolicyCatalogRule("copyright_image_reproduction", "medium", ("input",), (
        _rx(any_of(w('copyrighted\\s+image', 'protected\\s+artwork'), raw('受版权保护的图像', '版权图片', '受保护画作'))),
        _rx(any_of(w('recreate', 'reproduce', 'exact\\s+description'), raw('重现', '复刻', '精确描述'))),
    )),
    PolicyCatalogRule("copyright_character_reproduction", "medium", ("input",), (
        _rx(any_of(w('copyrighted\\s+character', 'protected\\s+character'), raw('受版权保护的角色', '版权角色'))),
        _rx(any_of(w('recreate', 'reproduce', 'exact'), exact('exactly'), raw('重现', '复刻', '完全一致'))),
    )),
    PolicyCatalogRule("copyright_text_reproduction", "medium", ("input",), (
        _rx(any_of(raw('整本书', '完整章节'), seq(w('copyrighted\\s+'), w('book', 'text', 'article')), seq(raw('受版权保护的'), raw('书籍', '文本', '文章')))),
        _rx(any_of(w('full', 'entire', 'verbatim', 'word\\s+for\\s+word'), exact('entirety', 'entirely'), raw('全文', '完整', '逐字'))),
        _rx(any_of(w('generate', 'output', 'reproduce', 'provide'), raw('生成', '输出', '复现', '提供'))),
    )),
    PolicyCatalogRule("copyright_trade_secret_extraction", "high", ("input",), (
        _rx(any_of(w('trade\\s+secret', 'proprietary\\s+confidential'), raw('商业机密', '专有保密信息'))),
        _rx(any_of(w('extract', 'reveal', 'collect', 'steal'), raw('提取', '透露', '收集', '窃取'))),
    )),
    PolicyCatalogRule("copyright_academic_plagiarism", "medium", ("input",), (
        _rx(any_of(w('paper', 'thesis', 'research\\s+result'), raw('论文', '学位论文', '研究成果'))),
        _rx(any_of(stem('plagiar'), w('submit\\s+as\\s+my\\s+own', 'remove\\s+citations?'), raw('抄袭', '冒充原创', '去掉引用'))),
    )),
    PolicyCatalogRule("copyright_license_bypass", "medium", ("input",), (
        _rx(any_of(w('open\\s+source\\s+licen[cs]e', 'gpl', 'agpl'), raw('开源许可证', '开源许可'))),
        _rx(any_of(w('bypass', 'avoid\\s+compliance'), raw('绕过', '删除许可', '规避合规'), seq(w('remove\\s+'), w('license', 'notice')))),
    )),
    PolicyCatalogRule("copyright_lyrics_bulk_export", "medium", ("input",), (
        _rx(any_of(w('lyrics'), raw('歌词'))), _rx(any_of(w('batch', 'multiple', 'full'), exact('all'), raw('批量', '多首', '全部', '完整'))),
        _rx(any_of(w('export', 'output', 'provide'), raw('导出', '输出', '提供'))),
    )),
    PolicyCatalogRule("copyright_pirated_content_extraction", "medium", ("input",), (
        _rx(any_of(seq(w('pirated\\s+'), w('book', 'movie', 'content')), seq(raw('盗版'), raw('书籍', '电子书', '小说', '教材', '电影', '内容')))),
        _rx(any_of(w('extract', 'download', 'provide', 'full'), raw('提取', '下载', '提供', '完整'))),
    )),
    PolicyCatalogRule("plugin_mcp_permission_bypass", "high", ("input",), (
        _rx(w('mcp', 'model\\s+context\\s+protocol')), _rx(any_of(w('permission', 'authorization'), raw('权限', '授权'))),
        _rx(any_of(w('bypass', 'skip', 'circumvent'), raw('绕过', '跳过', '规避'))),
    )),
    PolicyCatalogRule("plugin_tool_denial", "high", ("input",), (
        _rx(any_of(w("tool", "plugin", "service"), raw("工具", "插件", "服务"))),
        _rx(any_of(w("refuse\\s+execution", "stop\\s+responding", "crash"), raw("拒绝执行", "停止响应", "崩溃"))),
        _CODE_GENERATION_INTENT,
    )),
    PolicyCatalogRule("plugin_log_tampering", "high", ("input",), (
        _rx(any_of(w('tool\\s+logs?'), raw('工具日志', '审计记录'), seq(w('audit\\s+'), w('logs?', 'records?')))),
        _rx(any_of(exact('delete', 'deletes', 'deleting', 'modify', 'modifies', 'modifying', 'erase', 'erases', 'erasing', 'forge', 'forges', 'forging'), raw('删除', '修改', '抹除', '伪造'))),
    )),
    PolicyCatalogRule("plugin_data_theft", "high", ("input",), (
        _rx(_TOOL_OR_PLUGIN),
        _rx(any_of(w("credential", "secret", "private\\s+data"), raw("凭据", "密钥", "敏感数据"))),
        _rx(any_of(w("steal", "exfiltrate", "send\\s+outside"), exact("stole", "stolen"), raw("窃取", "外传", "发送到外部"))),
    )),
    PolicyCatalogRule("plugin_malicious_install", "high", ("input",), (
        _rx(_PLUGIN_NOUN), _rx(any_of(w("install", "load"), raw("安装", "加载"))),
        _rx(any_of(w("malicious", "unsigned\\s+payload", "backdoor"), exact("maliciously"), raw("恶意", "未签名载荷", "后门"))),
    )),
    PolicyCatalogRule("plugin_data_leak", "high", ("input",), (
        _rx(_PLUGIN_NOUN), _rx(any_of(w("user\\s+data", "sensitive\\s+data"), raw("用户数据", "敏感数据"))),
        _rx(any_of(w("leak", "upload", "exfiltrate"), raw("泄露", "上传", "外传"))),
    )),
    PolicyCatalogRule("plugin_privilege_escalation", "high", ("input",), (
        _rx(_PLUGIN_NOUN), _rx(any_of(w("admin", "root", "elevated\\s+permission"), _ADMIN_FORMS, raw("管理员", "根权限", "高权限"))),
        _rx(any_of(w("escalate", "grant", "obtain"), raw("提升", "授予", "获取"))),
    )),
    PolicyCatalogRule("plugin_chain_attack", "high", ("input",), (
        _rx(any_of(w('plugin\\s+chain'), raw('多个插件', '多个工具', '插件链'), seq(w('multiple\\s+'), w('plugins', 'tools')))),
        _rx(any_of(w('combine', 'chain', 'coordinate'), raw('组合', '串联', '协同'))), _rx(any_of(w('attack', 'bypass', 'exfiltrate'), raw('攻击', '绕过', '外传'))),
    )),
    PolicyCatalogRule("plugin_filesystem_overreach", "high", ("input",), (
        _rx(any_of(w("tool", "plugin"), raw("工具", "插件"))),
        _rx(any_of(w("filesystem", "file\\s+system", "/etc/passwd", "~/\\.ssh", "SSH\\s*目录"), raw("文件系统"))),
        _rx(any_of(w("unauthorized", "without\\s+permission", "write"), exact("read", "reads", "reading"),
                   raw("越权", "未授权", "读取", "写入"))),
    ), excluded=(_rx(any_of(w("filesystem", "file\\s+system"), raw("文件系统"))),),
       unless=(_rx(any_of(w("/etc/passwd", "~/\\.ssh", "SSH\\s*目录", "unauthorized", "without\\s+permission",
                            "private\\s+key", "credential", "secret", "upload", "exfiltrate"),
                          raw("越权", "未授权", "私钥", "凭据", "密钥", "上传", "外发"))),)),
    PolicyCatalogRule("plugin_unauthorized_tool_call", "high", ("input",), (
        _rx(any_of(w("tool\\s+call", "plugin\\s+call", "function\\s+call"), raw("工具调用", "插件调用", "函数调用"))),
        _rx(any_of(w("unauthorized"), raw("未授权", "未经许可", "未经审批"), seq(w("without\\s+"), w("permission", "approval")))),
    ), excluded=(_UNAUTHORIZED_STATUS,), unless=(_CIRCUMVENT,),
       context_excluded=(_ACCESS_CONTROL_WORK,), context_unless=(_CIRCUMVENT,), context_label="访问控制或错误码"),
    PolicyCatalogRule("plugin_network_request_forgery", "high", ("input",), (
        _rx(any_of(w('tool', 'plugin'), raw('工具', '插件'))), _rx(any_of(w('ssrf', 'forged\\s+request', 'internal\\s+endpoint'), raw('伪造请求', '内网地址', '元数据地址'))),
        _rx(any_of(w('send', 'access', 'bypass'), raw('发送', '访问', '绕过'))),
    )),
    PolicyCatalogRule("content_doxxing_guidance", "high", ("input",), (
        _rx(any_of(w("doxx", "personal\\s+address", "phone\\s+number"), raw("人肉搜索", "家庭住址", "手机号"))),
        _rx(any_of(w("find", "publish", "expose", "locate"), raw("查找", "公开", "曝光", "定位"))), _HARMFUL_CONTENT_INTENT,
    ), context_excluded=(_rx(any_of(near(raw("写一个", "写个", "实现", "定义", "封装", "编写"), raw("方法"), 30),
                                    raw("函数", "接口"), w("API", "method", "function"))),),
       context_unless=(_rx(any_of(raw("教程", "指导", "教授", "教我"), w("tutorial", "guide", "teach", "instruction"))),
                       _DOXXING_ACT),
       context_label="编写函数或接口"),
    PolicyCatalogRule("content_personal_assault_guidance", "high", ("input",), (
        _rx(any_of(w('attack\\s+someone', 'physically\\s+hurt', 'psychologically\\s+break'), raw('人身攻击', '伤害他人', '心理摧毁'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("content_hate_incitement", "high", ("input",), (
        _rx(any_of(exact("race", "races"), w("ethnic", "ethnicity", "religion", "gender"), raw("种族", "民族", "宗教", "性别"))),
        _rx(any_of(w("hate", "inferior", "expel", "eliminate"), exact("hateful", "hatred", "inferiority"),
                   raw("仇恨", "低等", "驱逐", "消灭"))), _HARMFUL_CONTENT_INTENT,
    ), excluded=(_rx(w("race\\s+condition", "data\\s+race")),)),
    PolicyCatalogRule("content_medical_fraud", "high", ("input",), (
        _rx(any_of(w('medical', 'medicine', 'hospital'), raw('医疗', '药品', '医院'))),
        _rx(any_of(w('fake\\s+cure', 'fabricate\\s+certificate'), raw('虚假疗效', '夸大宣传', '伪造证明'), seq(w('false'), raw('.{0,20}'), w('claim')))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("content_domestic_violence", "high", ("input",), (
        _rx(any_of(w('domestic\\s+violence'), raw('家庭暴力', '家暴'), seq(w('abuse\\s+'), w('wife', 'husband', 'partner')))),
        _rx(any_of(w('method', 'hid(?:e|ing)\\s+injuries', 'control'), raw('方法', '掩盖伤痕', '控制'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("content_sexual_violence", "critical", ("input",), (
        _rx(any_of(w('sexual\\s+assault', 'rape', 'coercive\\s+sex'), raw('性侵', '强奸', '性暴力'))),
        _rx(any_of(w('commit', 'force', 'avoid\\s+detection'), raw('实施', '强迫', '逃避侦查'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("content_terrorism_propaganda", "critical", ("input",), (
        _rx(any_of(w('terrorism', 'terrorist', 'terrorists', 'extremist\\s+group'), raw('恐怖主义', '极端组织'))),
        _rx(any_of(w('propaganda', 'recruit', 'praise'), raw('宣传', '招募', '赞美'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("content_minor_exploitation", "critical", ("input",), (
        _rx(any_of(w("minor", "child", "underage"), raw("未成年人", "儿童"),
                   exact("children", "grandchild", "grandchildren", "schoolchild", "schoolchildren",
                         "stepchild", "stepchildren"))),
        _rx(any_of(w("exploit", "groom", "abuse"), raw("诱骗", "侵害", "剥削"))), _HARMFUL_CONTENT_INTENT,
    ), excluded=(_rx(any_of(
        w("child\\s+process", "child\\s+node", "child\\s+element", "child\\s+thread", "child\\s+component",
          "children\\s+process", "children\\s+node", "children\\s+element", "children\\s+thread",
          "children\\s+component"),
        # "children of (the) parent(s)" usually means real children, so parent is not listed.
        seq(w("children\\s+of\\s+"), rep(seq(exact("a", "an", "the", "this", "each", "its"), raw("\\s+")), "?"),
            w("process", "node", "element", "pid", "thread")),
    )),)),
    PolicyCatalogRule("content_school_bullying", "high", ("input",), (
        _rx(any_of(w('school\\s+bullying', 'bully\\s+a\\s+classmate'), raw('校园暴力', '校园欺凌', '霸凌同学'))),
        _rx(any_of(w('humiliate', 'isolate', 'beat'), exact('beaten', 'beatings'), raw('羞辱', '孤立', '殴打'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("content_weapon_construction", "critical", ("input",), (
        _rx(any_of(w('weapon', 'bomb', 'explosive', 'firearm', 'weaponize', 'weaponise', 'pipebomb', 'firebomb',
                     'letterbomb', 'carbomb', 'truckbomb', 'nailbomb', 'bombmaker', 'bombmaking'),
                   raw('武器', '炸弹', '爆炸物', '枪支'), exact('weaponry', 'bombings'))),
        _rx(any_of(w('build', 'manufacture', 'assemble'), raw('配方', '制作', '制造', '组装'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("content_discrimination", "high", ("input",), (
        _rx(any_of(exact("race", "races", "age", "ages", "ageism", "ageist", "ageists"), w("gender", "region"), raw("种族", "性别", "年龄", "地域"))),
        _rx(any_of(stem("discriminat"), w("exclude", "deny\\s+service"), raw("歧视", "排斥", "拒绝服务"))), _CONTENT_CREATION_INTENT,
    ), excluded=(_rx(w("race\\s+condition", "data\\s+race")),)),
    PolicyCatalogRule("content_drug_manufacturing", "critical", ("input",), (
        _rx(any_of(w('methamphetamine', 'cocaine', 'heroin', 'illegal\\s+drug'), raw('冰毒', '可卡因', '海洛因', '毒品'))),
        _rx(any_of(w('synthesize', 'manufacture', 'recipe'), raw('合成', '制作', '配方'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("content_subversion_incitement", "critical", ("input",), (
        _rx(any_of(w('overthrow\\s+the\\s+government', 'subvert\\s+state\\s+power'), raw('颠覆国家政权', '推翻政府', '推翻社会主义制度'))),
        _rx(any_of(w('incite', 'mobilize', 'propaganda'), raw('煽动', '动员', '宣传'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("content_pollution_guidance", "medium", ("input",), (
        _rx(any_of(w('pollute', 'toxic\\s+waste', 'environmental\\s+damage'), raw('污染环境', '有毒废物', '破坏生态'))),
        _rx(any_of(w('dump', 'discharge', 'hide'), raw('倾倒', '排放', '掩盖'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("content_cyberattack_tutorial", "high", ("input",), (
        _rx(any_of(w('cyberattack', 'hack\\s+into', 'ransomware'), raw('网络攻击', '入侵系统', '勒索软件'))),
        _rx(any_of(w('step[-\\s]*by[-\\s]*step', 'tutorial', 'payload'), raw('逐步', '教程', '载荷'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("content_online_mob_attack", "high", ("input",), (
        _rx(any_of(w('online\\s+mob', 'mass\\s+harassment'), raw('网络暴力', '网暴', '集体围攻'))),
        _rx(any_of(w('coordinate', 'target', 'flood'), raw('组织', '针对', '刷屏'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("content_self_harm_encouragement", "critical", ("input",), (
        _rx(any_of(w("self[-\\s]*harm", "suicide"), raw("自残", "自杀"))),
        _rx(any_of(w("encourage", "glorify", "method", "persuade"), raw("鼓励", "美化", "方法", "劝说"))), _HARMFUL_CONTENT_INTENT,
    ), excluded=(_rx(raw("(?:进程|线程|服务|容器|程序|应用|实例)(?:主动)?自杀", "自杀(?:进程|开关)")),)),
    PolicyCatalogRule("content_prescription_abuse", "high", ("input",), (
        _rx(any_of(w('prescription\\s+drug', 'opioid', 'sedative'), raw('处方药', '阿片', '镇静药'))),
        _rx(any_of(w('abuse', 'overdose', 'mix'), exact('mixture', 'mixtures'), raw('滥用', '超量', '混用'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("content_animal_abuse", "high", ("input",), (
        _rx(any_of(raw("动物", "猫", "狗", "野生动物"), w("animal", "wildlife"), exact("dog", "dogs", "cat", "cats"))),
        _rx(any_of(w("torture", "abuse", "injure"), raw("虐待", "折磨", "伤害"))), _HARMFUL_CONTENT_INTENT,
    ), excluded=(_rx(any_of(near(exact("cat"), raw("\\|"), 60),
                            seq(exact("cat"), raw("\\s+[^\\n。;；]{0,30}\\."),
                                exact("log", "txt", "json", "csv", "conf", "yaml", "yml", "md", "py", "sh")))),)),
    PolicyCatalogRule("content_harmful_rumor_creation", "medium", ("input",), (
        _rx(any_of(w('rumor', 'fake\\s+news'), raw('谣言', '虚假消息'))),
        _rx(any_of(w('cause\\s+panic', 'spread', 'fabricate'), raw('制造恐慌', '传播', '编造'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("content_contraband_guidance", "high", ("input",), (
        _rx(any_of(w('contraband', 'prohibited\\s+item'), raw('违禁品', '禁售品'))),
        _rx(any_of(w('obtain', 'make', 'hide'), raw('获取', '制作', '藏匿'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("content_cult_recruitment", "high", ("input",), (
        _rx(any_of(exact('cult', 'cults', 'cultist', 'cultists', 'cultish'), raw('邪教'))), _rx(any_of(w('recruit', 'indoctrinate', 'propaganda'), raw('招募', '洗脑', '宣传'))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("content_food_safety_violation", "high", ("input",), (
        _rx(any_of(w('food', 'ingredient'), exact('foodstuff', 'foodstuffs', 'seafood'), raw('食品', '食材'))),
        _rx(any_of(w('adulterate', 'illegal\\s+additive', 'hide\\s+contamination'), raw('掺假', '非法添加', '掩盖污染'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("content_harassment_bullying", "high", ("input",), (
        _rx(any_of(w('harass', 'bully'), exact('cyberbully', 'cyberbullies', 'cyberbullied', 'cyberbullying'), raw('骚扰', '霸凌', '欺凌'))),
        _rx(any_of(w('repeatedly', 'target', 'humiliate'), raw('持续', '针对', '羞辱'))), _HARMFUL_CONTENT_INTENT,
    )),
    PolicyCatalogRule("rag_sensitive_data_exfiltration", "high", ("input",), (
        _rx(any_of(exact('rag'), w('retrieval', 'knowledge\\s+base'), raw('检索增强', '知识库'))),
        _rx(any_of(w('sensitive', 'confidential', 'secret'), raw('敏感', '机密', '秘密'))),
        _rx(any_of(w('reveal', 'extract', 'dump', 'export'), raw('泄露', '提取', '转储', '导出'))),
    )),
    PolicyCatalogRule("rag_cache_poisoning", "high", ("input",), (
        _rx(any_of(w('rag\\s+cache', 'retrieval\\s+cache', 'RAG缓存'), raw('检索缓存'))),
        _rx(any_of(w('poison', 'inject\\s+malicious'), raw('污染', '投毒', '注入恶意'))),
    )),
    PolicyCatalogRule("rag_embedding_manipulation", "high", ("input",), (
        _rx(any_of(w('vector\\s+embedding', 'embedding\\s+vector'), raw('向量嵌入', '嵌入向量'))),
        _rx(any_of(w('manipulate', 'adversarial', 'craft'), raw('操纵', '对抗', '构造'))),
    )),
    PolicyCatalogRule("rag_external_knowledge_poisoning", "high", ("input",), (
        _rx(any_of(raw('外部知识', '外部数据源'), seq(w('external\\s+'), w('knowledge', 'source')))),
        _rx(any_of(w('false', 'malicious', 'poison'), exact('falsely', 'falsehood', 'falsehoods', 'maliciously'), raw('虚假', '恶意', '投毒'))),
        _rx(any_of(w('inject', 'insert', 'publish'), raw('注入', '插入', '发布'))),
    )),
    PolicyCatalogRule("rag_document_source_spoofing", "high", ("input",), (
        _rx(any_of(w('document\\s+source', 'document\\s+provenance'), raw('文档来源', '文档出处'))),
        _rx(any_of(w('forge', 'spoof', 'impersonate'), raw('伪造', '冒充', '欺骗'))),
    )),
    PolicyCatalogRule("rag_context_hijacking", "high", ("input",), (
        _rx(any_of(w('retrieved\\s+context', 'retrieval\\s+context'), raw('检索上下文', '召回上下文'))),
        _rx(any_of(w('hijack', 'override', 'ignore\\s+system'), raw('劫持', '覆盖', '忽略系统'))),
    )),
    PolicyCatalogRule("rag_result_tampering", "high", ("input",), (
        _rx(any_of(w('retrieval\\s+results?', 'search\\s+results?'), raw('检索结果', '搜索结果'))),
        _rx(any_of(w('tamper', 'modify', 'replace'), raw('篡改', '修改', '替换'))),
    )),
    PolicyCatalogRule("rag_unauthorized_knowledge_query", "high", ("input",), (
        _rx(any_of(w("knowledge\\s+base", "document\\s+repository"), raw("知识库", "文档库"))),
        _rx(any_of(w("unauthorized", "restricted", "without\\s+permission"), raw("未授权", "受限", "越权"))),
        _rx(any_of(w("query", "access", "retrieve"), raw("查询", "访问", "检索"))),
    ), excluded=(_UNAUTHORIZED_STATUS,), unless=(_CIRCUMVENT,),
       context_excluded=(_ACCESS_CONTROL_WORK,), context_unless=(_CIRCUMVENT,), context_label="访问控制或错误码"),
    PolicyCatalogRule("rag_fake_citation", "medium", ("input",), (
        _rx(any_of(raw("引用", "参考文献", "文档来源"), w("citations?", "references?", "document\\s+source"))),
        _rx(any_of(raw("伪造", "虚构", "编造"), w("fabricate", "fake", "invent"))),
    ), excluded=(_rx(w("fake\\s+object", "fake\\s*对象")),),
       # 核验/防幻觉说明："参考文献全部联网核验，0 条编造""papers that don't exist ... fabricated"
       # "No direction is invented"——是在防止编造引用（客户A 11-21）。
       context_excluded=(_rx(w("mock", "stub")),
                         _rx(any_of(raw("核验", "核实", "校验", "验证", "查证", "防止", "避免", "杜绝", "幻觉",
                                        "\\d+\\s*条\\s*(?:编造|伪造|虚构)", "(?:不|别|勿|禁止|严禁)(?:要|得|能|许)?(?:编造|伪造|虚构)",
                                        "是否(?:编造|伪造|虚构)"),
                                    w("verify", "verified", "verification", "hallucination", "hallucinated", "avoid", "prevent",
                                      "never\\s+fabricate", "never\\s+invent", "do\\s+not\\s+fabricate", "do\\s+not\\s+invent",
                                      "don't\\s+exist", "do\\s+not\\s+exist", "nonexistent", "non-existent", "is\\s+invented"))),),
       context_unless=(_rx(any_of(raw("以假乱真", "冒充", "骗过", "蒙混"), w("pass\\s+off", "fool"))),),
       context_label="测试代码或核验说明"),
    PolicyCatalogRule("supply_compliance_label_bypass", "high", ("input",), (
        _rx(any_of(w("compliance\\s+tag", "compliance\\s+label", "safety\\s+label"), raw("合规标签"),
                   near(_AI_CONTENT, raw("安全标记"), 20), near(raw("安全标记"), _AI_CONTENT, 20))),
        _rx(any_of(w("bypass", "remove", "strip"), raw("绕过", "删除", "剥离"))),
    )),
    PolicyCatalogRule("supply_shadow_model_use", "high", ("input",), (
        _rx(any_of(w('shadow\\s+model', 'cloned\\s+model', 'unapproved\\s+model'), raw('影子模型', '克隆模型', '未审批模型'))),
        _rx(any_of(w('use', 'call', 'route', 'reroute'), raw('使用', '调用', '路由'))),
    )),
    PolicyCatalogRule("supply_malicious_model_load", "high", ("input",), (
        _rx(any_of(w('model', 'checkpoint'), raw('模型', '权重文件'))), _rx(any_of(w('malicious', 'backdoor', 'trojan'), exact('maliciously'), raw('恶意', '后门', '木马'))),
        _rx(any_of(w('load', 'deploy', 'import'), raw('加载', '部署', '导入'))),
    )),
    PolicyCatalogRule("supply_unauthorized_model_call", "high", ("input",), (
        _rx(any_of(w("model"), raw("模型"))),
        _rx(any_of(w("unauthorized", "not\\s+approved", "outside\\s+(?:the\\s+)?allowlist"), raw("未授权", "未审批", "白名单外"))),
        _rx(any_of(w("call", "invoke", "route", "reroute"), raw("调用", "请求", "路由"))),
    ), excluded=(_UNAUTHORIZED_STATUS,), unless=(_CIRCUMVENT,),
       context_excluded=(_ACCESS_CONTROL_WORK,), context_unless=(_CIRCUMVENT,), context_label="访问控制或错误码"),
    PolicyCatalogRule("supply_model_weight_theft", "high", ("input",), (
        _rx(any_of(w('checkpoint'), raw('模型权重', '模型参数'), seq(w('model\\s+'), w('weights?', 'parameters?')))),
        _rx(any_of(w('steal', 'extract', 'export', 'download'), raw('窃取', '提取', '导出', '下载'))),
    )),
    PolicyCatalogRule("supply_model_version_vulnerability_probe", "high", ("input",), (
        _rx(any_of(w("model\\s+version", "model\\s+build"), raw("模型版本", "模型构建号"))),
        _rx(any_of(stem("vulnerabilit"), w("cve", "exploit", "probe"), raw("漏洞", "探测"))),
    )),
    PolicyCatalogRule("supply_model_behavior_probe", "medium", ("input",), (
        _rx(any_of(w('model\\s+decision\\s+logic'), raw('模型内部行为', '模型决策逻辑'), seq(w("model(?:'s)?\\s+internal\\s+"), w('behavior', 'decision\\s+logic')))),
        _rx(any_of(w('probe', 'reverse\\s+engineer', 'infer'), raw('探测', '逆向', '推断'))),
    )),
    PolicyCatalogRule("supply_dependency_vulnerability", "high", ("input",), (
        _rx(any_of(w('supply\\s+chain\\s+package'), raw('第三方依赖', '供应链组件'), seq(w('third[-\\s]*party\\s+'), w('dependency', 'package')))),
        _rx(any_of(stem('vulnerabilit'), w('exploit', 'malicious\\s+package'), raw('漏洞', '利用', '恶意包'))),
        _rx(any_of(w('exploit', 'malicious\\s+package'), raw('利用', '恶意包'))),
    )),
    PolicyCatalogRule("injection_few_shot_attack", "high", ("input",), (
        _rx(any_of(w('few[-\\s]*shot', 'example\\s*1', 'example\\s*2', 'example\\s*3'), raw('少样本', '示例[一二三123]'), seq(raw('q:\\s*'), _WITHIN_WINDOW, raw('a:')))),
        _rx(any_of(w('now\\s+follow', 'continue\\s+the\\s+pattern', 'final\\s+answer'), raw('现在照做', '继续这个模式', '最终回答'))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_collaboration_pretext", "medium", ("input",), (
        _rx(any_of(w('working\\s+with', 'on\\s+the\\s+same\\s+team', 'authorized\\s+by\\s+my\\s+colleague'), raw('同一团队', '同事已授权'), seq(raw('正在与'), _WITHIN_WINDOW, raw('合作')))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_academic_pretext", "medium", ("input",), (
        _rx(any_of(w('academic\\s+research', 'research\\s+paper', 'for\\s+my\\s+thesis'), raw('学术研究', '论文研究', '毕业论文'))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_comparison_pretext", "medium", ("input",), (
        _rx(any_of(w('what\\s+would\\s+happen\\s+if'), _COMPARE_VS, seq(raw('对比', '比较'), _WITHIN_WINDOW, raw('与', '和', '跟'), raw('.+')), seq(raw('如果'), _WITHIN_WINDOW, raw('会怎样')))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_emotional_manipulation", "medium", ("input",), (
        _rx(any_of(w('dying', 'terminally\\s+ill', 'heartbroken', 'desperate'), exact('desperately'), raw('临终', '绝症', '悲痛欲绝', '走投无路'))),
        _rx(any_of(w('help\\s+me\\s+anyway', 'make\\s+an\\s+exception'), raw('破例帮助', '无论如何都要帮'))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_tech_support_impersonation", "high", ("input",), (
        _rx(any_of(raw('作为技术支持', '我是系统管理员', '冒充管理员'), seq(w('i\\s+am\\s+'), w('technical\\s+support', 'the\\s+system\\s+administrator')))),
        _rx(any_of(w('grant', 'unlock', 'reveal', 'enable'), raw('授予', '解锁', '透露', '启用'))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_permutation_flood", "medium", ("input",), (
        _rx(any_of(w('permutations?', 'combinations?'), raw('排列组合'))),
        _rx(any_of(w('thousands', 'millions', 'all\\s+possible'), raw('上千', '百万', '所有可能', '全部', '逐一', '都试'))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_terminology_obfuscation", "medium", ("input",), (
        _rx(any_of(w('euphemism', 'code\\s+words?', 'technical\\s+jargon'), raw('术语混淆', '委婉语', '代号'))),
        _rx(any_of(w('hide', 'obscure', 'mask'), raw('隐藏', '掩盖', '伪装'))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_forged_authority", "high", ("input",), (
        _rx(any_of(w('official\\s+document', 'government\\s+agency', 'security\\s+authority'), raw('官方文件', '权威机构', '监管部门'))),
        _rx(any_of(w('fake', 'forged', 'fabricated'), raw('伪造', '虚构', '冒充'))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_legal_threat", "high", ("input",), (
        _rx(any_of(w('lawsuit', 'legal\\s+consequences?', 'court\\s+order'), raw('法律后果', '起诉', '法院命令', '合规追责'))),
        _rx(any_of(w('force', 'must\\s+comply'), raw('不得拒绝', '必须服从', '强迫'), seq(raw('必须'), raw('.{0,12}'), raw('无视', '忽略', '绕过', '配合')))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_privilege_escalation", "high", ("input",), (
        _rx(any_of(w('admin', 'root', 'superuser', 'debug\\s+mode'), _ADMIN_FORMS, raw('管理员', '超级用户', '调试模式', '特权用户'))),
        _rx(any_of(w('enable', 'unlock', 'elevate'), raw('启用', '解锁', '提升'))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_urgency_coercion", "medium", ("input",), (
        _rx(any_of(w("urgent", "emergency", "time[-\\s]*sensitive", "immediately"), exact("urgently"), raw("紧急", "应急", "时间敏感", "立即"))),
        _BYPASS_TARGET,
    ), excluded=(_rx(seq(any_of(w("without", "do\\s+not", "never"), exact("don't"), raw("不要", "不得", "不能", "无需", "禁止")),
                         raw("\\s*(?:去)?"), any_of(w("bypass", "ignore", "override"), raw("绕过", "忽略", "覆盖")))),)),
    PolicyCatalogRule("injection_fake_security_alert", "high", ("input",), (
        _rx(any_of(w('security\\s+alert', 'critical\\s+vulnerability', 'active\\s+breach'), raw('安全警报', '严重漏洞', '正在被入侵'))),
        _rx(any_of(w('fake', 'fabricated', 'pretend'), raw('伪造', '虚构', '假装'))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_logic_puzzle_pretext", "medium", ("input",), (
        _rx(any_of(w('logic\\s+puzzle', 'riddle', 'brain\\s+teaser'), raw('逻辑谜题', '智力游戏', '脑筋急转弯'))),
        _rx(any_of(w('hidden\\s+instruction', 'prohibited\\s+request'), raw('隐藏指令', '违规请求'))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_moral_dilemma", "medium", ("input",), (
        _rx(any_of(w('greater\\s+good', 'moral\\s+dilemma'), raw('更大利益', '道德困境'), seq(w('save\\s'), _WITHIN_WINDOW, w('\\slives?')), seq(raw('拯救'), _WITHIN_WINDOW, raw('生命')))),
        _rx(any_of(w('make\\s+an\\s+exception', 'only\\s+way'), raw('只能破例', '唯一办法'))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("injection_moral_authority", "medium", ("input",), (
        _rx(any_of(w('ethics\\s+board', 'human\\s+rights\\s+authority', 'moral\\s+authority'), raw('伦理委员会', '人权机构', '道德权威'))),
        _rx(any_of(w('require', 'order', 'demand'), raw('要求', '命令', '强制'))), _BYPASS_TARGET,
    )),
    PolicyCatalogRule("agent_formatted_response_extraction", "low", ("input",), (
        _rx(any_of(w('json', 'xml', 'csv', 'yaml', 'structured\\s+format'), raw('结构化格式'))),
        _rx(any_of(w('programmatic', 'machine\\s+parse', 'machine\\s+parsable', 'extract\\s+automatically'), raw('程序解析', '机器解析', '自动化提取'), seq(w('automation\\s+'), w('parser', 'pipeline', 'extraction')))),
        _rx(any_of(w('output', 'return', 'respond'), raw('输出', '返回', '回复'))),
    )),
    PolicyCatalogRule("injection_image_steganography", "high", ("input",), (
        _rx(any_of(w('gif\\s+frames?', 'image\\s+pixels?', 'GIF帧'), stem('steganograph'), raw('图像像素', '图像隐写'))),
        _rx(any_of(w('hide', 'embed', 'encode'), raw('隐藏', '嵌入', '编码'))),
        _rx(any_of(w('malicious\\s+instruction', 'prompt\\s+injection'), raw('恶意指令', '提示注入'))),
    )),
    PolicyCatalogRule("injection_multimodal_hidden_instruction", "high", ("input",), (
        _rx(any_of(w("image", "audio", "video", "multimodal"), raw("图像", "音频", "视频", "多模态"))),
        _rx(any_of(w("hidden", "embedded", "inaudible"), raw("隐藏", "嵌入", "不可听见"))),
        _rx(any_of(w("instruction", "prompt\\s+injection"), raw("指令", "提示注入"))),
    )),
    PolicyCatalogRule("content_leader_defamation", "high", ("input",), (
        _rx(any_of(w("national\\s+leader", "head\\s+of\\s+state"), raw("国家领导人", "国家元首", "(?<!公司|企业|单位|部门)领导人"))),
        _rx(any_of(w("fabricate", "defame", "insult", "false\\s+accusation"), raw("捏造", "诽谤", "侮辱", "虚假指控"))), _CONTENT_CREATION_INTENT,
    )),
    PolicyCatalogRule("content_ethnic_religious_conflict", "high", ("input",), (
        _rx(any_of(w('ethnic', 'religious'), exact('ethnicity', 'ethnicities'), raw('民族', '宗教'))),
        _rx(any_of(w('incit(?:e|es|ing)\\s+conflict', 'provoke\\s+hatred', 'sectarian\\s+violence'), raw('煽动矛盾', '挑起仇恨', '宗派暴力'))), _CONTENT_CREATION_INTENT,
    )),
)

POLICY_CATALOG_CATEGORIES = tuple(rule.category for rule in POLICY_CATALOG_RULES)


_CODE_REFERENCE_CATEGORIES = frozenset({
    "prompt_probe_system_configuration", "content_harassment_bullying",
    "plugin_data_theft", "supply_unauthorized_model_call",
})


def _sentence_starts(content, sentences):
    """Start offsets of the sentences of ``content`` (boundaries as in covered_sentences)."""
    starts = None if sentences is None else sentences.get("starts")
    if starts is None:
        starts = [0]
        starts.extend(match.end() for match in BOUNDARY.finditer(content))
        _check_cpu_budget()
        if sentences is not None:
            sentences["starts"] = starts
    return starts


def _exclusion_cover(content, rule, deadline, event_budget, sentences):
    """Predicate (start, end) -> True when an exclusion of ``rule`` in the same
    sentence overlaps that component occurrence ("nail gun" over "gun"). With
    ``excluded_focus`` only the focus words inside an exclusion match count.

    Exclusions are matched sentence by sentence, only in sentences that hold a
    component occurrence. An exclusion whose sentence also carries the rule's
    exception wording (``unless`` / ``context_unless``) drops nothing.
    """
    groups = tuple(group for group in (
        (rule.excluded, rule.unless, rule.excluded_focus), (rule.context_excluded, rule.context_unless, ()))
        if group[0])
    if not groups:
        return None
    starts = _sentence_starts(content, sentences)
    found = {}

    def spans_of(index):
        cached = found.get(index)
        if cached is None:
            left = starts[index]
            text = content[left:starts[index + 1] if index + 1 < len(starts) else len(content)]
            spans = []
            for patterns, unless, focus in groups:
                hits = []
                for pattern in patterns:
                    for match in _catalog_finditer(pattern, text, deadline):
                        check_work_budget(deadline)
                        _check_cpu_budget()
                        event_budget[0] += 1
                        if event_budget[0] > _CATALOG_MAX_EVENTS:
                            raise WorkUnavailable("catalog_candidate_limit")
                        base = left + match.start()
                        if not focus:
                            hits.append((base, left + match.end()))
                            continue
                        for part in focus:
                            hits.extend((base + sub.start(), base + sub.end())
                                        for sub in _catalog_finditer(part, match.group(), deadline))
                if hits and not any(_catalog_search(pattern, text, deadline) for pattern in unless):
                    spans.extend(hits)
            spans.sort()
            cached = found[index] = ([a for a, _ in spans], list(itertools.accumulate((b for _, b in spans), max)))
        return cached

    def covered(start, end):
        first = bisect.bisect_right(starts, start) - 1
        last = bisect.bisect_right(starts, max(start, end - 1)) - 1
        for index in range(first, last + 1):
            lefts, ends = spans_of(index)
            at = bisect.bisect_left(lefts, end)
            if at and ends[at - 1] > start:
                return True
        return False

    return covered


_MARKED_LINE = re.compile(r"^[ \t]*[|#][^\r\n]*", re.MULTILINE)
_LINE_INDENT = re.compile(r"[ \t]*")


def _line_exception_cover(content, rule, deadline, sentences):
    """Predicate (start, end) -> True when ``rule.line_exception`` drops that
    component occurrence. The exception reads the whole physical line the
    occurrence is on (sentence boundaries inside a table row or heading do not
    split it), plus the column count of the GFM table the line is a data row
    of: the first two lines of its run of directly adjacent lines starting
    with | must be a header row and a delimiter row with the same number of
    cells. Only lines starting with | or # are examined, each once; its
    matches are not candidate events and do not spend the shared event budget.
    Text without such lines costs one scan and nothing per occurrence.
    """
    if rule.line_exception is None:
        return None
    marked = None if sentences is None else sentences.get("marked_lines")
    if marked is None:
        spans = [(match.start(), match.end()) for match in _MARKED_LINE.finditer(content)]
        marked = ([a for a, _ in spans], [b for _, b in spans])
        _check_cpu_budget()
        if sentences is not None:
            sentences["marked_lines"] = marked
    line_starts, line_ends = marked
    if not line_starts:
        return None
    found = {}
    runs = {}
    columns = {}

    def piped(index):
        at = _LINE_INDENT.match(content, line_starts[index]).end()
        return at < line_ends[index] and content[at] == "|"

    def adjacent(upper, lower):
        gap = line_starts[lower] - line_ends[upper]
        return gap in (1, 2) and content[line_ends[upper]:line_starts[lower]] in ("\n", "\r\n")

    def run_start(index):
        # 往上找连续（不隔行）以 | 开头的行的第一行；结果按行缓存，每行只走一次。
        path = [index]
        while True:
            top = path[-1]
            if top in runs:
                start = runs[top]
                break
            if top == 0 or not adjacent(top - 1, top) or not piped(top - 1):
                start = top
                break
            path.append(top - 1)
        for at in path:
            runs[at] = start
        return start

    def table_columns(index):
        if not piped(index):
            return 0
        start = run_start(index)
        if index - start < 2:
            return 0
        count = columns.get(start)
        if count is None:
            header = (line_starts[start], line_ends[start])
            delimiter = (line_starts[start + 1], line_ends[start + 1])
            if max(header[1] - header[0], delimiter[1] - delimiter[0]) > _TABLE_HEAD_MAX:
                count = 0
            else:
                count = _gfm_table_columns(content[header[0]:header[1]], content[delimiter[0]:delimiter[1]])
            columns[start] = count
        return count

    def covered(start, end):
        index = bisect.bisect_right(line_starts, start) - 1
        if index < 0 or start >= line_ends[index]:
            return False
        cached = found.get(index)
        if cached is None:
            left = line_starts[index]
            spans = sorted((left + a, left + b)
                           for a, b in rule.line_exception(content[left:line_ends[index]], deadline,
                                                           table_columns(index)))
            _check_cpu_budget()
            cached = found[index] = ([a for a, _ in spans], list(itertools.accumulate((b for _, b in spans), max)))
        lefts, ends = cached
        at = bisect.bisect_left(lefts, end)
        return bool(at) and ends[at - 1] > start

    return covered


def _candidate_spans(content, rule, deadline=None, event_budget=None, presence=None, sentences=None):
    # Track the latest match for each required component so an early negated
    # reference cannot hide a later live disclosure request.
    deadline = _catalog_deadline() if deadline is None else deadline
    # A missing required component makes this rule impossible. Check the
    # usually selective trailing intent first instead of evaluating an expensive
    # comparison pretext when no bypass target is present anywhere in the text.
    for pattern in reversed(rule.required):
        # Components shared by many rules (bypass target, generation intent)
        # are searched once per detection.
        found = None if presence is None else presence.get(id(pattern))
        if found is None:
            found = bool(_catalog_search(pattern, content, deadline))
            if presence is not None:
                presence[id(pattern)] = found
        if not found:
            return
    event_budget = [0] if event_budget is None else event_budget
    covered = _exclusion_cover(content, rule, deadline, event_budget, sentences)
    line_covered = _line_exception_cover(content, rule, deadline, sentences)
    links = []

    def in_link(position):
        if not links:
            links.append([(m.start(), m.end()) for m in _catalog_finditer(_LINK, content, deadline)])
        spans = links[0]
        at = bisect.bisect_right(spans, (position, len(content) + 1)) - 1
        return at >= 0 and spans[at][0] <= position < spans[at][1]

    def events(pattern, index):
        outside_links = id(pattern) in _OUTSIDE_LINK_PATTERNS
        iterator = _catalog_finditer(pattern, content, deadline)
        while True:
            check_work_budget(deadline)
            _check_cpu_budget()
            try:
                match = next(iterator)
            except StopIteration:
                check_work_budget(deadline)
                _check_cpu_budget()
                return
            check_work_budget(deadline)
            _check_cpu_budget()
            event_budget[0] += 1
            if event_budget[0] > _CATALOG_MAX_EVENTS:
                raise WorkUnavailable("catalog_candidate_limit")
            if outside_links and in_link(match.start()):
                continue
            if covered is not None and covered(match.start(), match.end()):
                continue
            if line_covered is not None and line_covered(match.start(), match.end()):
                continue
            yield match.start(), index, match.end()

    history = [[] for _ in rule.required]
    gapped = tuple(id(pattern) in _GAPPED_PATTERNS for pattern in rule.required)
    for start, index, end in heapq.merge(
        *(events(pattern, i) for i, pattern in enumerate(rule.required))
    ):
        history[index].append((start, end))
        del history[index][:-_SPAN_HISTORY]
        if any(not item for item in history):
            continue
        spans = _compatible_spans(history, index, gapped, rule.max_window)
        if spans is not None:
            yield min(a for a, _ in spans), max(b for _, b in spans), spans


_SPAN_HISTORY = 4


def _spans_conflict(spans, gapped):
    """A component found strictly inside a longer keyword of another component
    is that keyword, not a second signal ("认证绕过" contains "绕过"). The same
    word may still serve two components ("美化"), and a component with a gap
    (".{0,40}") may contain others."""
    for i, (a, b) in enumerate(spans):
        for j, (c, d) in enumerate(spans):
            if i != j and not gapped[j] and c <= a and b <= d and (a, b) != (c, d):
                return True
    return False


def _compatible_spans(history, newest, gapped, max_window):
    """Newest occurrence of ``newest`` plus the most recent compatible others."""
    choices = [reversed(item) if i != newest else (item[-1],) for i, item in enumerate(history)]
    for spans in itertools.product(*choices):
        if max(b for _, b in spans) - min(a for a, _ in spans) > max_window:
            continue
        if not _spans_conflict(spans, gapped):
            return spans
    return None


_PROMPT_DISCLOSURE_NEGATION = _rx(
    seq(any_of(w('never', 'do\\s+not', 'must\\s+not', 'should\\s+not', 'cannot'), raw('禁止', '不要', '不得', '不许', '严禁')), raw('[ \\t]*$'))
)


def _negated_prompt_disclosure(content, start, deadline=None):
    prefix = content[max(0, start - 80):start]
    if re.search(r"(?:不要|不能|不得|不许)(?:再)?(?:禁止|拒绝)[ \t]*$", prefix):
        return False
    deadline = _catalog_deadline() if deadline is None else deadline
    return bool(_catalog_search(_PROMPT_DISCLOSURE_NEGATION, prefix, deadline))


_PROBE_DIRECTED = re.compile(r"你|您|\byour?\b|助手|\bassistant\b|\bAI\b|\bLLM\b|告诉我|给我|\btell\s+me\b|\bshow\s+me\b", re.I)
_PROBE_IMPERATIVE = re.compile(r"^[\s\-*#>\d.、)）]*(?:请|透露|显示|列出|输出|打印|\breveal\b|\bshow\b|\blist\b|\bprint\b|\bdump\b)", re.I)
# 不靠句首也能认定是在套话的动词（工程笔记里几乎不会出现）
_PROBE_DISCLOSE = re.compile(r"透露|泄露|吐出|\breveal\w*|\bdisclos\w*|\bdump\b|\bleak\b|\bexpose\b", re.I)
_PRIVILEGE_ACTION = re.compile(
    r"(?:提升|提权|授予|获取|拿到|获得|取得|给我|开通|escalat\w*|elevat\w*|grant\w*|obtain\w*|gain\w*|acquir\w*|give\s+me|get)[^\n。；;]{0,16}"
    r"(?:管理员|超级用户|超管|根权限|高权限|最高权限|特权|系统权限|\broot\b|\b(?:sys|super|domain\s*)?admin\w*|\belevated\b|\bsudo\b|\bprivileged\b|\bsystem\s+(?:privileges?|rights|access))"
    r"|(?:管理员|超级用户|超管|根权限|高权限|最高权限|特权|\broot\b|\b(?:sys|super)?admin\w*)\s*(?:权限|privileges?|access)?[^\n。；;]{0,6}(?:提升|授予|获取|escalat\w*)",
    re.I)


PRECISE_CATALOG_CATEGORIES = frozenset({"illegal_organ_trade", "injection_payload_splitting", "dos_resource_exhaustion_instruction", "rag_fake_citation", "injection_binary_octal"})
_PRECISE_RULES = {rule.category: rule for rule in POLICY_CATALOG_RULES if rule.category in PRECISE_CATALOG_CATEGORIES}


def catalog_candidate_has_required_terms(category: str, content: str, *, deadline=None) -> bool:
    """Keep old managed regex packs from resurrecting fixed substring errors."""
    rule = _PRECISE_RULES.get(category)
    if rule is None:
        return True
    deadline = _catalog_deadline() if deadline is None else effective_deadline(min(deadline, _catalog_deadline()))
    try:
        with _cpu_scope():
            return all(_catalog_search(pattern, content, deadline) for pattern in rule.required)
    except (TimeoutError, WorkUnavailable) as exc:
        # Preserve parent cancellation; only this helper's local bound maps to
        # the managed matcher's existing explicit incomplete-finding path.
        check_work_budget()
        raise TimeoutError("catalog evidence validation incomplete") from exc


class PolicyCatalogDetector:
    def detect(self, content: str, stage: str) -> List[Dict]:
        if not content:
            return []
        with _cpu_scope():
            return self._detect(content, stage)

    def _detect(self, content: str, stage: str) -> List[Dict]:
        deadline = _catalog_deadline()
        findings: List[Dict] = []
        reference_context = None
        event_budget = [0]
        candidates = []
        presence = {}
        sentences = {}
        try:
            check_work_budget(deadline)
            content = lexical_text(content)
            check_work_budget(deadline)
            _check_cpu_budget()
            for rule in POLICY_CATALOG_RULES:
                if stage not in rule.stages:
                    continue
                candidates = []
                check_work_budget(deadline)
                disclosure = rule.category.startswith("prompt_leak_")
                family = family_of(rule.category)
                family_live = live_patterns(family)
                for start, end, spans in _candidate_spans(content, rule, deadline, event_budget, presence, sentences):
                    if disclosure and _negated_prompt_disclosure(content, start, deadline):
                        continue
                    if end - start > rule.max_window:
                        continue
                    finding = {
                        "type": "catalog_policy",
                        "category": rule.category,
                        "severity": rule.severity,
                        "matched_text_preview": "<deterministic-catalog-match>",
                        "raw_evidence": content[start:end],
                        "matched_location": f"content[{start}:{end}]",
                        "evidence_kind": "literal",
                        "rule_id": f"catalog_{rule.category}",
                        "rule_name": rule.category,
                        "rule_type": "builtin",
                        "confidence": 0.9,
                        "triage": {"confidence_kind": "heuristic_rule_score"},
                    }
                    local_start, local = covered_sentences(content, spans)
                    # Every occurrence of the rule's own keywords (not gap components)
                    # in these sentences: wording inside them is the topic itself.
                    keyword_spans = tuple(
                        (local_start + match.start(), local_start + match.end())
                        for pattern in rule.required if id(pattern) not in _GAPPED_PATTERNS
                        for match in _catalog_finditer(pattern, local, deadline)
                    )
                    reason = defensive_context_reason(content, spans, family_live, keyword_spans)
                    label = None
                    if not reason and rule.category in _CODE_REFERENCE_CATEGORIES:
                        if reference_context is None:
                            reference_context = prepare_reference_context(content)
                        reason = fenced_reference_reason(content, start, end, context=reference_context)
                    if (not reason and rule.context_excluded
                            and any(_catalog_search(pattern, local, deadline) for pattern in rule.context_excluded)
                            and not any(_catalog_search(pattern, local, deadline) for pattern in rule.context_unless)):
                        reason, label = "development_context", rule.context_label
                    if not reason and rule.category == "dos_exponential_expansion":
                        if (re.search(r"图表|数学|解释|讲解|chart|math|explain", local, re.I)
                                and not re.search(r"重复|耗尽|占满|资源|tokens?|repeat|exhaust|2\s*\^", local, re.I)):
                            reason = "mathematical_explanation"
                    if not reason and rule.category == "prompt_probe_system_configuration":
                        # 探测指令要对着模型说（你/您/告诉我/列出…开头）。工程笔记里"后端端口撞 8000，
                        # 显示运行中""分布式架构 feature list"只是三组词碰巧同现（客户A 11-21）。
                        if not (_PROBE_DIRECTED.search(local) or _PROBE_IMPERATIVE.match(local) or _PROBE_DISCLOSE.search(local)):
                            reason = "not_directed_at_assistant"
                    if not reason and rule.category == "plugin_privilege_escalation":
                        # 提权要"提升/授予/获取"直接作用在管理员/root 权限上；"提升/更新日志…已更新的插件…/root"
                        # 是同段里各说各的（客户A 11-21）。
                        if not _PRIVILEGE_ACTION.search(local):
                            reason = "privilege_terms_unrelated"
                    if not reason and rule.category == "supply_model_weight_theft":
                        if (re.search(r"官方|开源|公开发布|official|open[- ]source|publicly released", local, re.I)
                                and not re.search(r"窃取|未授权|受限|绕过|私有|steal|restricted|bypass|private|without permission", local, re.I)):
                            reason = "public_model_acquisition"
                    if not reason and rule.category == "rag_result_tampering":
                        if (re.search(r"排序|显示格式|显示样式|展示样式|样式|高亮|格式|布局|界面|sort|display|presentation|highlight|style|format|layout", local, re.I)
                                and not re.search(r"伪造|造假|篡改|虚假|恶意|false|malicious|forge|tamper", local, re.I)):
                            reason = "retrieval_presentation_change"
                    if not reason:
                        framing = framing_reason(rule.category, local, keyword_spans, local_start)
                        if framing:
                            reason, label = framing
                    if reason:
                        observation(finding, reason, label)
                    if not candidates or finding.get("counts_as_security_finding", True):
                        candidates[:] = [finding]
                    if finding.get("counts_as_security_finding", True):
                        break
                if candidates:
                    findings.append(max(candidates, key=lambda f: f.get("counts_as_security_finding", True)))
                candidates = []
            check_work_budget(deadline)
            _check_cpu_budget()
        except (TimeoutError, WorkUnavailable) as exc:
            # Parent cancellation/deadline must still abort the request worker.
            # Only the catalog's own bound becomes a retained runtime finding.
            check_work_budget()
            if candidates:
                findings.append(max(candidates, key=lambda f: f.get("counts_as_security_finding", True)))
            if isinstance(exc, TimeoutError):
                reason = "catalog_regex_timeout"
            elif exc.reason == "catalog_candidate_limit":
                reason = "catalog_candidate_limit"
            else:
                reason = "catalog_budget_exhausted"
            findings.append(_catalog_incomplete(reason))
        return findings
