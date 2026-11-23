"""命中内容的可读显示：按显示方式把命中原文变成可以给管理员看的文本。

规格：docs/superpowers/specs/2026-11-14-hit-visibility-design.md 4.2、4.3。
这里全是纯函数。secret_text 只在内存里传给网关，绝不落库、不写日志。

凭据方式的原则是“默认都遮”，而且不切分：第一个字段名之后的整段都算一个取值，整体打码。
只显示字段名、赋值号、成对的引号、Bearer 一类的前缀词、已知的密钥前缀，以及连接串的协议、用户名和主机。
不去分辨一段命中里有几处赋值、几行、几个连接串——分得越细，边界越多，越容易漏。

自动方式用于客户自定义规则，命中文本可能是任意文字，所以只遮认得出的部分：
已知字段名后面的取值、连接串里的密码、16 位以上同时含字母和数字的长串。
"""
from __future__ import annotations

import logging
import re
from types import SimpleNamespace
from dataclasses import dataclass
from typing import List, Optional, Tuple

from app.detectors.severity_downgrade import assignment_value

DISPLAY_KINDS = frozenset({"marker", "credential", "identifier", "plain", "auto"})
MAX_DISPLAY_CHARS = 120
CONTEXT_WINDOW = 500  # 与 engine._annotate_admin_evidence 保存前后文的窗口一致
BODY_SCAN_LIMIT = 16384

_PEM_END = re.compile(r"-----END [A-Z0-9 ]*-----")
_KEY_NAMES = (
    r"(?i:pass(?:word|wd)?|pwd|secret(?:[_ -]?key)?|token|api[_ -]?key|access[_ -]?key(?:[_ -]?id)?|"
    r"private[_ -]?key|credential|aws[_ -]?secret|authorization)"
)
# 字段名（左边界同 severity_downgrade：前面不能紧贴字母数字，驼峰除外；可带数字后缀）加赋值号。
_KEY = re.compile(
    r"(?:(?<![A-Za-z0-9])|(?<=[a-z])(?=[A-Z]))" + _KEY_NAMES + r"(?:[_-]?\d+)?[\"']?[ \t]*[=:：][ \t]*"
)
# 凭据方式（strict）下，行首的任意 NAME= 也算字段名：环境变量、配置文件片段里的名字五花八门，一律默认遮取值。
# 后面紧跟 // 的是协议名（http://），不算。
_KEY_STRICT = re.compile(
    _KEY.pattern
    + r"|(?:^|(?<=[\r\n]))[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_.\-]*[\"']?[ \t]*[=:：][ \t]*(?!//)"
)
_SCHEME = re.compile(r"(?i:bearer|basic|digest)[ \t]+")
_CJK_STOP = "，。；：、）】」！？"
_LOOSE_END = re.compile(r"[\s\"',;" + _CJK_STOP + r"]")
_ESCAPED_DQ = re.compile(r'"(?:[^"\\\n]|\\.)*"')
_ESCAPED_SQ = re.compile(r"'(?:[^'\\\n]|\\.)*'")
_KNOWN_PREFIX = re.compile(r"^(?:sk-ant-|sk-proj-|sk-|ghp_|gho_|ghs_|github_pat_|AKIA|ASIA|xox[abprs]-)")
_RUN_CHARS = r"A-Za-z0-9+/_\-"
_SWEEP_CREDENTIAL = re.compile(r"[" + _RUN_CHARS + r"]{12,}")
_TRAILING_CLOSERS = " \t\r\n,;}])"
_YAML_BLOCK = re.compile(r"^[|>][+-]?[ \t]*\r?\n")
_URL_AUTHORITY_END = re.compile(r"[/?#]")
_WHITESPACE = re.compile(r"\s")
_URL_EXTRA = re.compile(r"[?#]")
_URL_ONLY = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://\S+$")
_SWEEP_AUTO = re.compile(r"[" + _RUN_CHARS + r"]{16,}")
_SEPARATOR_PREFIX = re.compile(r"^[\"']?[ \t]*[=:：]?[ \t]*[\"']?")
_URL_MASK = "\ue000"  # 连接串密码的占位符，最后换成 ****；避免被赋值规则再处理一次


# 取值“只是占位”的形态：整个取值必须完整匹配，开头像占位符、后面还跟着别的内容的不算。
_PLACEHOLDER = re.compile(
    r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}"                 # ${VAR}
    r"|\$[A-Z_][A-Z0-9_]*"                              # $VAR：只认全大写，$uperS3cret 这类是真密码
    r"|%[A-Z_][A-Z0-9_]*%"                              # %VAR%：同上
    r"|\{\{[A-Za-z0-9_.]+\}\}"                          # {{vault.db}}
    r"|<[A-Za-z_\-]{1,40}>"                             # <your-password>
    r"|os\.environ\[[\"'][A-Za-z_][A-Za-z0-9_]*[\"']\]"
    r"|(?:os\.getenv|getenv|env)\([\"']?[A-Za-z_][A-Za-z0-9_]*[\"']?\)"
    r"|process\.env\.[A-Za-z_][A-Za-z0-9_]*"
    r"|(?i:changeme|change_me|example|placeholder|redacted|null|none|todo|x{3,}|your[_-][a-z_\-]+)"
    r"|\*+|\.{3})"
)


def _is_placeholder(value: str) -> bool:
    return _PLACEHOLDER.fullmatch(value) is not None


@dataclass(frozen=True)
class HitDisplay:
    text: str
    secret_text: str = ""


def bounded(text: str, limit: int = MAX_DISPLAY_CHARS) -> str:
    """压掉换行和制表符；超长时保留开头和结尾。"""
    text = re.sub(r"[\r\n\t]+", " ", text or "").strip()
    if len(text) <= limit:
        return text
    head = limit * 3 // 5
    return text[:head] + "…" + text[-(limit - head):]


def mask_value(value: str) -> str:
    """保留头尾各 2 位并写位数；不足 6 位全部打码。"""
    if len(value) < 6:
        return "*" * len(value) + f"（{len(value)} 位）"
    return f"{value[:2]}****{value[-2:]}（{len(value)} 位）"


MARKER_BODY_PREFIX = "（后续正文 "
MARKER_BODY_SUFFIX = " 字已隐藏）"


def _marker(matched: str, following: str) -> HitDisplay:
    scan = following[:BODY_SCAN_LIMIT]
    end = _PEM_END.search(scan)
    body = scan[: end.start()] if end else scan[:CONTEXT_WINDOW]
    secret = body[:CONTEXT_WINDOW]
    if not secret.strip():
        return HitDisplay(bounded(matched))
    return HitDisplay(f"{bounded(matched)}{MARKER_BODY_PREFIX}{len(body.strip()):,}{MARKER_BODY_SUFFIX}", secret)


def _token_like(run: str) -> bool:
    return bool(re.search(r"[A-Za-z]", run) and re.search(r"\d", run))


def _sweep(text: str, pattern: re.Pattern) -> str:
    """保底：仍像令牌的长串（同时含字母和数字）打码。"""

    def replace(match: re.Match) -> str:
        run = match.group(0)
        return mask_value(run) if _token_like(run) else run

    return pattern.sub(replace, text)


def _split_scheme(value: str) -> Tuple[str, str]:
    scheme = _SCHEME.match(value)
    head = scheme.group(0) if scheme else ""
    return head, value[len(head):]


# ---- 凭据方式：第一个字段名之后的整段是一个取值 ----


def _render_url(url: str) -> Optional[Tuple[str, str]]:
    """连接串的 (显示文本, 秘密本体)；连接串里没有任何可遮的结构时返回 None，由调用方整体打码。

    主机段在 /、?、# 中最先出现的位置结束。? 或 # 之后的参数一律写 ?…。
    有密码：密码写 ****，路径保留（一般是库名）。
    没有密码：主机之后的路径可能就是秘密（如带令牌的回调地址），写 /…。
    用户名和保留下来的路径里像令牌的长串也打码。
    主机段之后还有 @：密码里多半直接写了 /、?、#（没有编码），主机段切在了密码中间，结构不可信，只显示协议。
    秘密本体：只有密码要遮时取密码；还遮了别的（参数、路径、用户名）就取整个连接串。
    """
    start = url.index("://") + 3
    cut = _URL_AUTHORITY_END.search(url, start)
    end = cut.start() if cut else len(url)
    authority, rest = url[start:end], url[end:]
    if "@" in rest:
        return url[:start] + "…", url
    last_at = authority.rfind("@")
    userinfo, host = (authority[:last_at], authority[last_at:]) if last_at >= 0 else ("", authority)
    colon = userinfo.find(":")
    user, password = (userinfo, "") if colon < 0 else (userinfo[:colon], userinfo[colon + 1:])
    shown_user = _sweep(user, _SWEEP_CREDENTIAL)
    extra = _URL_EXTRA.search(rest)
    path = rest if extra is None else rest[: extra.start()]
    tail = "" if extra is None else "?…"
    if password:
        shown_path = _sweep(path, _SWEEP_CREDENTIAL)
        text = url[:start] + shown_user + ":****" + host + shown_path + tail
        only_password = extra is None and shown_user == user and shown_path == path
        return text, (password if only_password else url)
    shown_userinfo = shown_user + (":" if colon >= 0 else "")
    if len(path) > 1:
        return url[:start] + shown_userinfo + host + "/…", url
    if tail or shown_user != user:
        return url[:start] + shown_userinfo + host + path + tail, url
    return None


def _render_secret_value(value: str) -> Tuple[str, str]:
    """一个取值的 (显示文本, 秘密本体)。"""
    rendered = _render_url(value) if _URL_ONLY.match(value) else None
    if rendered is not None:
        return rendered
    prefix = _KNOWN_PREFIX.match(value)
    head = prefix.group(0) if prefix else ""
    return head + mask_value(value[len(head):]), value


def _first_key(text: str) -> Optional[re.Match]:
    """第一个字段名。行首的任意 NAME= 只有“像个名字”才算数，下面两种不算，整段都当取值：
    后面没有取值（或只剩补位的 =）——多半是一段以 = 结尾的密钥；
    名字本身像令牌（12 位以上、同时含字母和数字，又不含已知字段名）——多半是中间带 = 的密钥。
    """
    key = _KEY_STRICT.search(text)
    if key is None or _KEY.match(text, key.start()) is not None:
        return key
    name = re.search(r"[A-Za-z_][A-Za-z0-9_.\-]*", re.sub(r"^[ \t]*(?:export[ \t]+)?", "", key.group(0))).group(0)
    if not text[key.end():].strip().strip("="):
        return None
    if len(name) >= 12 and _token_like(name) and re.search(_KEY_NAMES, name) is None:
        return None
    return key


def _credential(matched: str) -> HitDisplay:
    whole = matched.strip()
    rendered = _render_url(whole) if _URL_ONLY.match(whole) else None
    if rendered is not None:  # 整段就是一个连接串
        return HitDisplay(bounded(rendered[0]), rendered[1])
    key = _first_key(matched)
    before = matched[: key.start()] if key else ""
    body = (matched[key.end():] if key else matched).strip()
    block = _YAML_BLOCK.match(body)  # YAML 的块写法：password: |\n  取值
    if block:
        body = body[block.end():].strip()
    # 成对的引号和它后面的收尾标点（JSON 里的 } ] ,）原样显示；引号不成对就全部算取值。
    peeled = body.rstrip(_TRAILING_CLOSERS)
    if len(peeled) >= 2 and peeled[0] in "\"'" and peeled[-1] == peeled[0]:
        quote, inner, closing = peeled[0], peeled[1:-1], body[len(peeled):]
    else:
        quote, inner, closing = "", body, ""
    scheme, value = _split_scheme(inner)
    # 字段名之前的文字里如果扫出了像令牌的长串，秘密本体就取整段命中：网关据此把整段从前后文里隐藏，
    # 不依赖它自己的保底扫描（那边 16 位起，这边 12 位起）。
    swept_before = _sweep(before, _SWEEP_CREDENTIAL)
    if not value or _is_placeholder(value):  # 空值、变量引用、占位符：取值没有要遮的
        return HitDisplay(bounded(swept_before + matched[len(before):]), matched if swept_before != before else "")
    shown, secret = _render_secret_value(value)
    lead = swept_before + (key.group(0) if key else "")
    return HitDisplay(bounded(lead + quote + scheme + shown + quote + closing), matched if swept_before != before else secret)


# ---- 自动方式：只遮认得出的部分 ----


def _url_password_spans(text: str) -> List[Tuple[int, int]]:
    """文本里每个连接串密码的 (起, 止)。

    连接串取到下一个空白为止，按其中最后一个 @ 切：密码里可以含 @，也可以直接写 /、?、#（没有编码）。
    宁可把带端口、参数里又有 @ 的普通网址多遮一段，也不让密码漏出来。
    """
    spans: List[Tuple[int, int]] = []
    at = text.find("://")
    segment_end = -1  # 当前这段（到下一个空白为止）的结束位置；同一段里的所有 :// 共用，避免每个都从头扫到底
    segment_last_at = -1
    while at >= 0:
        start = at + 3
        if start >= segment_end:
            stop = _WHITESPACE.search(text, start)
            segment_end = stop.start() if stop else len(text)
            segment_last_at = text.rfind("@", start, segment_end)
        last_at = segment_last_at if segment_last_at >= start else -1
        colon = text.find(":", start, last_at) if last_at >= 0 else -1
        if at > 0 and colon >= 0 and last_at > colon + 1:
            spans.append((colon + 1, last_at))
        at = text.find("://", start)
    return spans


def _hide_url_passwords(text: str) -> str:
    parts: List[str] = []
    cursor = 0
    for start, end in _url_password_spans(text):
        if start < cursor:
            continue
        parts.append(text[cursor:start])
        parts.append(_URL_MASK)
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


def _mask_one(value: str) -> str:
    if not value or _is_placeholder(value):
        return value
    if _URL_MASK in value and _URL_ONLY.match(value):
        return value  # 取值本身就是一个连接串，密码已换成占位符
    return mask_value(value)


def _mask_value_region(region: str) -> str:
    """region 是赋值号之后、下一个字段名之前的文字。取值可以另起一行；带引号时取到第一个未转义的闭引号，
    否则遇空白、引号、逗号分号或中文标点就停。取值之后的文字做保底扫描。"""
    lead = region[: len(region) - len(region.lstrip())]
    region = region[len(lead):]
    block = _YAML_BLOCK.match(region)  # YAML 的块写法：password: |\n  取值
    if block:
        after = region[block.end():]
        lead += region[: block.end()] + after[: len(after) - len(after.lstrip())]
        region = after.lstrip()
    quote = region[:1] if region[:1] in "\"'" else ""
    if quote:
        closed = (_ESCAPED_DQ if quote == '"' else _ESCAPED_SQ).match(region)
        if closed is None:  # 只有开引号：取到行尾
            line = region[1:].split("\n", 1)[0]
            head, value = _split_scheme(line)
            stripped = value.rstrip()
            rest = value[len(stripped):] + region[1 + len(line):]
            return lead + quote + head + _mask_one(stripped) + _sweep(rest, _SWEEP_AUTO)
        head, value = _split_scheme(region[1:closed.end() - 1])
        return lead + quote + head + _mask_one(value) + quote + _sweep(region[closed.end():], _SWEEP_AUTO)
    head, rest = _split_scheme(region)
    end = _LOOSE_END.search(rest)
    value = rest[: end.start()] if end else rest
    return lead + head + _mask_one(value) + _sweep(rest[len(value):], _SWEEP_AUTO)


def _mask_structured(text: str) -> str:
    """把 text 切成“已知字段名=取值”和其余部分：取值打码，其余部分做保底扫描。"""
    keys = list(_KEY.finditer(text))
    if not keys:
        return _sweep(text, _SWEEP_AUTO)
    out = [_sweep(text[: keys[0].start()], _SWEEP_AUTO)]
    for index, key in enumerate(keys):
        region_end = keys[index + 1].start() if index + 1 < len(keys) else len(text)
        out.append(key.group(0))
        out.append(_mask_value_region(text[key.end():region_end]))
    return "".join(out)


# 证件方式的显示规则（compact = 去掉空白和连字符后的原文；结果最后统一过 bounded）：
#   1. 手机号（1 开头共 11 位数字）：前 3 后 4。
#   2. 整段恰好是一个邮箱：用户名只露前 min(2, 用户名长度//2) 位，接 ***@ 和完整域名。
#   3. compact 只由字母、数字和括号组成（号码类）：n 不超过 4 全部打 *；5–15 位头尾各露 n//4 位，
#      中间按位数打 *；16–24 位前 6 后 4（号码惯例，不保证遮一半）；超过 24 位用 mask_value。
#   4. 其余（含中文、逗号、点号、冒号、斜杠、@ 等任何别的字符，如姓名、地址、病历、经纬度）：
#      一个字符都不露，只写“（已隐藏 N 字）”，N 是去掉首尾空白后的原文字数。
# 末尾常常就是敏感内容（罪名、药名），所以自由文本不露头也不露尾。
_EMAIL_WHOLE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_NUMBER_LIKE = re.compile(r"[A-Za-z0-9()]+")


def _mask_email(address: str) -> str:
    user, _, domain = address.rpartition("@")
    return user[:min(2, len(user) // 2)] + "***@" + domain


def _identifier(matched: str) -> HitDisplay:
    return HitDisplay(bounded(_identifier_text(matched)))


def _identifier_text(matched: str) -> str:
    compact = re.sub(r"[\s\-]", "", matched)
    n = len(compact)
    if re.fullmatch(r"1\d{10}", compact):
        return compact[:3] + "****" + compact[-4:]
    if _EMAIL_WHOLE.fullmatch(matched.strip()):
        return _mask_email(matched.strip())
    if not _NUMBER_LIKE.fullmatch(compact):
        return f"（已隐藏 {len(matched.strip())} 字）"
    if n <= 4:
        return "*" * n
    if 16 <= n <= 24:
        return compact[:6] + "*" * (n - 10) + compact[-4:]
    if n <= 15:
        edge = n // 4
        return compact[:edge] + "*" * (n - 2 * edge) + compact[-edge:]
    return mask_value(compact)


def _auto_text(matched: str, following: str) -> str:
    text = matched
    extra = assignment_value(matched, following)
    if extra:
        extra = re.split("[" + _CJK_STOP + "]", extra, maxsplit=1)[0]
    if extra:
        text = matched + _SEPARATOR_PREFIX.match(following).group(0) + extra
    text = _mask_structured(_hide_url_passwords(text))
    return text.replace(_URL_MASK, "****")


def _auto(matched: str, following: str) -> HitDisplay:
    return HitDisplay(bounded(_auto_text(matched, following)))


# 普通文字方式在自动方式之后再补遮三类（只看命中文本本身，不看后文）：
#   完整的邮箱；7 位及以上的数字串（允许空格和连字符，可带 +86）和“17 位数字加 X”；
#   中文标注的凭据（密码、口令、密钥、秘钥、令牌、PIN 后面的 ASCII 取值）。
# 已知局限（安全优先，不在这一版处理）：姓名、地址、出生日期等自由文本；
# 用点、斜杠或连续空格分隔的手机号；全角字母数字的取值；中文取值的口令；
# 英文字段名后用空格隔开的裸值（如 password Passw0rd!）；不认识的字段名（如 Cookie: sessionid=...）；
# 6 位以下的数字（含验证码）；不足 16 位、带已知前缀的短密钥；
# 命中原文经过归一化（全角标点等）与原文对不上时不生成新显示、保留占位；
# 自然语言里 secret:、password: 后面的普通单词会被多遮（安全但降低可读性）。
_PLAIN_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PLAIN_NUMBER = re.compile(r"(?<!\d)(\+86[ \-]?)?(\d{17}[Xx]|\d(?:[ \-]?\d){6,})(?!\d)")
_PLAIN_LABELLED = re.compile(
    r"(?i:密码|口令|密钥|秘钥|令牌|(?<![A-Za-z])PIN(?![A-Za-z])码?)"
    r"\s*[是为]?\s*[:：=＝]?\s*[\"'“（(]?"  # 分隔：可选 是/为、冒号或等号、开引号或开括号
    r"((?![:=\"'()])[\x21-\x7e](?:(?![\"'()])[\x21-\x7e])*)"  # 取值：首字符不是冒号等号引号括号，遇闭引号闭括号停
)


def _mask_labelled(match: re.Match) -> str:
    value = match.group(1)
    if "*" in value:  # 已经被前面的遮盖处理过
        return match.group(0)
    return match.group(0)[: match.start(1) - match.start(0)] + mask_value(value)


def _plain(matched: str) -> HitDisplay:
    text = _auto_text(matched, "")
    text = _PLAIN_EMAIL.sub(lambda m: _mask_email(m.group(0)), text)
    text = _PLAIN_LABELLED.sub(_mask_labelled, text)
    text = _PLAIN_NUMBER.sub(lambda m: (m.group(1) or "") + _identifier_text(m.group(2)), text)
    return HitDisplay(bounded(text))


def render_hit_display(kind: str, matched: str, following: str = "") -> HitDisplay:
    """kind 取 DISPLAY_KINDS；不认识的值按 auto 处理。"""
    original = matched or ""
    if not original:
        return HitDisplay("")
    # 占位符 _URL_MASK 是私有区字符；输入里本来就有时先换成替换符，免得被当成“已处理的连接串密码”而漏遮。
    matched = original.replace(_URL_MASK, "\ufffd")
    following = (following or "").replace(_URL_MASK, "\ufffd")
    if kind == "marker":
        return _marker(matched, following)
    if kind == "credential":
        display = _credential(matched)
        if matched != original and display.secret_text:
            return HitDisplay(display.text, original)  # 秘密本体必须是原文里的子串，网关才替换得掉
        return display
    if kind == "identifier":
        return _identifier(matched)
    if kind == "plain":
        # 普通文字也可能夹着密钥、连接串密码、号码：自动方式的遮盖加上补遮，不拉入后文。
        return _plain(matched)
    return _auto(matched, following)


CUSTOM_RULE_TYPES = frozenset({"regex", "keyword", "field_name", "secret"})
_SECRET_BEARING_KINDS = frozenset({"marker", "credential"})
_LOCATION = re.compile(r"^content\[(\d+):(\d+)\]$")
_logger = logging.getLogger(__name__)


def annotate_hit_display(findings, content: str) -> None:
    """给有明确命中位置的 finding 写可读命中内容和秘密本体。

    - 目录里声明了显示方式的内置能力：按声明的方式。
    - 自定义规则：secret 类型按凭据，其余按自动；覆盖它原先的“头尾各 2 位 + sha256”。
    - 目录里没有的内置能力、检测器已自己写了说明文字的、没有明确位置的：不动。

    生成显示内容不能让检测失败：任何一条出错都只记一条不含内容的 warning，
    这一条保持原来的 redacted_evidence，secret_text 置空。
    """
    content = content or ""
    for finding in findings:
        try:
            _annotate_one(finding, content)
        except Exception as error:  # noqa: BLE001 展示是锦上添花，绝不影响检测结果
            finding.secret_text = ""
            # 只记规则、类别和异常类型：异常消息、命中原文、秘密本体都可能带内容。
            _logger.warning(
                "命中内容显示生成失败，保持原显示：rule_id=%s category=%s error=%s",
                finding.rule_id, finding.category, type(error).__name__,
            )


WANT_SECRET_TEXT_HEADER = "X-JJD-Want-Secret-Text"


def want_secret_text(header_value) -> bool:
    """只有请求头恰好为 1 才要秘密本体；缺省、其他值、非字符串（直接调函数时的默认对象）都不要。"""
    return isinstance(header_value, str) and header_value.strip() == "1"


def apply_secret_text_policy(response, want: bool):
    """出口统一处理：不要秘密本体时，返回 findings 和 raw_findings 都清空 secret_text 的副本。"""
    if want:
        return response
    update = {}
    for name in ("findings", "raw_findings"):
        items = getattr(response, name, None)
        if items:
            update[name] = [item.model_copy(update={"secret_text": ""}) for item in items]
    return response.model_copy(update=update) if update else response


def evidence_context_for(content: str, start: int, end: int) -> str:
    """命中点前后各 CONTEXT_WINDOW 字符；截断处加“…”。引擎写 evidence_context 和重放算偏移共用这一处规则。"""
    context_start = max(0, start - CONTEXT_WINDOW)
    context_end = min(len(content), end + CONTEXT_WINDOW)
    prefix = "…" if context_start > 0 else ""
    suffix = "…" if context_end < len(content) else ""
    return prefix + content[context_start:context_end] + suffix


def raw_offset_in_context(start: int) -> int:
    """命中原文在 evidence_context_for(content, start, end) 里的起点。"""
    return (1 if start > CONTEXT_WINDOW else 0) + min(start, CONTEXT_WINDOW)


def is_custom_rule_type(rule_type) -> bool:
    return rule_type in CUSTOM_RULE_TYPES


def _resolve_kind(finding) -> Tuple[Optional[str], bool]:
    """显示方式的唯一判定：返回 (方式, 是否自定义规则)。目录里没有声明的内置能力返回 None。"""
    from app.capability_docs import display_kind  # 延迟导入，避免与 capability_docs 的循环依赖

    if is_custom_rule_type(finding.rule_type):
        return ("credential" if finding.rule_type == "secret" else "auto"), True
    return display_kind(finding.category), False


def masked_placeholder(category: str) -> str:
    """sensitive_data 检测器给所有命中写的 redacted_evidence 占位。"""
    return f"{category}:<MASKED>"


def is_credential_format_match(finding_type: str, category: str) -> bool:
    return finding_type == "secret" and category != "plain_password"


def credential_explanation(finding_type: str, category: str) -> str:
    return "匹配凭据格式" if is_credential_format_match(finding_type, category) else "提取到凭据字段的字面值"


def credential_evidence_text(finding_type: str, category: str, preview: str) -> str:
    """engine._annotate_credential_assessment 在 redacted_evidence 为空时写的文字。"""
    return credential_explanation(finding_type, category) + "：" + (preview or "<MASKED>")


def _has_own_explanation(finding) -> bool:
    """检测器自己写了说明文字。sensitive_data 统一写的“<类别>:<MASKED>”占位不算说明。"""
    text = finding.redacted_evidence
    return bool(text) and text != masked_placeholder(finding.category)


def _annotate_one(finding, content: str) -> None:
    location = _LOCATION.fullmatch(finding.matched_location or "")
    if location is None or not finding.raw_evidence or finding.evidence_kind not in ("", "literal"):
        return
    start, end = int(location.group(1)), int(location.group(2))
    if not (0 <= start < end <= len(content)) or content[start:end] != finding.raw_evidence:
        return
    kind, custom = _resolve_kind(finding)
    if kind is None or (not custom and _has_own_explanation(finding)):
        return
    display = render_hit_display(kind, finding.raw_evidence, content[end:end + BODY_SCAN_LIMIT])
    finding.redacted_evidence = display.text
    # 自定义规则的前后文不进告警库：不给秘密本体（secret 类型仍按凭据显示）。
    finding.secret_text = display.secret_text if kind in _SECRET_BEARING_KINDS and not custom else ""


def restore_secret_text(findings) -> None:
    """缓存重放时没有原文：用 raw_evidence 和 evidence_context 重新算出秘密本体。

    只写 secret_text，不改 redacted_evidence（那是首次检测用完整原文生成的）。
    出错只记不含内容的 warning，secret_text 置空，不抛。
    """
    for finding in findings:
        try:
            _restore_one(finding)
        except Exception as error:  # noqa: BLE001
            finding.secret_text = ""
            _logger.warning(
                "秘密本体还原失败，已留空：rule_id=%s category=%s error=%s",
                finding.rule_id, finding.category, type(error).__name__,
            )


def _restore_one(finding) -> None:
    if finding.secret_text or not finding.raw_evidence or finding.evidence_kind not in ("", "literal"):
        return
    kind, custom = _resolve_kind(finding)
    if custom or kind not in _SECRET_BEARING_KINDS:
        return
    following = ""
    if kind == "marker":
        # 按精确位置取：命中点在 evidence_context 里的偏移由 matched_location 的起点和同一套窗口规则算出，
        # 对不上就不补，绝不用“第一次出现”去猜。
        location = _LOCATION.fullmatch(finding.matched_location or "")
        if location is None:
            return
        start = int(location.group(1))
        context = finding.evidence_context or ""
        offset = raw_offset_in_context(start)
        if context[offset:offset + len(finding.raw_evidence)] != finding.raw_evidence:
            return
        following = context[offset + len(finding.raw_evidence):]
    finding.secret_text = render_hit_display(kind, finding.raw_evidence, following).secret_text


_TRIAGE_FIELDS = ("type", "category", "rule_id", "source_rule_id", "rule_type", "evidence_kind", "matched_location",
                  "raw_evidence", "redacted_evidence", "matched_text_preview")


def _view(finding):
    get = finding.get if isinstance(finding, dict) else (lambda name, default="": getattr(finding, name, default))
    return SimpleNamespace(**{name: str(get(name, "") or "") for name in _TRIAGE_FIELDS})


def legacy_triage_evidence(finding) -> str:
    """还原 2.9.19 之前这条 finding 的 redacted_evidence（为空取预览）。

    改版前的写入顺序：检测器自写（sensitive_data 的占位）→ engine._annotate_credential_assessment
    在为空时补凭据说明 → 否则只有预览。
    """
    view = _view(finding)
    # 策略绑定会把 rule_id 改成策略编号，原编号在 source_rule_id。
    if (view.source_rule_id or view.rule_id).startswith("sensitive_data_"):
        return masked_placeholder(view.category)
    if view.type == "secret" or view.category.startswith("code_leak_"):
        return credential_evidence_text(view.type, view.category, view.matched_text_preview)
    return view.matched_text_preview


def _confirmed_generated(view, kind: str) -> bool:
    """redacted_evidence 是不是 hit_display 对这条 finding 生成的。只看 finding 自己，不依赖复核时传入的
    content 和 matched_location（网关按单条消息检测、复核传的是拼接文本，位置对不上）。"""
    raw, shown = view.raw_evidence, view.redacted_evidence
    if not raw or not shown:
        return False
    if kind == "marker":
        head = bounded(raw)
        return shown == head or (shown.startswith(head + MARKER_BODY_PREFIX) and shown.endswith(MARKER_BODY_SUFFIX))
    # credential、identifier、plain 的结果只取决于命中原文；auto 带后文时无法在这里重算，按“无法确认”处理。
    return render_hit_display(kind, raw).text == shown


def triage_evidence(finding) -> str:
    """发给 AI 复核的 evidence 原始值：这一版必须与 2.9.18 逐字相同。"""
    try:
        view = _view(finding)
        # type 不会被策略绑定改写；rule_type 会（变成 matcher_policy 等）。
        if view.type == "custom" or is_custom_rule_type(view.rule_type):
            return view.matched_text_preview or view.redacted_evidence
        kind, _ = _resolve_kind(view)
        if kind is not None:
            from app.triage_service import NEVER_TRIAGE_TYPES  # 延迟导入：triage_service 依赖 triage，triage 依赖本模块

            if _confirmed_generated(view, kind) or view.type in NEVER_TRIAGE_TYPES:
                return legacy_triage_evidence(finding)
    except Exception as error:  # noqa: BLE001 复核不能因此失败
        _logger.warning("复核证据还原失败，按原逻辑取值：error=%s", type(error).__name__)
    return _plain_evidence(finding)


def _plain_evidence(finding) -> str:
    view = _view(finding)
    return view.redacted_evidence or view.matched_text_preview
