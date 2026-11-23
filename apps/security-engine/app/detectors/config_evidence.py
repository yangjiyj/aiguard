"""Sensitive configuration requires a literal value, not just a variable name."""
import re
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit, unquote, parse_qsl

SENSITIVE_KEY = re.compile(
    r"\b(?:[A-Za-z][A-Za-z0-9]*[_-]){0,8}"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|database[_-]?url|db[_-]?url|connection|dsn|credential|"
    r"authorization|client[_-]?secret)\b[ \t]*(?:\\*[\"'])?[ \t]*[:=]", re.I)

# Exact conventional placeholders only: a caller saying "example" elsewhere
# must not suppress a real credential in the same text.
_PLACEHOLDER = re.compile(
    r"(?:your[_-]?(?:api[_-]?key|password|secret|token)(?:[_-]?here)?|"
    r"(?:example|sample|dummy|test|placeholder)[_-](?:password|api[_-]?key|secret|token)|"
    r"(?:password|api[_-]?key|secret|token)[_-](?:here|placeholder)|"
    r"replace[_-]?(?:me|this)|changeme|<[^<>\r\n]+>)", re.I)


def is_placeholder_value(value):
    return bool(_PLACEHOLDER.fullmatch(str(value).strip().strip("\"'")))


_SERIALIZED_VALUE_END = re.compile(r"\\+(?:[nrt]|['\"`])")

_QUOTED_FIELD_END = re.compile(
    r"(?P<quote>['\"`])[\w][\w .-]{0,127}\s*[:=]\s*$", re.I)
_REFERENCE_VALUE = re.compile(
    r"(?:\$\{[A-Za-z_][A-Za-z0-9_.]*(?::-?|:\?[^{}]*)?\}|"
    r"\$[A-Za-z_][A-Za-z0-9_]*|\$env:[A-Za-z_][A-Za-z0-9_]*|"
    r"%[A-Za-z_][A-Za-z0-9_]*%|\{(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]*)\}|"
    r"%(?:[0-9]+\$)?[-+0-9.]*[sdfiu])", re.I)
# A value that begins with a simple variable expansion is derived from that
# variable at run time; whatever follows it is concatenated onto an unknown
# value, so the text never states the secret itself. Braced forms keep the
# strict grammar above because "${NAME:-literal}" carries a default value.
_REFERENCE_PREFIX = re.compile(
    r"(?:\$env:[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_])|\$[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_])|%[A-Za-z_][A-Za-z0-9_]*%)", re.I)
# The content of a quote that opens with an infix operator is the gap between
# two string literals ('KEY=' + name + '\n'), not a quoted secret.
_CONCATENATION_GAP = re.compile(r"[ \t]*(?:\+|\.\.?|\|\||&)[ \t]+\S")
_CJK = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff]")
_CJK_PUNCTUATION = re.compile(r"[、，。：；！？“”‘’（）《》〈〉【】「」『』·—…]")
# Ellipsis marks an elided excerpt in prose or a shortened log line; it is
# never part of a machine credential.
_UNQUOTED_STOP = " \t,，;；`'\"。！？…"


def is_prose_value(value: str, quoted: bool = False) -> bool:
    """Sentences about the field are not credential material.

    An unquoted run after "password:" that carries no ASCII letter or digit
    ("password: 提示后吞入中文说明"), or any value that mixes CJK text with
    spaces or CJK punctuation, is an explanation, not the secret itself. A
    quoted CJK-only value without spaces ("密码甲乙丙丁戊己") stays a literal:
    unusual real passwords are not exempted by their script.
    """
    text = value.strip()
    if not text:
        return False
    if not quoted and not re.search(r"[A-Za-z0-9]", text):
        return True
    if _CJK.search(text) and (re.search(r"\s", text) or _CJK_PUNCTUATION.search(text)):
        return True
    return False


_LABEL_PAIR_AFTER = re.compile(
    r"['\"`]?[ \t]*,[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*[:=][ \t]*(['\"`])(?P<label>[^'\"`\r\n]{1,64})\1")
_LABEL_PAIR_BEFORE = re.compile(
    r"(['\"`])(?P<label>[^'\"`\r\n]{1,64})\1[ \t]*,[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*[:=][ \t]*\\*['\"`]$")


def is_label_mapping_value(content: str, start: int, end: int) -> bool:
    """A quoted CJK-only value inside a dictionary of identifier→label pairs.

    "plain_password: '疑似明文密码', code_leak_password_in_code: '代码中的凭据候选'"
    is an i18n table: the sibling entry is another identifier with another
    CJK display name. A lone CJK password has no such sibling.
    """
    value = content[start:end]
    if not value or re.search(r"[A-Za-z0-9]", value):
        return False
    for pattern, segment in ((_LABEL_PAIR_AFTER, content[end:end + 160]),
                             (_LABEL_PAIR_BEFORE, content[max(0, start - 160):start])):
        match = pattern.match(segment) if pattern is _LABEL_PAIR_AFTER else pattern.search(segment)
        if match and _CJK.search(match.group("label")):
            return True
    return False

_CODE_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_CODE_INDEX = re.compile(r"-?[0-9]*(?::-?[0-9]*){0,2}|[A-Za-z_$][A-Za-z0-9_$]*")


def _parse_code_expression(text: str, pos: int, depth: int = 0):
    """Parse ``primary postfix*``; return (end, saw_call_or_group, saw_member, saw_index) or None."""
    if depth > 8 or pos >= len(text):
        return None
    call = member = index = False
    if text[pos] == "(":
        inner = _parse_code_expression(text, pos + 1, depth + 1)
        if inner is None or inner[0] >= len(text) or text[inner[0]] != ")":
            return None
        pos, call = inner[0] + 1, True
        member, index = inner[2], inner[3]
    else:
        ident = _CODE_IDENT.match(text, pos)
        if not ident:
            return None
        pos = ident.end()
    while pos < len(text):
        char = text[pos]
        if char == ".":
            ident = _CODE_IDENT.match(text, pos + 1)
            if not ident:
                return None
            pos, member = ident.end(), True
        elif char == "(":
            pos += 1
            while pos < len(text) and text[pos] != ")":
                arg = _parse_code_expression(text, pos, depth + 1)
                if arg is None:
                    return None
                pos = arg[0]
                if pos < len(text) and text[pos] == ",":
                    pos += 1
            if pos >= len(text):
                return None
            pos, call = pos + 1, True
        elif char == "[":
            idx = _CODE_INDEX.match(text, pos + 1)
            close = idx.end() if idx else pos + 1
            if close >= len(text) or text[close] != "]":
                return None
            pos, index = close + 1, True
        else:
            break
    return pos, call, member, index


def is_code_expression(value: str) -> bool:
    """``(input().split())[0]`` / ``sys.argv[1]``: the value is computed at run time.

    Whole-value grammar of identifiers, member access, calls and subscripts.
    A literal that merely contains parentheses (``P@ss(w0rd)!``) does not parse.
    """
    parsed = _parse_code_expression(value, 0)
    if parsed is None or parsed[0] != len(value):
        return False
    _, call, member, index = parsed
    return call or (member and index)


@dataclass(frozen=True)
class CredentialValue:
    kind: str
    value: str
    start: int
    end: int


def read_credential_value(content: str, start: int = 0) -> CredentialValue:
    """Read one value in its original representation; never recursively unescape.

    Serialized newline/quote runs are delimiters, not credential material.
    Offsets always refer to the original input, including nested tool JSON.
    """
    i = start
    while i < len(content) and content[i] in " \t":
        i += 1
    opener = re.match(r"\\*(['\"`])", content[i:])
    quote = opener.group(1) if opener else ""
    if opener:
        boundary = _QUOTED_FIELD_END.search(content[max(0,i-256):i])
        after = i + opener.end()
        if boundary and boundary.group("quote") == quote and re.match(r"[ \t]*(?:[+%.,);\]}]|$)",content[after:]):
            # This delimiter closes the field-name string in executable source.
            # Do not treat the following operator/variable as its value. A
            # directly concatenated literal still represents embedded material.
            concat = re.match(r"[ \t]*\+[ \t]*",content[after:])
            if concat:
                rhs=after+concat.end()
                if re.match(r"\\*['\"`]",content[rhs:]):
                    literal=read_credential_value(content,rhs)
                    if literal.kind=="literal":return literal
            return CredentialValue("expression","",after,after)
        i = after
    end = i
    while end < min(len(content), i + 4096):
        if _SERIALIZED_VALUE_END.match(content, end):
            break
        char = content[end]
        if char in "\r\n" or (quote and char == quote):
            break
        if not quote and char in _UNQUOTED_STOP:
            break
        end += 1
    value = content[i:end]
    # A quote immediately followed by source punctuation closes a quoted field
    # name/example, rather than opening an assigned secret value.
    if quote and (not value.strip(", ") or re.match(r"\);[A-Za-z_][A-Za-z0-9_]*\.", value)
                  or value.startswith(("。", "：", "！", "？"))):
        return CredentialValue("expression", value, i, end)
    if quote and _CONCATENATION_GAP.match(value):
        # 'PASSWORD=' + value + '\n' quoted in prose: the quote after "=" closes
        # the key string and the quoted run is source code between literals.
        return CredentialValue("expression", value, i, end)
    if not value or value in {"null", "None", "undefined"}:
        kind = "empty"
    elif is_placeholder_value(value):
        kind = "placeholder"
    elif _REFERENCE_VALUE.fullmatch(value) or (not quote and _REFERENCE_PREFIX.match(value)):
        kind = "reference"
    elif not quote and (re.match(r"process\.env(?:\.[A-Za-z_][A-Za-z0-9_]*|\[)",value)
                         or re.match(r"[A-Za-z_][A-Za-z0-9_.]*\(",value)
                         or re.match(r"os\.environ\[",value)
                         or is_code_expression(value)):
        kind = "expression"
    elif is_prose_value(value, quoted=bool(quote)) or (quote and is_label_mapping_value(content, i, end)):
        kind = "prose"
    else:
        kind = "literal"
    return CredentialValue(kind, value, i, end)


def is_reference_value(value):
    return read_credential_value(str(value)).kind in {"reference", "expression"}


def is_empty_shell_parameter(content, start):
    """Empty defaults and error-message expansions are not password assignments."""
    return bool(re.search(r"\$\{[A-Za-z0-9_]*$", content[max(0,start-256):start])
                and re.match(r"[A-Za-z0-9_]+(?::-\}|:\?[^{}]*\})", content[start:]))


def credential_url_has_literal(value):
    # Validate authority before calling this a connection-string credential.
    # A source fragment ending in @ or an escaped quote is not a hostname.
    candidate=read_credential_value(value).value
    try:
        parsed=urlsplit(candidate)
        host=parsed.hostname or ""
        if not host:return False
        if not _REFERENCE_VALUE.fullmatch(host):
            if ":" in host:
                ipaddress.ip_address(host)
            else:
                host=host.encode("idna").decode("ascii")
                if not re.fullmatch(r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_.-])?",host):return False
        candidates=[unquote(parsed.password or "")]
        candidates.extend(v for k,v in parse_qsl(parsed.query,max_num_fields=64)
                          if k.lower() in {"password","passwd","pwd","sslpassword","auth","token"})
        return any(v and not is_placeholder_value(v) and not _REFERENCE_VALUE.fullmatch(v) for v in candidates)
    except (ValueError,UnicodeError):
        return False


_AUTH_SCHEMES = frozenset({"bearer", "basic", "token", "digest", "negotiate", "ntlm"})


def has_literal_sensitive_config(text):
    for match in SENSITIVE_KEY.finditer(text):
        if is_empty_shell_parameter(text, match.start()):
            continue
        value = read_credential_value(text, match.end())
        if value.kind == "literal" and value.value.lower() in _AUTH_SCHEMES:
            # "Authorization: Bearer ${TOKEN}": the scheme word is not the secret;
            # judge the credential that follows it (none at all → header template).
            value = read_credential_value(text, value.end)
        if value.kind != "literal":
            continue
        if re.match(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://", value.value, re.I):
            if credential_url_has_literal(value.value):
                return True
            continue
        return True
    # A bare URL still needs a literal password; a host or reference is not one.
    return any(credential_url_has_literal(m.group()) for m in re.finditer(
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"`]+", text, re.I))
