"""Numeric syntax and fixed telemetry columns, never a source/client allowlist."""
import re


def is_git_remote_reference(content: str, start: int, end: int) -> bool:
    """Recognize Git SSH transport syntax, not arbitrary email domains."""
    value = content[start:end]
    if not value.lower().startswith("git@"):
        return False
    tail = content[end:end + 256]
    return bool(re.match(r":[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+(?:\.git)?(?:[\s\"'`;,)\]}]|$)", tail)
                or (content[max(0, start - 6):start] == "ssh://" and tail.startswith("/")))

# Only the fractional digits are excluded: they are part of one decimal token,
# not a standalone card/phone number. Quoted integer identifiers remain scanned.
_DECIMAL = re.compile(r"(?<![\w.])[+-]?\d+\.(?P<fraction>\d{11,19})(?!\d)")
_NL = r"(?:\r?\n|\\r\\n|\\n)"
_SWAP_HEADER = re.compile(
    r"(?:^|" + _NL + r")NAME[ \t]+TYPE[ \t]+SIZE[ \t]+USED[ \t]+PRIO[ \t]*" + _NL,
    re.MULTILINE,
)
_SWAP_ROW = re.compile(
    r'[^ \t\r\n\\"]+[ \t]+(?:file|partition)[ \t]+'
    r"(?P<size>\d+)[ \t]+(?P<used>\d+)[ \t]+-?\d+[ \t]*(?=" + _NL + r"|$)"
)


def is_complete_pii_token(content: str, start: int, end: int) -> bool:
    """Reject numeric substrings of identifiers without excluding Chinese labels.

    Separators in URLs and JSON do not make a complete PII value harmless.
    Decimal components, adjacent digits (including Unicode), and ASCII
    identifier characters do not delimit a standalone phone/card/ID.
    """
    if not 0 <= start < end <= len(content):
        return False
    for adjacent in (content[start - 1:start] if start else "", content[end:end + 1]):
        if adjacent and (adjacent.isdecimal() or adjacent in
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"):
            return False
    if start >= 2 and content[start - 1] == "." and content[start - 2].isdecimal():
        return False
    if end + 1 < len(content) and content[end] == "." and content[end + 1].isdecimal():
        return False
    return True


_MAX_BOUNDING_LETTERS = 12
_HEX_LETTERS = frozenset("abcdefABCDEF")


def is_letter_bounded_number(content: str, start: int, end: int) -> bool:
    """A number glued only to short ASCII letter words: "tel13800138000end".

    Boundaries are "not a digit": adjacent Unicode digits, decimal parts and
    underscores still reject. The enclosing ASCII word may hold no other digit
    or underscore (hashes, identifiers such as user_138..., a1b2c138...), and
    the letter runs on each side stay short, so encoded blobs do not qualify.
    Letter runs made only of hex digits are treated as a hash fragment.
    """
    if not 0 <= start < end <= len(content):
        return False
    before = content[start - 1:start] if start else ""
    after = content[end:end + 1]
    for adjacent in (before, after):
        if adjacent and (adjacent.isdecimal() or adjacent == "_"):
            return False
    if start >= 2 and before == "." and content[start - 2].isdecimal():
        return False
    if end + 1 < len(content) and after == "." and content[end + 1].isdecimal():
        return False
    left = start
    while left > 0 and content[left - 1].isascii() and content[left - 1].isalpha():
        left -= 1
    right = end
    while right < len(content) and content[right].isascii() and content[right].isalpha():
        right += 1
    if start - left > _MAX_BOUNDING_LETTERS or right - end > _MAX_BOUNDING_LETTERS:
        return False
    # Letters that are all hex digits ("abc13800138000def", "cafe138...") read
    # as a fragment of a hash, not as a word such as "tel" or "end".
    if all(_HEX_LETTERS.issuperset(side) for side in (content[left:start], content[end:right])):
        return False
    for edge in (content[left - 1:left] if left else "", content[right:right + 1]):
        if edge and edge.isascii() and (edge.isalnum() or edge == "_"):
            return False
    return True


def non_pii_numeric_spans(content, identifiers=True):
    """Numeric spans that are syntax, not PII.

    identifiers=False keeps decimal fractions and swap columns but not digit
    runs inside ASCII words; the letter-bounded phone check
    (is_letter_bounded_number) judges those words itself.
    """
    spans = {m.span("fraction") for m in _DECIMAL.finditer(content)}
    # A digit run embedded in an ASCII identifier/hash is not a phone/card.
    # Do not use Unicode \w boundaries: Chinese labels may touch real numbers.
    for token in re.finditer(r"[A-Za-z0-9_]+", content) if identifiers else ():
        value = token.group()
        if re.search(r"[A-Za-z_]", value):
            spans.update((token.start()+m.start(), token.start()+m.end())
                         for m in re.finditer(r"\d{11,19}", value))
    for header in _SWAP_HEADER.finditer(content):
        position = header.end()
        for _ in range(32):
            row = _SWAP_ROW.match(content, position)
            if row is None:
                break
            spans.update((row.span("size"), row.span("used")))
            newline = re.match(_NL, content[row.end():row.end()+4])
            if newline is None:
                break
            position = row.end() + newline.end()
    return spans


def is_url_userinfo(content: str, start: int, end: int) -> bool:
    """"user:pass@host" inside "scheme://" is URL authority, not a mailbox.

    The connection-string detectors own that credential; reporting the same
    span as an email address duplicates it under a wrong category.
    """
    prefix = content[max(0, start - 512):start]
    return bool(re.search(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/?#@\"'`<>]*$", prefix))


def is_escaped_sequence_local_part(content: str, start: int, end: int) -> bool:
    """A backslash escape is not a mailbox name.

    Serialized source keeps "\n@pytest.fixture" as the two characters "\n"
    followed by a decorator; the regex sees "n@pytest.fixture". Only an escape
    letter directly after a backslash is rejected, so "\nadmin@corp.example"
    still yields the real address minus its stray prefix.
    """
    if start <= 0 or content[start - 1] != "\\":
        return False
    local = content[start:end].split("@", 1)[0]
    return bool(re.fullmatch(r"[nrtbfav0]|x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}", local))
