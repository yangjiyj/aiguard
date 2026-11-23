"""Catalog term constructors.

Every English word in a catalog rule is declared through ``w()`` or ``stem()``
so it never matches inside a longer word (``scraper`` is not ``rape``,
``agent`` is not ``age``) while still matching next to Chinese text
(``生成XSS载荷``). ``raw()`` carries Chinese, symbols and digits only.

``w()`` adds the regular inflections of a plain trailing English word
(encourage -> encourages/encouraged/encouraging, glorify -> glorifies),
so whole-word matching does not lose the forms the old substring rules
matched by accident. Irregular forms (wrote, built, stole) are listed
explicitly by the rule.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Tuple

LEFT = "(?<![A-Za-z0-9_])"
RIGHT = "(?![A-Za-z0-9_])"
_STEM_TAIL = "[A-Za-z]*"
_SPACE_TOKENS = ("\\s+", "\\s*", "\\s?", "\\s", "[-\\s]*", "[-\\s]+", "[ \\-]+", "[ \\-]*")
_VOWELS = "aeiouAEIOU"
_PLAIN_PHRASE = re.compile(r"[A-Za-z][A-Za-z']*(?:(?:\\s[+*?]?|\[-\\s\][*+]|\[ \\-\][*+]| )[A-Za-z][A-Za-z']*)*")
_TRAILING_WORD = re.compile(r"[A-Za-z]{3,}$")
_QUANTIFIER = re.compile(r"\?|\{[0-9]+,[0-9]*\}")


@dataclass(frozen=True)
class Fragment:
    """One declared English fragment and the boundaries generated for it."""
    source: str
    left: bool
    right: bool
    stem: bool = False
    inflected: bool = False


@dataclass(frozen=True)
class Pat:
    source: str
    fragments: Tuple[Fragment, ...] = ()


def _is_word_char(char: str) -> bool:
    return char.isascii() and (char.isalnum() or char == "_")


def _first_literal(fragment: str) -> str:
    if fragment.startswith("\\"):
        return ""  # escaped symbol such as \$ or \.
    if fragment[:1] in "([.":
        raise ValueError(f"catalog fragment must start with a literal: {fragment!r}")
    return fragment[:1]


def _last_literal(fragment: str) -> str:
    if fragment.endswith(_SPACE_TOKENS):
        return ""  # "phishing\s+" is followed by another declared word
    tail = fragment
    if len(tail) >= 2 and tail.endswith("?") and _is_word_char(tail[-2]) and tail[-3:-2] != "\\":
        tail = tail[:-1]  # instructions? -> instruction|instructions, both end in a letter
    if len(tail) >= 2 and tail[-2] == "\\":
        return ""  # escaped symbol such as \( or \.
    last = tail[-1:]
    if last in ")]*+}?":
        raise ValueError(f"catalog fragment must end with a literal: {fragment!r}")
    return last


_DERIVED = ("ion", "ions", "ation", "ations", "er", "ers", "or", "ors", "ery")


def inflections(word: str) -> Tuple[str, ...]:
    """Regular inflections plus the derived nouns the old prefix rules matched.

    inject -> injection, exploit -> exploitation, harass -> harassment,
    forge -> forgery. Over-generation is harmless for matching; unrelated
    longer words (agent, culture, heroine, wireless) are still not produced.
    """
    forms = {word}
    if word[-1] in "eE":
        base = word[:-1]
        forms |= {word + "s", word + "d", base + "ing", word + "ment", word + "ments"}
        forms |= {base + suffix for suffix in _DERIVED}
    elif word[-1] in "yY" and word[-2] not in _VOWELS:
        base = word[:-1]
        forms |= {base + "ies", base + "ied", word + "ing"}
        if word[-2:].lower() == "fy":
            forms |= {base + "ication", base + "ications"}
    else:
        forms |= {word + "s", word + "es", word + "ed", word + "ing", word + "ment", word + "ments"}
        forms |= {word + suffix for suffix in _DERIVED}
        if (word[-1] not in _VOWELS + "wxyWXY" and word[-2] in _VOWELS
                and word[-3] not in _VOWELS):
            forms |= {word + word[-1] + "ed", word + word[-1] + "ing", word + word[-1] + "er"}
    return tuple(sorted(forms, key=lambda form: (-len(form), form)))


def _with_inflections(fragment: str) -> Tuple[str, bool]:
    if fragment.endswith("?") or not _PLAIN_PHRASE.fullmatch(fragment):
        return fragment, False
    match = _TRAILING_WORD.search(fragment)
    if match is None:
        return fragment, False
    head, word = fragment[:match.start()], match.group(0)
    return head + "(?:" + "|".join(inflections(word)) + ")", True


def _ascii_letter_run(text: str) -> bool:
    """True when two ASCII letters appear next to each other outside escapes/classes."""
    index = 0
    previous_letter = False
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            previous_letter = False
            continue
        if char == "[":
            index = text.index("]", index + 1) + 1
            previous_letter = False
            continue
        if char == "(" and text.startswith(("(?:", "(?!", "(?<!"), index):
            index += 4 if text.startswith("(?<!", index) else 3
            previous_letter = False
            continue
        letter = char.isascii() and char.isalpha()
        if letter and previous_letter:
            return True
        previous_letter = letter
        index += 1
    return False


def _words(fragments, inflect: bool) -> Pat:
    if not fragments:
        raise ValueError("at least one English fragment is required")
    parts, declared = [], []
    for fragment in fragments:
        left = _is_word_char(_first_literal(fragment))
        right = _is_word_char(_last_literal(fragment))
        body, inflected = _with_inflections(fragment) if inflect else (fragment, False)
        parts.append((left, body + (RIGHT if right else "")))
        declared.append(Fragment(fragment, left, right, inflected=inflected))
    if all(left for left, _ in parts):
        # One boundary test per position instead of one per alternative.
        return Pat(LEFT + "(?:" + "|".join(body for _, body in parts) + ")", tuple(declared))
    return Pat("(?:" + "|".join((LEFT if left else "") + body for left, body in parts) + ")", tuple(declared))


def w(*fragments: str) -> Pat:
    """English words, phrases and code tokens; boundaries follow the edge characters.

    A plain trailing word also matches its regular inflections and derived nouns.
    """
    return _words(fragments, inflect=True)


def exact(*fragments: str) -> Pat:
    """Whole words without inflection, for short words whose inflections mean
    something else (race -> racing, wire -> wiring, age -> aging)."""
    return _words(fragments, inflect=False)


def stem(*stems: str) -> Pat:
    """English stems that accept any ending (discriminat, url\\s*encod)."""
    if not stems:
        raise ValueError("stem() needs at least one stem")
    declared = []
    for value in stems:
        letters = value.replace("[sz]", "s")
        for token in _SPACE_TOKENS:
            letters = letters.replace(token, " ")
        words = letters.split()
        if not words or not all(part.isascii() and part.isalpha() for part in words) or len(words[-1]) < 5:
            raise ValueError(f"catalog stem must end with at least 5 ASCII letters: {value!r}")
        declared.append(Fragment(value, True, False, stem=True))
    return Pat(LEFT + "(?:" + "|".join(stems) + ")" + _STEM_TAIL, tuple(declared))


def raw(*fragments: str) -> Pat:
    """Chinese, symbols and digits. English words must use w() or stem()."""
    if not fragments:
        raise ValueError("raw() needs at least one fragment")
    for fragment in fragments:
        if _ascii_letter_run(fragment):
            raise ValueError(f"English text in raw(): {fragment!r}; use w() or stem()")
    if len(fragments) == 1:
        return Pat(fragments[0])
    return Pat("(?:" + "|".join(fragments) + ")")


def any_of(*pats: Pat) -> Pat:
    _require_pats(pats)
    return Pat("(?:" + "|".join(p.source for p in pats) + ")",
               tuple(f for p in pats for f in p.fragments))


def seq(*pats: Pat) -> Pat:
    _require_pats(pats)
    return Pat("".join(p.source for p in pats), tuple(f for p in pats for f in p.fragments))


def rep(pat: Pat, quantifier: str) -> Pat:
    """Repeat a group: "?" or "{m,n}" / "{m,}" only."""
    if not _QUANTIFIER.fullmatch(quantifier):
        raise ValueError(f"unsupported catalog quantifier: {quantifier!r}")
    _require_pats((pat,))
    return Pat("(?:" + pat.source + ")" + quantifier, pat.fragments)


def near(left: Pat, right: Pat, distance: int, *, gap: str = ".") -> Pat:
    """left then right within ``distance`` characters (gap is "." or an audited class)."""
    return seq(left, raw(f"{gap}{{0,{distance}}}"), right)


def not_followed_by(pat: Pat, follow: Pat) -> Pat:
    """``pat`` unless ``follow`` comes right after it."""
    _require_pats((pat, follow))
    return Pat(pat.source + "(?!" + follow.source + ")", pat.fragments + follow.fragments)


def tempered(stop: Pat, low: int, high: int) -> Pat:
    """``low`` to ``high`` characters, none of which starts ``stop``.

    A gap after a keyword that may not run over the next start of the keyword
    makes a long run of the keyword try each start once instead of rescanning
    the whole window from every start ("compare compare ...").
    """
    _require_pats((stop,))
    if not 0 <= low <= high:
        raise ValueError(f"tempered gap needs 0 <= low <= high: {low}, {high}")
    return Pat("(?:(?!" + stop.source + ").){" + str(low) + "," + str(high) + "}", stop.fragments)


def _require_pats(pats) -> None:
    if not pats:
        raise ValueError("at least one pattern is required")
    for pat in pats:
        if not isinstance(pat, Pat):
            raise TypeError(f"catalog patterns must be built with w/stem/raw, got {type(pat).__name__}")


def not_after(prefix: str, pat: Pat) -> Pat:
    """``pat`` unless the previous word is ``prefix`` (a file extension is not a plugin)."""
    if not (prefix.isascii() and prefix.isalpha()):
        raise ValueError(f"not_after prefix must be ASCII letters: {prefix!r}")
    _require_pats((pat,))
    return Pat("(?<!" + prefix + "\\s)" + pat.source, pat.fragments)


def not_before(pat: Pat, *words: str) -> Pat:
    """``pat`` unless the next word is one of ``words`` ("follow up" is not "follow it").

    Spaces and hyphens may separate the words ("follow-up"); a longer next word
    ("follow upstream") does not stop the match.
    """
    if not words or not all(word.isascii() and word.isalpha() for word in words):
        raise ValueError(f"not_before words must be ASCII letters: {words!r}")
    _require_pats((pat,))
    return Pat(pat.source + "(?![-\\s]+(?:" + "|".join(words) + ")" + RIGHT + ")", pat.fragments)
