"""内置“辱骂脏话”检测器（capability: content_profanity_abuse）。

设计要点
- 词表在 app/data/profanity_lexicon.json，分强词 / 弱词 / 白名单 / 讨论线索，改词表不改代码。
- 强词（傻逼、他妈的、去死……含谐音、拼音缩写、字间插空格）直接命中；
  弱词（废物、垃圾、蠢……）只有“你/他 + 修饰 + 弱词”这类指向人的结构才命中；
  白名单（废物利用、垃圾分类、傻瓜相机、蠢蠢欲动……）完整覆盖命中才不算；强词命中的白名单前面
  有“你/您/滚/全家/一家”等指人或骂人语气时白名单不生效（“你全家畜生”“滚过去死了算了”）。
- 引用/讨论场景（“请把脏话‘傻逼’翻译成英文”“傻逼这个词是脏话吗”）：强词降为观察
  （counts_as_security_finding=False、action=allow，仍留证据），弱词不命中。
- 输入、输出两个方向共用本检测器（由 ContentSafetyDetector.detect 调用）。

归一化：本模块自带一个小的本地归一化（NFKC、去零宽/不可见字符、汉字之间的空白与少量分隔符折叠），
并保留到原文偏移的映射，使证据位置仍指向原文。
合并后改用车道 A 的统一归一化：只需把 fold_text() 的实现换成统一函数，保持返回
(归一化文本, 每个字符对应的原文下标) 即可。
"""
from __future__ import annotations

import itertools
import json
import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from app.text_normalize import fold_text as _unified_fold_text
from app.detectors.evidence_context import (
    SentenceIndex, has_quote_execution, prepare_reference_context,
)

CATEGORY = "content_profanity_abuse"
RULE_ID = "content_safety_profanity_abuse"
RULE_NAME = "辱骂脏话"
LEXICON_PATH = Path(__file__).resolve().parent.parent / "data" / "profanity_lexicon.json"

_NON_WORD = "[^一-鿿A-Za-z0-9]"


def fold_text(text: str, separators: str) -> Tuple[str, Sequence[int]]:
    """NFKC + 去零宽/不可见字符 + 汉字之间的分隔符折叠（委托统一归一化模块）。

    返回 (归一化文本, idx)，idx[i] 是归一化文本第 i 个字符对应的原文下标。
    实现见 app.text_normalize.fold_text，与原本地实现做过随机差分对拍、结果一致。
    """
    return _unified_fold_text(text, separators)


def _cls(chars: str) -> str:
    return "[" + "".join(re.escape(c) for c in chars) + "]"


def _is_ascii_alnum(ch: str) -> bool:
    return ch.isascii() and ch.isalnum()


def _suffix_pattern(last: str, spec: dict) -> str:
    suffix = ""
    if _is_ascii_alnum(last):
        suffix += "(?![A-Za-z0-9])"
    if spec.get("after_not"):
        suffix += "(?!" + _cls(spec["after_not"]) + ")"
    if spec.get("after_only"):
        suffix += "(?=" + _cls(spec["after_only"]) + "|" + _NON_WORD + "|$)"
    return suffix


def _expand_group(group: dict, kind: str) -> List[Tuple[Tuple[str, ...], str, str]]:
    """返回 [(原子序列, 首字符, 末字符)]。原子是单个转义字符或一段分隔正则。"""
    items: List[Tuple[Tuple[str, ...], str, str]] = []
    for word in group.get("words", []):
        atoms: List[str] = []
        if kind == "en":
            for number, part in enumerate(word.split()):
                if number:
                    atoms.append(r"\s+")
                atoms.extend(re.escape(c) for c in part)
        else:
            atoms = [re.escape(c) for c in word]
        items.append((tuple(atoms), word[0], word[-1]))
    if group.get("expand"):
        for combo in itertools.product(*group["expand"]):
            word = "".join(combo)
            items.append((tuple(re.escape(c) for c in word), word[0], word[-1]))
    for syllables in group.get("syllables", []):
        atoms = []
        for number, syllable in enumerate(syllables):
            if number:
                atoms.append(r"[\s._-]?")
            atoms.extend(re.escape(c) for c in syllable)
        items.append((tuple(atoms), syllables[0][0], syllables[-1][-1]))
    return items


def _trie_regex(entries: List[Tuple[Tuple[str, ...], str]]) -> str:
    """把 (原子序列, 后缀断言) 压成前缀树正则。匹配时按首字符分流，
    避免几百个候选词逐个线性尝试（长文本下差一个数量级）。"""
    root: dict = {}
    for atoms, suffix in entries:
        node = root
        for atom in atoms:
            node = node.setdefault(atom, {})
        node.setdefault(None, set()).add(suffix)

    def render(node: dict) -> str:
        branches = [atom + render(node[atom]) for atom in sorted(k for k in node if k is not None)]
        terminal = node.get(None)
        if terminal:
            # 更长的延续写在前面，终结分支写在最后，保证优先取最长词
            branches.append("|".join(sorted(terminal, key=len, reverse=True)))
        if len(branches) == 1:
            return branches[0]
        return "(?:" + "|".join(branches) + ")"

    return render(root)


@dataclass
class _Special:
    regex: "re.Pattern[str]"
    ctx_before: Optional["re.Pattern[str]"]
    ctx_after: Optional["re.Pattern[str]"]
    after_not_dot: bool
    not_before: Optional["re.Pattern[str]"] = None
    not_after: Optional["re.Pattern[str]"] = None


class ProfanityLexicon:
    def __init__(self, data: dict):
        self.version = data.get("version", 1)
        self.separators = data.get("fold", {}).get("separators", "")
        # 普通词按 before_not 分组，每组一棵前缀树
        trees: Dict[str, List[Tuple[Tuple[str, ...], str]]] = {}
        self.special: List[_Special] = []
        self.strong_terms = 0
        for kind in ("zh", "pinyin", "en"):
            for group in data["strong"].get(kind, []):
                special = bool(group.get("ctx_before") or group.get("ctx_after")
                               or group.get("after_not_dot") or group.get("case_sensitive")
                               or group.get("not_before") or group.get("not_after"))
                # case_sensitive：只认词表里写出的大小写（与技术缩写同形的词，如 TMD/SB）
                flags = 0 if group.get("case_sensitive") else re.I
                lookbehind = "(?<!" + _cls(group["before_not"]) + ")" if group.get("before_not") else ""
                for atoms, _first, last in _expand_group(group, kind):
                    self.strong_terms += 1
                    suffix = _suffix_pattern(last, group)
                    if special:
                        self.special.append(_Special(
                            re.compile(lookbehind + "".join(atoms) + suffix, flags),
                            re.compile(group["ctx_before"], re.I) if group.get("ctx_before") else None,
                            re.compile(group["ctx_after"], re.I) if group.get("ctx_after") else None,
                            bool(group.get("after_not_dot")),
                            re.compile(group["not_before"], re.I) if group.get("not_before") else None,
                            re.compile(group["not_after"], re.I) if group.get("not_after") else None,
                        ))
                    else:
                        trees.setdefault(lookbehind, []).append((atoms, suffix))
        self.strong_res = [re.compile(lb + _trie_regex(entries), re.I) for lb, entries in trees.items()]

        weak = data["weak"]
        self.weak_terms = list(weak.get("zh", []))
        prefix = weak.get("person_prefix", "")
        terms = "|".join(re.escape(t) for t in sorted(self.weak_terms, key=len, reverse=True))
        self.weak_re = re.compile(prefix + "(?P<term>" + terms + ")") if terms else None
        self.weak_en_re = [re.compile(p, re.I) for p in weak.get("en", [])]

        allow = sorted(data.get("allow", []), key=len, reverse=True)
        self.allow_re = re.compile("|".join(re.escape(a) for a in allow)) if allow else None
        self.allow_count = len(allow)
        void = data.get("allow_void_before")
        self.allow_void_re = re.compile(void) if void else None
        void_after = data.get("allow_void_after")
        self.allow_void_after_re = re.compile(void_after) if void_after else None
        keep_after = data.get("allow_keep_after")
        self.allow_keep_after_re = re.compile(keep_after) if keep_after else None

        discussion = data.get("discussion", {})
        self.cue_re = re.compile(discussion["cue"], re.I) if discussion.get("cue") else None
        self.quote_max = int(discussion.get("quote_max_chars", 24))
        self.second_person_re = re.compile(discussion["second_person"]) if discussion.get("second_person") else None
        self.direct_re = re.compile(discussion["direct_address_before_quote"]) if discussion.get("direct_address_before_quote") else None
        self.forward_re = re.compile(discussion["forward_to_person"]) if discussion.get("forward_to_person") else None
        self.bare_after_re = re.compile(discussion["bare_after"]) if discussion.get("bare_after") else None
        self.bare_before_re = re.compile(discussion["bare_before"]) if discussion.get("bare_before") else None
        self.bare_example_re = re.compile(discussion["bare_before_example"]) if discussion.get("bare_before_example") else None

    @classmethod
    def load(cls, path: Path = LEXICON_PATH) -> "ProfanityLexicon":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))


# A bracket class without escapes or negation: the pattern matches exactly one character.
_ONE_CHARACTER = re.compile(r"\[[^\\\]^][^\\\]]*\]")
# The lexicon's forward_to_person pattern: a literal head of at most three characters (骂 not followed by
# 人词话的声, 发给, 转给, 发送给, 转发给, 传给, 私信给, 回复给), optional whitespace, then a letter. From any
# position it matches at most one way, and a match reads nothing outside itself; _MatchOutside relies on both.
_HEAD_SPACE_LETTER = r"(?:骂(?![人词话的声])|(?:发|转|发送|转发|传|私信|回复)给)\s*[一-鿿A-Za-z]"
_HEAD_WIDTH = 3


class _MatchOutside:
    """``pattern.search(local[:a] + " " + local[b:])`` for many spans of one text, where ``local`` is the span's
    sentence and ``a``, ``b`` the span within it: does the sentence match once the span becomes a space?

    For the lexicon's two sentence-wide patterns the matches are found once (per text or per sentence) and each span
    only looks around itself; any other pattern is searched as written.
    - One character class ([你您妳]): a matching character in the sentence outside the span.
    - _HEAD_SPACE_LETTER: a match wholly before the span, wholly after it, or across the space — the head right
      before the whitespace that ends the text before the span, the letter right after the whitespace that starts
      the text after it.
    """

    def __init__(self, pattern, content, sentences):
        self.pattern = pattern
        self.sentences = sentences
        plain_flags = pattern.flags == re.compile("").flags
        if plain_flags and _ONE_CHARACTER.fullmatch(pattern.pattern):
            self.kind = "char"
            self.positions = [match.start() for match in pattern.finditer(content)]
            self.space = bool(pattern.match(" "))
        elif plain_flags and pattern.pattern == _HEAD_SPACE_LETTER:
            self.kind = "head"
            self.matches = {}
        else:
            self.kind = "plain"

    def __call__(self, start, end):
        bounds = self.sentences.bounds(start, end)
        if self.kind == "char":
            return self.space or self._character_outside(bounds, start, end)
        local = self.sentences.text(*bounds)
        a, b = start - bounds[0], end - bounds[0]
        if self.kind == "plain":
            return bool(self.pattern.search(local[:a] + " " + local[b:]))
        return self._head_outside(bounds, local, a, b)

    def _character_outside(self, bounds, start, end):
        left, right = bounds
        positions = self.positions
        index = bisect_left(positions, left)
        if index < len(positions) and positions[index] < start:
            return True
        index = bisect_left(positions, end, index)
        return index < len(positions) and positions[index] < right

    def _head_outside(self, bounds, local, a, b):
        found = self.matches.get(bounds)
        if found is None:
            # Every position a match starts at, including ones inside another match.
            starts, ends = [], []
            match = self.pattern.search(local)
            while match is not None:
                starts.append(match.start())
                ends.append(match.end())
                match = self.pattern.search(local, match.start() + 1)
            found = self.matches[bounds] = (min(ends, default=len(local) + 1), max(starts, default=-1))
        first_end, last_start = found
        if first_end <= a or last_start >= b:
            return True
        head_end = a
        while head_end > 0 and local[head_end - 1].isspace():
            head_end -= 1
        letter = b
        while letter < len(local) and local[letter].isspace():
            letter += 1
        return bool(self.pattern.search(local[max(0, head_end - _HEAD_WIDTH):a] + " " + local[b:letter + 1]))


class _Scan:
    """Lookups shared by every hit of one text: its sentences, its quotes and the sentence-wide patterns."""

    def __init__(self, lexicon: ProfanityLexicon, content: str, ctx):
        self.sentences = SentenceIndex(content)
        self.quotes = ctx.quotes
        self.quote_starts = [a for a, _ in ctx.quotes]
        self.second_person = (_MatchOutside(lexicon.second_person_re, content, self.sentences)
                              if lexicon.second_person_re is not None else None)
        self.forward = (_MatchOutside(lexicon.forward_re, content, self.sentences)
                        if lexicon.forward_re is not None else None)


@dataclass
class _Hit:
    tier: str  # strong | weak
    start: int  # 归一化文本偏移
    end: int
    kind: str


def _ascii_token_start_ok(norm: str, start: int) -> bool:
    """以 ASCII 字母数字开头的词必须是独立单词（前面不能紧挨字母数字）。"""
    return not (start > 0 and _is_ascii_alnum(norm[start]) and _is_ascii_alnum(norm[start - 1]))


class ProfanityDetector:
    def __init__(self, lexicon: Optional[ProfanityLexicon] = None):
        self.lexicon = lexicon or ProfanityLexicon.load()

    # ---- 匹配 -------------------------------------------------------
    def _strong_hits(self, norm: str) -> List[_Hit]:
        lex = self.lexicon
        hits: List[_Hit] = []
        for regex in lex.strong_res:
            for m in regex.finditer(norm):
                if _ascii_token_start_ok(norm, m.start()):
                    hits.append(_Hit("strong", m.start(), m.end(), "strong"))
        for special in lex.special:
            for m in special.regex.finditer(norm):
                if not _ascii_token_start_ok(norm, m.start()):
                    continue
                if special.after_not_dot and norm[m.end():m.end() + 1] in (".", "-", "_", "/"):
                    continue
                # 技术语境（变量、参数、key=value、函数调用、信号/关节等术语）不算
                if special.not_before is not None and special.not_before.search(
                        norm[max(0, m.start() - 6):m.start()]):
                    continue
                if special.not_after is not None and special.not_after.search(norm[m.end():m.end() + 12]):
                    continue
                before_ok = special.ctx_before is not None and bool(
                    special.ctx_before.search(norm[max(0, m.start() - 4):m.start()]))
                after_ok = special.ctx_after is not None and bool(
                    special.ctx_after.search(norm[m.end():m.end() + 10]))
                if special.ctx_before is None and special.ctx_after is None:
                    before_ok = True
                if before_ok or after_ok:
                    hits.append(_Hit("strong", m.start(), m.end(), "strong"))
        return hits

    def _weak_hits(self, norm: str) -> List[_Hit]:
        lex = self.lexicon
        hits: List[_Hit] = []
        if lex.weak_re:
            for m in lex.weak_re.finditer(norm):
                hits.append(_Hit("weak", m.start("term"), m.end("term"), "weak"))
        for regex in lex.weak_en_re:
            for m in regex.finditer(norm):
                hits.append(_Hit("weak", m.start(), m.end(), "weak_en"))
        return hits

    def _allow_lookup(self, norm: str, allow_spans: List[Tuple[int, int]]):
        """命中是否被白名单豁免：白名单完整覆盖命中；强词还要看白名单前后是不是骂人。

        只与命中部分重叠不算。白名单后面紧跟延续成分（畜生病、畜生产量）时始终豁免；否则强词命中前
        紧挨着"你/您 + 可选的 就是/全家/一家/个/这帮…（再接家）"或"滚"、或白名单后面是"算了/吧"时，
        白名单不生效（你全家畜生、我看你就是家畜生、你个畜生产的、你跳下去死了算了）。"你"与强词之间
        隔着别的词（你家畜生病了、你说过去死了多少人）照常豁免。

        白名单区间来自同一次 finditer，互不重叠：能完整覆盖命中的只可能是起点不晚于命中的最后一个。
        """
        lex = self.lexicon
        starts = [a for a, _ in allow_spans]

        def allowed(hit: _Hit) -> bool:
            index = bisect_right(starts, hit.start) - 1
            if index < 0 or hit.end > allow_spans[index][1]:
                return False
            b = allow_spans[index][1]
            if lex.allow_keep_after_re is not None and lex.allow_keep_after_re.match(norm[b:b + 8]):
                return True
            if hit.tier == "strong":
                if lex.allow_void_re is not None and lex.allow_void_re.search(norm[max(0, hit.start - 8):hit.start]):
                    return False
                if lex.allow_void_after_re is not None and lex.allow_void_after_re.match(norm[b:b + 8]):
                    return False
            return True

        return allowed

    # ---- 引用 / 讨论 --------------------------------------------------
    def _discussion_reason(self, content: str, start: int, end: int, scan: _Scan) -> str:
        if self.lexicon.cue_re is None:
            return ""
        reason = self._reference_reason(content, start, end, scan)
        # 句内（命中所在引号之外）有"你/您"指向：是骂人不是讨论，一律不降级。
        # 句内有"骂张三 / 发给他 / 转给王五"：让模型把脏话转给具体的人，不算讨论。
        # 这两条整句都要看，比引用、讨论线索费事，所以有引用或讨论线索时才查。
        if not reason or self._addresses_second_person(start, end, scan) or self._forwards_to_person(start, end, scan):
            return ""
        return reason

    def _reference_reason(self, content: str, start: int, end: int, scan: _Scan) -> str:
        lex = self.lexicon
        # 引号互不重叠：严格包住命中的只可能是起点在命中之前的最后一个。
        index = bisect_left(scan.quote_starts, start) - 1
        if index >= 0:
            a, b = scan.quotes[index]
            if end < b and (b - a - 2) <= lex.quote_max:
                left, right = scan.sentences.bounds(a, b)
                prefix = content[max(left, a - 60):a]
                if not (lex.direct_re and lex.direct_re.search(prefix[-12:])):
                    outside = prefix + " " + content[b:min(right, b + 60)]
                    if lex.cue_re.search(outside) and not has_quote_execution(outside):
                        return "quoted_profanity_reference"
        if lex.bare_after_re and lex.bare_after_re.search(content[end:end + 20]):
            if scan.sentences.judge("cue", scan.sentences.bounds(start, end), lex.cue_re.search):
                return "bare_profanity_reference"
        before = content[max(0, start - 16):start]
        if lex.bare_before_re and lex.bare_before_re.search(before):
            return "bare_profanity_reference"
        if lex.bare_example_re and lex.bare_example_re.search(before):
            # “比如：傻逼”本身不说明问题，同一句里还要有词库/敏感词/翻译之类的讨论线索
            if scan.sentences.judge("cue", scan.sentences.bounds(start, end), lex.cue_re.search):
                return "bare_profanity_reference"
        return ""

    @staticmethod
    def _forwards_to_person(start: int, end: int, scan: _Scan) -> bool:
        return scan.forward is not None and scan.forward(start, end)

    @staticmethod
    def _addresses_second_person(start: int, end: int, scan: _Scan) -> bool:
        if scan.second_person is None:
            return False
        # 引号互不重叠：包住命中的只可能是起点不晚于命中的最后一个。
        index = bisect_right(scan.quote_starts, start) - 1
        if index >= 0 and end <= scan.quotes[index][1]:
            start, end = scan.quotes[index]
        return scan.second_person(start, end)

    # ---- 入口 -------------------------------------------------------
    def detect(self, content: str) -> List[Dict]:
        if not content:
            return []
        lex = self.lexicon
        norm, idx = fold_text(content, lex.separators)
        if not norm:
            return []
        allow_spans = [(m.start(), m.end()) for m in lex.allow_re.finditer(norm)] if lex.allow_re else []
        allowed = self._allow_lookup(norm, allow_spans)
        hits = [h for h in self._strong_hits(norm) + self._weak_hits(norm) if not allowed(h)]
        if not hits:
            return []
        scan = _Scan(lex, content, prepare_reference_context(content))
        live: List[Tuple[_Hit, int, int]] = []
        observed: List[Tuple[_Hit, int, int, str]] = []
        for hit in sorted(hits, key=lambda h: (h.start, -(h.end - h.start))):
            start = idx[hit.start]
            end = idx[hit.end - 1] + 1
            reason = self._discussion_reason(content, start, end, scan)
            if reason:
                if hit.tier == "strong":
                    observed.append((hit, start, end, reason))
                continue
            live.append((hit, start, end))
        findings: List[Dict] = []
        if live:
            strong = [item for item in live if item[0].tier == "strong"]
            hit, start, end = (strong or live)[0]
            findings.append(self._finding(content, hit, start, end, total=len(live)))
        elif observed:
            hit, start, end, reason = observed[0]
            finding = self._finding(content, hit, start, end, total=len(observed))
            finding["counts_as_security_finding"] = False
            finding["action"] = "allow"
            finding["evidence_kind"] = "contextual"
            finding["evidence_reason"] = "局部上下文仅支持引用/讨论线索：" + reason
            finding["triage"] = {"disposition": "observation", "disposition_reason": reason,
                                 "confidence_kind": "heuristic_rule_score"}
            findings.append(finding)
        return findings

    @staticmethod
    def _finding(content: str, hit: _Hit, start: int, end: int, *, total: int) -> Dict:
        raw = content[start:end]
        strong = hit.tier == "strong"
        preview = raw.strip()
        if len(preview) > 48:
            preview = preview[:48] + "…"
        return {
            "type": "content_safety",
            "category": CATEGORY,
            "severity": "medium",
            "action": "audit",
            "counts_as_security_finding": True,
            "matched_text_preview": preview,
            "matched_location": f"content[{start}:{end}]",
            "raw_evidence": raw,
            "redacted_evidence": "命中辱骂脏话" + ("（强辱骂词）" if strong else "（指向人的侮辱性用语）"),
            "evidence_kind": "literal",
            "evidence_reason": ("强辱骂词直接命中" if strong else "弱词出现在指向人的结构中")
                               + (f"，共 {total} 处" if total > 1 else ""),
            "rule_id": RULE_ID,
            "rule_name": RULE_NAME,
            "confidence": 0.97 if strong else 0.85,
            "triage": {"cannot_downgrade": True} if strong else {},
        }
