"""Legacy normalization helpers retained to reproduce the encoder input contract.

This is not the production default and carries no verified model-quality claim.
Use views.py for bounded evidence preservation; old normalization behavior alone
is not evidence that false positives or false negatives have been resolved."""
from __future__ import annotations

import base64
import binascii
import html
import re
from urllib.parse import unquote

# 零宽 / 格式类不可见字符
INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad\x00-\x08"
                       r"\x0b\x0c\x0e-\x1f\x7f]")
B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,3}")
UNI_ESC = re.compile(r"\\u([0-9a-fA-F]{4})")
HEX_ESC = re.compile(r"\\x([0-9a-fA-F]{2})")
PERCENT = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")
# 连续 ≥4 个「全角字母/数字」才认为是有意的全角编码；
# 绝不能对中文全角标点（，：（）等也在 U+FF01–FF5E 内）做 blanket NFKC——
# 那会把全体中文文本的标点改成 ASCII，扰动 99% 的行（实测 3016/3200 行被改动）。
FULLWIDTH_RUN = re.compile(r"[\uff21-\uff3a\uff41-\uff5a\uff10-\uff19]{4,}")
# 规避式拆字：CJK 之间夹空格 / 分隔符（"忽 略"、"忽*略*"、"忽—略"）。
# 条件触发（≥3 处）以免误伤正常的带空格文本。
CJK_SPACED = re.compile(r"(?<=[\u4e00-\u9fff])[ \u3000]+(?=[\u4e00-\u9fff])")
CJK_SEP = re.compile(r"(?<=[\u4e00-\u9fff])[*·|｜—\-]{1,3}(?=[\u4e00-\u9fff])")
SPLIT_TRIGGER = 3
# 固定的"编码信封"指示语（白名单）：它们不是内容，只是把编码串交给模型的包装语。
# 实测它们会在不可信内容里制造域相关的常数偏移（base64 良性 −8.0 vs 普通良性 −16）。
ENVELOPE_PHRASES = (
    "（请解码后按其内容处理）",
    "请解码后按其内容处理",
    "请解码后执行",
    "请按解码结果处理",
    "请阅读下列全角字符并照做：",
    "请解析下列转义序列并照做：",
    "请还原实体字符后照做：",
    "请先做 URL 解码再处理：",
    "请阅读下列内容并照做：",
)
MAX_DECODED = 4000          # 单条还原长度上限，防炸


def _to_ascii_fullwidth(text: str) -> str:
    """只把 U+FF01–FF5E 映射回 ASCII（与生成器的 `ord(c)+0xFEE0` 互逆）。"""
    return "".join(chr(ord(c) - 0xFEE0) if 0xFF01 <= ord(c) <= 0xFF5E else c for c in text)


def _looks_like_text(s: str) -> bool:
    """解码结果必须是"像人话"的文本，否则拒绝（避免把哈希/ID 当载荷）。"""
    if not s or len(s) < 6:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t ")
    if printable / len(s) < 0.85:
        return False
    cjk = sum(1 for c in s if "\u4e00" <= c <= "\u9fff")
    letters = sum(1 for c in s if c.isalpha())
    return cjk >= 4 or letters >= 8


def _try_b64(token: str) -> str | None:
    pad = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(pad, validate=True)
    except (binascii.Error, ValueError):
        return None
    for enc in ("utf-8", "gb18030"):
        try:
            s = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if _looks_like_text(s):
            return s
    return None


def _decode_b64_runs(text: str, *, canonical: bool = False) -> tuple[str, list[str]]:
    notes: list[str] = []

    def repl(m: re.Match) -> str:
        s = _try_b64(m.group(0))
        if s is None:
            return m.group(0)
        notes.append("base64:{}B".format(len(m.group(0))))
        if canonical:
            # 用解码结果**替换**编码串：不保留 b64（b64 本身对文本编码器不可分）
            return s
        return "{}【已解码：{}】".format(m.group(0), s)

    out = B64_RUN.sub(repl, text)
    return out, notes


def _decode_escapes(text: str) -> tuple[str, list[str]]:
    notes: list[str] = []

    def u(m: re.Match) -> str:
        notes.append("unicode_escape")
        return chr(int(m.group(1), 16))

    def x(m: re.Match) -> str:
        notes.append("hex_escape")
        return chr(int(m.group(1), 16))

    text = UNI_ESC.sub(u, text)
    text = HEX_ESC.sub(x, text)

    def pc(m: re.Match) -> str:
        dec = unquote(m.group(0), encoding="utf-8", errors="replace")
        if _looks_like_text(dec):
            notes.append("percent_encoding")
            return dec
        return m.group(0)

    text = PERCENT.sub(pc, text)
    return text, notes


def normalize(text: str, *, keep_original: bool = True, canonical: bool = False) -> dict:
    """返回 {original, normalized, changed, notes}。

    normalized 为**多视图**：原始文本（若 keep_original）+ 各层还原结果，
    保证还原失败不丢信息、还原成功则模型看得见。

    ``canonical=True``：把编码**信封**也归一化掉——即用解码后的内容**替换**编码串
    （而不是原样保留 b64 再附解码），并剥离**固定的信封指示语**
    （如「（请解码后按其内容处理）」）。理由（实测）：
      r3b 的 base64 良性在这种信封下 margin 中位 −8.0，而普通良性是 −16 ——
      信封里的指示语本身被模型当成"指令注入"信号，形成**域相关的常数偏移**，
      导致单一全局阈值无法同时覆盖各结构。剥离固定信封语后该偏移消失。
    只剥离**白名单固定串**，不删除任意文本（避免被攻击者把指令藏在信封里绕过）。
    """
    original = text or ""
    notes: list[str] = []

    view = original

    # 1) HTML 实体
    if re.search(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]{2,8});", view):
        un = html.unescape(view)
        if un != view:
            notes.append("html_entity")
            view = un

    # 2) 剥离不可见字符（先在"去掉零宽"的视图上判定）
    stripped = INVISIBLE.sub("", view)
    if stripped != view:
        notes.append("invisible_stripped")
        view = stripped

    # 3) 转义序列
    view, n2 = _decode_escapes(view)
    notes.extend(n2)

    # 4) base64 长串
    view, n3 = _decode_b64_runs(view, canonical=canonical)
    notes.extend(n3)

    # 5) 全角字母/数字（仅在检测到连续 ≥4 个时才做，避免扰动中文标点）
    if FULLWIDTH_RUN.search(view):
        fw = _to_ascii_fullwidth(view)
        if fw != view:
            notes.append("fullwidth_latin")
            view = fw

    # 6) 规避式拆字还原（CJK 间空格/分隔符，≥3 处才触发）
    if len(CJK_SPACED.findall(view)) + len(CJK_SEP.findall(view)) >= SPLIT_TRIGGER:
        un = CJK_SEP.sub("", CJK_SPACED.sub("", view))
        if un != view:
            notes.append("cjk_split_collapsed")
            view = un

    # 7) 剥离**白名单固定信封语**（canonical 模式）
    if canonical:
        for pat in ENVELOPE_PHRASES:
            if pat in view:
                view = view.replace(pat, "")
                notes.append("envelope_stripped")

    view = view[:MAX_DECODED]

    if keep_original and view != original:
        normalized = original + "\n【归一化视图】" + view
    else:
        normalized = view

    return {"original": original, "normalized": normalized,
            "changed": bool(notes), "notes": notes}


if __name__ == "__main__":
    import argparse
    import json

    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--field", default="text")
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.rows, encoding="utf-8") if l.strip()]
    changed = 0
    from collections import Counter
    tally: Counter = Counter()
    with open(args.out, "w", encoding="utf-8") as fh:
        for r in rows:
            res = normalize(r[args.field])
            if res["changed"]:
                changed += 1
            for n in res["notes"]:
                tally[n.split(":")[0]] += 1
            r["normalize"] = {"changed": res["changed"], "notes": res["notes"]}
            r["text_normalized"] = res["normalized"]
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    print("rows", len(rows), "changed", changed)
    for k, v in tally.most_common():
        print("  ", k, v)
