import random
import time
from typing import List, Tuple

from app.detectors import hit_display
from app.detectors.hit_display import _WHITESPACE, _url_password_spans, render_hit_display


def _reference_spans(text: str) -> List[Tuple[int, int]]:
    """改前的实现（每个 :// 都从头扫到底），作为等价性对照。"""
    spans: List[Tuple[int, int]] = []
    at = text.find("://")
    while at >= 0:
        start = at + 3
        stop = _WHITESPACE.search(text, start)
        end = stop.start() if stop else len(text)
        last_at = text.rfind("@", start, end)
        colon = text.find(":", start, last_at) if last_at >= 0 else -1
        if at > 0 and colon >= 0 and last_at > colon + 1:
            spans.append((colon + 1, last_at))
        at = text.find("://", start)
    return spans


SMALL = [
    "postgres://app:S3cret@db.example.internal/app",
    "://a:b@c ://d:e@f",
    "x://u:p@h://v:q@w y://k:z@m",
    "http://a/b@c://d:e@f",
    "a://b://c://d:e@f@g",
    "no urls here @ : //",
    "ftp://user:pa:ss@word@host/path ssh://x:y@z",
    "://:@",
    "a://@:b",
]


def test_spans_match_the_quadratic_reference_on_small_and_random_inputs():
    for text in SMALL:
        assert _url_password_spans(text) == _reference_spans(text), text
    rng = random.Random(7)
    alphabet = ["://", ":", "@", "a", "b", " ", "/", "x", "\n"]
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 30)))
        assert _url_password_spans(text) == _reference_spans(text), text


def test_long_text_with_many_url_markers_renders_in_linear_time():
    text = "a://u:p@" * 37500  # 30 万字，没有空白
    assert len(text) == 300000
    for kind in ("auto", "plain"):
        started = time.perf_counter()
        shown = render_hit_display(kind, text).text
        elapsed = time.perf_counter() - started
        assert elapsed < 2.0, (kind, elapsed)
        assert shown
