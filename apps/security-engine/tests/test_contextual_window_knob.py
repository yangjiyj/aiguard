"""SECURITY_SEMANTIC_WINDOW_CHARS applies to tool / RAG / web content too.

``_contextual_window_end`` hard-coded ``start + 1200``, a 1600-char excerpt and a
2048-byte transport budget, so for indirect content the knob was a no-op while
the direct-text path honoured it.
"""
from app.detectors.semantic import SemanticDetector

_TASK = {"user_task": "summarize the tool output", "user_task_status": "complete"}
_BODY = "alpha beta gamma delta. " * 400          # ~9600 ASCII chars


def _end(monkeypatch, window=None):
    if window is None:
        monkeypatch.delenv("SECURITY_SEMANTIC_WINDOW_CHARS", raising=False)
    else:
        monkeypatch.setenv("SECURITY_SEMANTIC_WINDOW_CHARS", str(window))
    return SemanticDetector._contextual_window_end(_BODY, 0, "tool_result", _TASK)


def test_default_window_for_indirect_content_is_unchanged(monkeypatch):
    end = _end(monkeypatch)
    assert 0 < end <= 1200


def test_a_larger_window_applies_to_indirect_content(monkeypatch):
    default_end = _end(monkeypatch)
    wide_end = _end(monkeypatch, 3000)
    assert wide_end > default_end
    assert wide_end <= 3000


def test_a_smaller_window_applies_to_indirect_content(monkeypatch):
    assert _end(monkeypatch, 400) <= 400
