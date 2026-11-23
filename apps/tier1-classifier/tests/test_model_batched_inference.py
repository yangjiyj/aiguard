"""C4: long-text sliding windows must be batched, never run one by one."""
import numpy as np

from app.model import ModelScorer


class Tokenizer:
    def __init__(self, windows):
        self.windows = windows

    def __call__(self, text, **kwargs):
        return {
            "input_ids": np.ones((self.windows, 512), dtype=np.int64),
            "attention_mask": np.ones((self.windows, 512), dtype=np.int64),
        }


class RecordingSession:
    """Records the row count of every session.run so the test proves batching."""

    def __init__(self, probabilities):
        self.probabilities = np.asarray(probabilities, dtype=np.float64)
        self.calls = []

    def get_inputs(self):
        return [type("Input", (), {"name": n})
                for n in ("input_ids", "attention_mask")]

    def get_providers(self):
        return ["CPUExecutionProvider"]

    def run(self, _outputs, inputs):
        rows = len(inputs["input_ids"])
        start = sum(self.calls)
        self.calls.append(rows)
        batch = self.probabilities[start:start + rows]
        return [np.argmax(batch, axis=1), batch]


LABELS = {0: "benign", 1: "attack"}


def test_long_text_uses_one_batched_run_not_one_run_per_window():
    session = RecordingSession([[.99, .01]] * 15 + [[.03, .97]])
    model = ModelScorer(session, Tokenizer(16), LABELS)
    assert model.score("a" * 400) == (.97, "attack")
    assert session.calls == [16], (
        "16 windows must go through one session.run; a serial loop reintroduces "
        "the measured 1.6s cost for 4k characters"
    )


def test_batch_window_cap_splits_runs_but_preserves_maximum_score(monkeypatch):
    monkeypatch.setenv("TIER1_BATCH_WINDOWS", "5")
    session = RecordingSession([[.10, .90]] + [[.99, .01]] * 14 + [[.20, .80]])
    model = ModelScorer(session, Tokenizer(16), LABELS)
    assert model.score("x" * 100) == (.90, "attack")
    assert session.calls == [5, 5, 5, 1]


def test_batch_window_cap_is_clamped_to_the_window_budget(monkeypatch):
    monkeypatch.setenv("TIER1_BATCH_WINDOWS", "999")
    session = RecordingSession([[.5, .5]] * 3)
    model = ModelScorer(session, Tokenizer(3), LABELS)
    assert model._batch_windows() == model._max_token_windows
    model.score("y")
    assert session.calls == [3]


def test_invalid_batch_window_falls_back_to_a_single_run(monkeypatch):
    monkeypatch.setenv("TIER1_BATCH_WINDOWS", "many")
    session = RecordingSession([[.5, .5]] * 2)
    model = ModelScorer(session, Tokenizer(2), LABELS)
    model.score("y")
    assert session.calls == [2]


def test_runtime_info_reports_batch_windows():
    session = RecordingSession([[.5, .5]])
    model = ModelScorer(session, Tokenizer(1), LABELS)
    info = model.runtime_info()
    assert info["batch_windows"] == model._max_token_windows
    assert info["execution_provider"] == "cpu"
