import numpy as np
import pytest
from app.model import ModelScorer


class Tokenizer:
    def __init__(self, windows):
        self.windows = windows
    def __call__(self, text, **kwargs):
        assert kwargs["return_overflowing_tokens"] is True
        assert kwargs["stride"] > 0
        return {"input_ids": np.ones((self.windows, 512), dtype=np.int64),
                "attention_mask": np.ones((self.windows, 512), dtype=np.int64)}


class Session:
    def get_inputs(self):
        return [type("Input", (), {"name": name}) for name in ("input_ids", "attention_mask")]
    def run(self, outputs, inputs):
        rows = len(inputs["input_ids"])
        probabilities = np.tile([.99, .01], (rows, 1))
        probabilities[-1] = [.03, .97]
        return [np.argmax(probabilities, axis=1), probabilities]


def test_last_token_window_contributes_to_score():
    model = ModelScorer(Session(), Tokenizer(3), {0: "benign", 1: "attack"})
    assert model.score("中文" * 600) == (.97, "attack")


def test_token_window_budget_fails_explicitly(monkeypatch):
    monkeypatch.setenv("TIER1_MAX_TOKEN_WINDOWS", "2")
    model = ModelScorer(Session(), Tokenizer(3), {0: "benign", 1: "attack"})
    with pytest.raises(ValueError, match="coverage"):
        model.score("中文" * 600)
