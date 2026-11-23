import pytest

from app.model import ModelScorer, _select_execution_providers


def test_provider_defaults_to_cpu(monkeypatch):
    monkeypatch.delenv("TIER1_EXECUTION_PROVIDER", raising=False)
    mode, providers = _select_execution_providers(
        ["CUDAExecutionProvider", "CPUExecutionProvider"]
    )
    assert mode == "cpu"
    assert providers == ["CPUExecutionProvider"]


def test_auto_prefers_cuda_and_keeps_cpu_fallback(monkeypatch):
    monkeypatch.setenv("TIER1_EXECUTION_PROVIDER", "auto")
    mode, providers = _select_execution_providers(
        ["CPUExecutionProvider", "CUDAExecutionProvider"]
    )
    assert mode == "cuda"
    assert providers == ["CUDAExecutionProvider", "CPUExecutionProvider"]


def test_auto_uses_cpu_without_gpu_runtime(monkeypatch):
    monkeypatch.setenv("TIER1_EXECUTION_PROVIDER", "auto")
    assert _select_execution_providers(["CPUExecutionProvider"]) == (
        "cpu",
        ["CPUExecutionProvider"],
    )


def test_explicit_cuda_fails_when_provider_is_missing(monkeypatch):
    monkeypatch.setenv("TIER1_EXECUTION_PROVIDER", "cuda")
    with pytest.raises(RuntimeError, match="CUDAExecutionProvider"):
        _select_execution_providers(["CPUExecutionProvider"])


def test_unknown_provider_mode_is_rejected(monkeypatch):
    monkeypatch.setenv("TIER1_EXECUTION_PROVIDER", "magic")
    with pytest.raises(ValueError, match="TIER1_EXECUTION_PROVIDER"):
        _select_execution_providers(["CPUExecutionProvider"])


class _RuntimeSession:
    def get_providers(self):
        return ["CUDAExecutionProvider", "CPUExecutionProvider"]


def test_model_runtime_info_is_observable():
    scorer = ModelScorer(
        _RuntimeSession(), lambda *_args, **_kwargs: {}, {0: "benign", 1: "attack"},
        configured_provider="cuda", threads=1,
    )
    assert scorer.runtime_info() == {
        "configured_provider": "cuda",
        "execution_provider": "cuda",
        "onnx_provider": "CUDAExecutionProvider",
        "threads": 1,
        # C4: the batch knob is part of the observable runtime contract.
        "batch_windows": scorer._max_token_windows,
    }
