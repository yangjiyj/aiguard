from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]  # apps/tier1-classifier


def _names(text):
    out = set()
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        name = ln.split("==")[0].split(">=")[0].split("[")[0].strip().lower()
        out.add(name)
    return out


def test_requirements_train_has_training_stack():
    names = _names((_ROOT / "requirements-train.txt").read_text(encoding="utf-8"))
    for pkg in ("scikit-learn", "skl2onnx", "onnx", "onnxruntime",
                "optimum", "transformers", "torch", "numpy"):
        assert pkg in names, f"requirements-train.txt 缺训练依赖 {pkg}"


def test_runtime_requirements_excludes_heavy_train_deps():
    names = _names((_ROOT / "requirements.txt").read_text(encoding="utf-8"))
    for heavy in ("torch", "scikit-learn", "skl2onnx", "optimum"):
        assert heavy not in names, f"sidecar 运行时 requirements.txt 不应含训练重依赖 {heavy}"
