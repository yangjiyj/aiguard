from pathlib import Path

_README = Path(__file__).resolve().parents[1] / "README.md"


def test_readme_documents_pipeline_contract():
    txt = _README.read_text(encoding="utf-8")
    for token in [
        "requirements-train.txt",
        "tier1_labels",
        "retrain",
        "id2label",
        "model.onnx",
        "slow",
    ]:
        assert token in txt, f"README 缺关键说明：{token}"
