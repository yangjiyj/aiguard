from pathlib import Path


def test_tokenizer_loading_is_forced_to_local_files_only():
    source = (Path(__file__).resolve().parents[1] / "app" / "model.py").read_text(encoding="utf-8")

    assert "AutoTokenizer.from_pretrained(model_dir, local_files_only=True)" in source
