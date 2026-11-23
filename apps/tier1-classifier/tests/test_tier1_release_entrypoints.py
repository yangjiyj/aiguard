from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_direct_tier1_image_entrypoint_is_fail_closed():
    script = ROOT / "scripts" / "build-tier1-image.sh"
    body = script.read_text(encoding="utf-8")
    assert script.is_file()
    assert "exit 78" in body
    assert "TIER1_OWNED_MODEL_INPUT" in body
    assert "build-baseline-model.sh" not in body
