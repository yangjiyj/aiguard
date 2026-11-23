"""The build-time file selftest must agree with the runtime attachment contract."""
from pathlib import Path

from app import feature_flags as ff
from app.file_selftest import run

ROOT = Path(__file__).parent / "fixtures/file_detection"


def test_build_selftest_matches_attachment_action_contract(monkeypatch):
    # build_vm_development.py runs this selftest inside every candidate SE image;
    # keeping it in pytest stops it drifting from the engine's action contract.
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    result = run(ROOT)
    assert result["passed"], result
    assert len(result["cases"]) == 12
    assert all(case["coverage_complete"] for case in result["cases"])
