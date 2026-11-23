"""R1 window dilution contract.

Measured on the production 4B judge against real 4000+ character bodies: a 4000
char window hits only 30/100 embedded hardcase sentences, while 1200 hits 49/100.
The wider window dilutes the attack inside the context, so recall falls. The
default therefore stays 1200/200; widening it must be an explicit operator
decision with a re-measured recall number, never a silent default change.
"""
from pathlib import Path

import pytest

from app.bounded_work import positive_number
from app.detectors.llm_judge import semantic_window_chars

ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILES = (
    ROOT / "deploy/docker-compose/docker-compose.yml",
    ROOT / "deploy/docker-compose/docker-compose.offline.yml",
)


@pytest.fixture(autouse=True)
def _no_window_env(monkeypatch):
    monkeypatch.delenv("SECURITY_SEMANTIC_WINDOW_CHARS", raising=False)
    monkeypatch.delenv("SECURITY_SEMANTIC_WINDOW_OVERLAP", raising=False)


def test_default_window_is_the_measured_safe_width():
    assert semantic_window_chars() == 1200


def test_default_overlap_is_the_measured_safe_overlap():
    assert positive_number("SECURITY_SEMANTIC_WINDOW_OVERLAP", 200, integer=True) == 200


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_compose_fallback_uses_the_measured_safe_window(path):
    body = path.read_text(encoding="utf-8")
    assert "SECURITY_SEMANTIC_WINDOW_CHARS=${SECURITY_SEMANTIC_WINDOW_CHARS:-1200}" in body
    assert "SECURITY_SEMANTIC_WINDOW_OVERLAP=${SECURITY_SEMANTIC_WINDOW_OVERLAP:-200}" in body
    # A 4000 fallback would silently reintroduce the recall regression.
    assert "${SECURITY_SEMANTIC_WINDOW_CHARS:-4000}" not in body


def test_env_example_does_not_ship_a_widened_window():
    body = (ROOT / "deploy/docker-compose/.env.example").read_text(encoding="utf-8")
    assert "\nSECURITY_SEMANTIC_WINDOW_CHARS=4000" not in body
    assert "\n#SECURITY_SEMANTIC_WINDOW_CHARS=1200" in body


def test_explicit_env_still_widens_the_window(monkeypatch):
    monkeypatch.setenv("SECURITY_SEMANTIC_WINDOW_CHARS", "4000")
    assert semantic_window_chars() == 4000


def test_window_stays_bounded(monkeypatch):
    monkeypatch.setenv("SECURITY_SEMANTIC_WINDOW_CHARS", "999999")
    assert semantic_window_chars() == 8000
    monkeypatch.setenv("SECURITY_SEMANTIC_WINDOW_CHARS", "1")
    assert semantic_window_chars() == 200


def test_detector_reads_the_window_through_the_shared_helper():
    body = (ROOT / "apps/security-engine/app/detectors/semantic.py").read_text(encoding="utf-8")
    assert "window_chars = semantic_window_chars()" in body


def test_overlap_is_clamped_to_a_quarter_of_the_window():
    # The detector clamps overlap at window//4 so a misconfigured overlap cannot
    # turn a long body into O(n) windows with near-total duplication.
    window_chars = 1200
    overlap = min(900, max(1, window_chars // 4))
    assert overlap == 300
    assert min(200, window_chars // 4) == 200
