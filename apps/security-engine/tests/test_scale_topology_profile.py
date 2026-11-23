"""The configured Tier-1 topology must be visible in /health.

tier1-scale.sh --apply persists TIER1_REPLICAS / TIER1_SCALE_MODE and every
upgrade path restores them. Without them in the profile, an install that was
scaled to 2 replicas and silently came back as 1 still reads "within_limit" from
the single-replica point of view and nothing on the console shows the loss.
"""
from __future__ import annotations

import pytest

from app.runtime_profile import resource_profile, runtime_snapshot


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    for key in ("TIER1_REPLICAS", "TIER1_SCALE_MODE"):
        monkeypatch.delenv(key, raising=False)
    yield


def test_reports_the_persisted_topology(monkeypatch):
    monkeypatch.setenv("TIER1_REPLICAS", "2")
    monkeypatch.setenv("TIER1_SCALE_MODE", "gpu")
    profile = resource_profile()
    assert profile["tier1_replicas"] == "2"
    assert profile["tier1_scale_mode"] == "gpu"


def test_defaults_describe_an_unscaled_install():
    profile = resource_profile()
    assert profile["tier1_replicas"] == "1"
    # Empty in .env means base compose with no overlay; the profile says so
    # explicitly instead of returning a blank field the console cannot render.
    assert profile["tier1_scale_mode"] == "single"


def test_blank_values_fall_back_to_the_unscaled_default(monkeypatch):
    monkeypatch.setenv("TIER1_REPLICAS", "  ")
    monkeypatch.setenv("TIER1_SCALE_MODE", "")
    profile = resource_profile()
    assert profile["tier1_replicas"] == "1"
    assert profile["tier1_scale_mode"] == "single"


def test_snapshot_carries_the_topology(monkeypatch):
    monkeypatch.setenv("TIER1_REPLICAS", "4")
    monkeypatch.setenv("TIER1_SCALE_MODE", "cpu")
    snapshot = runtime_snapshot()
    assert snapshot["resource_profile"]["tier1_replicas"] == "4"
    assert snapshot["resource_profile"]["tier1_scale_mode"] == "cpu"
