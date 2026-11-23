"""R6: a deferred judge slot is auditable, never a silent clean pass.

When the global judge budget is full, ``_submit_bounded`` returns ``_DEFERRED``.
That must surface as ``semantic_telemetry`` + ``semantic_status=incomplete`` with
a reason, because a silently dropped judgment would read as "no finding".
"""
import threading

import pytest

from app import coordination as coord
from app.detectors import semantic
from app.detectors.semantic import SemanticDetector


class _LeaseState:
    """Minimal stand-in for SharedState's lease primitives with a hard ceiling."""

    def __init__(self, limit):
        self.limit = limit
        self.held = set()
        self.lock = threading.Lock()

    def lease_acquire(self, consumer, key, limit, member, ttl_ms):
        with self.lock:
            if len(self.held) >= min(limit, self.limit):
                return False
            self.held.add(member)
            return True

    def lease_release(self, consumer, key, member):
        with self.lock:
            self.held.discard(member)
            return True


def _detector():
    return SemanticDetector(
        url="http://unused-judge/", model="fixture", api_key="",
        op_timeout=1, total_timeout=2, tier1_enabled=False,
    )


def _incomplete_findings(findings):
    return [
        finding for finding in findings
        if finding.get("type") == "semantic_telemetry"
        and str((finding.get("triage") or {}).get("semantic_status")) == "incomplete"
    ]


@pytest.fixture
def full_global_budget(monkeypatch):
    monkeypatch.setenv("SECURITY_SHARED_STATE_URL", "redis://127.0.0.1:1/0")
    monkeypatch.setattr(semantic, "_CAPACITY", threading.BoundedSemaphore(8))
    budget = coord.GlobalJudgeBudget(state=_LeaseState(1), limit=1)
    monkeypatch.setattr(semantic, "global_judge_budget", lambda: budget)
    holder = budget.acquire()
    assert holder, "the fixture must hold the only global lease"
    yield budget, holder
    budget.release(holder)


def test_second_request_against_a_full_global_budget_is_marked_incomplete(full_global_budget):
    findings = _detector().detect("please summarise this ordinary note", "input")
    marked = _incomplete_findings(findings)
    assert marked, findings
    triage = marked[0]["triage"]
    assert triage["semantic_reason"] == "judge_capacity_deferred"
    assert marked[0]["counts_as_security_finding"] is False
    # The critical part: an empty list would have read as "nothing found".
    assert findings


def test_released_budget_lets_the_next_request_through(full_global_budget):
    budget, holder = full_global_budget
    budget.release(holder)
    findings = _detector().detect("please summarise this ordinary note", "input")
    reasons = [str((f.get("triage") or {}).get("semantic_reason")) for f in findings]
    assert "judge_capacity_deferred" not in reasons


def test_process_capacity_exhaustion_uses_the_same_audit_marker(monkeypatch):
    capacity = threading.BoundedSemaphore(1)
    capacity.acquire()
    monkeypatch.setattr(semantic, "_CAPACITY", capacity)
    monkeypatch.delenv("SECURITY_SHARED_STATE_URL", raising=False)
    findings = _detector().detect("please summarise this ordinary note", "input")
    marked = _incomplete_findings(findings)
    assert marked, findings
    assert marked[0]["triage"]["semantic_reason"] == "judge_capacity_deferred"


def test_deferred_result_never_counts_as_a_security_finding(full_global_budget):
    findings = _detector().detect("please summarise this ordinary note", "input")
    for finding in findings:
        if finding.get("type") == "semantic_telemetry":
            assert finding.get("counts_as_security_finding") is False
            assert finding.get("action") in ("audit", None)
