"""A capacity degradation must not rewrite unrelated verdicts; the cascade warning
must see the value the detector actually uses.

Both were found by running the branch, not by its own tests:

* ``check_input`` promoted every recent degradation (process-global, 30 s window)
  into ``inspection_status=incomplete``, so one breaker blip made every request
  incomplete. docs/deployment-capacity.md promises "keep going on the local
  breaker, audited, no amplified false positives".
* ``cascade_warnings`` read ``os.environ`` while the control plane pushes the
  threshold through the feature-flag overrides, so the 0.0 that disabled the
  cascade in production produced no warning.
"""
from app import feature_flags as ff
from app import runtime_profile as rp
from app import shared_state as ss
from app.api import check_input as ci


def setup_function(_):
    ss.AUDIT.clear()


def teardown_function(_):
    ss.AUDIT.clear()
    ff.apply_overrides({})


def _check(**kwargs):
    return ci._run_check(ci.CheckInputRequest(request_id="t", content="hello world", **kwargs))


def test_capacity_degradation_is_reported_but_keeps_the_inspection_complete():
    ss.record_degradation("circuit_breaker", "is_open", "breaker_shared_state_unavailable",
                          impact="capacity")
    for kwargs in ({}, {"skip_semantic": True}):
        response = _check(**kwargs)
        assert response.inspection_status == "completed"
        assert response.inspection_reason == ""
        assert response.degradation_reasons == ["breaker_shared_state_unavailable"]


def test_detection_degradation_still_marks_the_inspection_incomplete():
    ss.record_degradation("tool_pin", "check", "tool_pin_shared_state_unavailable",
                          impact="detection")
    response = _check()
    assert response.inspection_status == "incomplete"
    assert "tool_pin_shared_state_unavailable" in response.inspection_reason
    assert response.degradation_reasons == ["tool_pin_shared_state_unavailable"]


def test_cascade_warning_sees_a_threshold_pushed_through_the_overrides(monkeypatch):
    monkeypatch.delenv("SECURITY_TIER1_LOW_THRESHOLD", raising=False)
    monkeypatch.delenv("SECURITY_SEMANTIC_CASCADE_POLICY", raising=False)
    assert rp.cascade_warnings() == []
    ff.apply_overrides({"SECURITY_TIER1_LOW_THRESHOLD": "0.0"})
    warnings = rp.cascade_warnings()
    assert any(w.startswith("tier1_cascade_disabled") for w in warnings)
    assert any(w.startswith("tier1_cascade_guard_off") for w in warnings)
    ff.apply_overrides({"SECURITY_TIER1_LOW_THRESHOLD": "0.0",
                        "SECURITY_SEMANTIC_CASCADE_POLICY": "coverage_v2"})
    warnings = rp.cascade_warnings()
    assert any(w.startswith("tier1_cascade_disabled") for w in warnings)
    assert not any(w.startswith("tier1_cascade_guard_off") for w in warnings)
