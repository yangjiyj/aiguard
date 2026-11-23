"""Advisory review failures must not erase a completed scan or its action."""
import json
from types import SimpleNamespace
import anyio
import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse
import app.api.check_input as api
from app.detectors.engine import SecurityEngine, SecurityFinding, SecurityCheckResult


def run(coro):
    return anyio.run(lambda: coro)


def finding(action="audit", mode=None, category="semantic_instruction_override"):
    triage={"review_status":"incomplete", "review_reason":"triage_total_budget_exhausted"}
    if mode is not None:
        triage["review_mode"]=mode
    return SecurityFinding(type="semantic_attack", category=category, severity="high",
        rule_id="semantic-test", matched_text_preview="untrusted instruction", action=action,
        triage=triage)


def result(request_id, hit):
    return SecurityCheckResult(request_id=request_id, findings=[hit], action=hit.action,
        raw_findings=[hit.model_copy(deep=True)], semantic_status="completed")


@pytest.mark.parametrize("candidate", [False, True])
def test_budget_expiry_records_server_selected_review_mode(monkeypatch, candidate):
    engine=SecurityEngine()
    monkeypatch.setattr(engine,"_is_contextual_candidate",lambda f:candidate)
    runtime=SimpleNamespace(fp_suppression_enabled=candidate,semantic_master_enabled=True,
        llm_judge_mode="shadow",triage_total_budget=0)
    hit=finding(mode="shadow" if candidate else "contextual_candidate")
    out=engine._apply_finding_triage("evidence",[hit],"input",runtime)
    assert out[0].triage["review_mode"] == ("contextual_candidate" if candidate else "shadow")
    assert out[0].triage["review_status"] == "incomplete"
    assert out[0].triage["review_reason"] == "triage_total_budget_exhausted"
    assert out[0].action == "audit"
    assert out[0].counts_as_security_finding is not False


@pytest.mark.parametrize("action", ["block", "audit"])
def test_shadow_timeout_returns_completed_detection_without_losing_action(monkeypatch, action):
    hit=finding(action, "shadow")
    monkeypatch.setattr(api.engine,"check_input",lambda **kw:result(kw["request_id"],hit))
    response=run(api.check_input(api.CheckInputRequest(request_id="shadow",content="fixture")))
    assert response.inspection_status == "completed"
    assert response.semantic_status == "completed"
    assert response.action == action
    assert response.findings[0].model_dump() == hit.model_dump()
    assert response.findings[0].triage["review_status"] == "incomplete"
    assert response.raw_findings[0].action == action


@pytest.mark.parametrize("mode,category", [(None,"semantic_instruction_override"),
    ("contextual_candidate","semantic_instruction_override"),
    ("shadow","engine_scan_incomplete")])
def test_required_or_unknown_review_and_scan_failure_still_return_503(monkeypatch, mode, category):
    hit=finding("audit",mode,category)
    monkeypatch.setattr(api.engine,"check_input",lambda **kw:result(kw["request_id"],hit))
    with pytest.raises(HTTPException) as exc:
        run(api.check_input(api.CheckInputRequest(request_id="required",content="fixture")))
    assert exc.value.status_code == 503
    assert exc.value.detail["inspection_status"] == "incomplete"


def test_batch_preserves_shadow_action_but_reports_true_incomplete_item(monkeypatch):
    def check(**kw):
        hit=finding("block","shadow", "engine_scan_incomplete" if kw["request_id"]=="scan-failed" else "semantic_instruction_override")
        return result(kw["request_id"],hit)
    monkeypatch.setattr(api.engine,"check_input",check)
    response=run(api.check_input_batch([api.CheckInputRequest(request_id=x,content="fixture") for x in ["shadow","scan-failed"]]))
    assert isinstance(response,JSONResponse) and response.status_code==207
    rows=json.loads(response.body)
    assert rows[0]["inspection_status"]=="completed"
    assert rows[0]["action"]=="block"
    assert rows[0]["findings"][0]["triage"]["review_status"]=="incomplete"
    assert rows[1]["inspection_status"]=="incomplete"
