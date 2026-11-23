"""Regression tests for bounded requests and per-item batch deadlines."""
import asyncio
import json
import threading
import time
import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from app.api import check_input as api


def response(req):
    return api.CheckInputResponse(request_id=req.request_id, findings=[], action="allow",
                                  latency_ms=1, semantic_status="completed")


def decode(value):
    if isinstance(value, JSONResponse):
        return value.status_code, json.loads(value.body)
    return 200, [v.model_dump() for v in value]


def test_single_request_does_not_block_event_loop(monkeypatch):
    def slow(req):
        time.sleep(0.25)
        return response(req)
    monkeypatch.setattr(api, "_run_check", slow)
    async def run():
        task = asyncio.create_task(api.check_input(api.CheckInputRequest(request_id="slow", content="x")))
        await asyncio.sleep(0.02)
        assert not task.done(), "the event loop must run while the synchronous detector is busy"
        await task
    asyncio.run(run())


def test_batch_timeout_preserves_completed_results_and_sources(monkeypatch):
    seen=[]
    def check(req):
        seen.append((req.request_id, req.content, req.content_source))
        if req.request_id == "slow":
            time.sleep(0.15)
        return response(req)
    monkeypatch.setattr(api, "_run_check", check)
    monkeypatch.setenv("SECURITY_BATCH_BUDGET_SECONDS", "0.03")
    reqs=[api.CheckInputRequest(request_id="done", content="platform", content_source="system_prompt"),
          api.CheckInputRequest(request_id="slow", content="untrusted", content_source="user")]
    status, out = decode(asyncio.run(api.check_input_batch(reqs)))
    assert status == 207, "partial inspection must not masquerade as an HTTP 200 complete batch"
    assert out[0]["request_id"] == "done"
    assert out[0]["inspection_status"] == "completed"
    assert out[1]["request_id"] == "slow"
    assert out[1]["inspection_status"] == "incomplete"
    assert out[1]["inspection_reason"] == "batch_timeout"
    assert out[1]["findings"] == [] and out[1]["file_bindings"] == []
    # Worker start order is concurrent; response order above remains contractual.
    assert sorted(seen) == [("done", "platform", "system_prompt"), ("slow", "untrusted", "user")]


def test_single_timeout_is_transport_failure_not_allow(monkeypatch):
    monkeypatch.setenv("SECURITY_INPUT_BUDGET_SECONDS", "0.02")
    def slow(req):
        time.sleep(0.15)
        return response(req)
    monkeypatch.setattr(api, "_run_check", slow)
    async def run():
        with pytest.raises(HTTPException) as caught:
            await api.check_input(api.CheckInputRequest(request_id="r", content="x"))
        assert caught.value.status_code == 503
        assert caught.value.detail["inspection_status"] == "incomplete"
        assert caught.value.detail["code"] == "input_timeout"
    asyncio.run(run())


def test_request_failure_is_sanitized(monkeypatch):
    def broken(req):
        raise RuntimeError("PRIVATE-PAYLOAD-SHOULD-NOT-ESCAPE")
    monkeypatch.setattr(api, "_run_check", broken)
    async def run():
        with pytest.raises(HTTPException) as caught:
            await api.check_input(api.CheckInputRequest(request_id="r", content="x"))
        assert caught.value.status_code == 503
        assert "PRIVATE-PAYLOAD" not in str(caught.value.detail)
    asyncio.run(run())

def test_output_detector_does_not_block_event_loop(monkeypatch):
    from app.api import check_output as output_api
    from app.detectors.engine import SecurityCheckResult
    def slow(**kwargs):
        time.sleep(.25)
        return SecurityCheckResult(request_id=kwargs["request_id"], findings=[], action="allow")
    monkeypatch.setattr(output_api.engine, "check_output", slow)
    async def run():
        task=asyncio.create_task(output_api.check_output(output_api.CheckOutputRequest(request_id="o", content="x")))
        await asyncio.sleep(.02)
        assert not task.done()
        await task
    asyncio.run(run())


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0", "-1", "invalid"])
def test_batch_budget_rejects_nonfinite_or_invalid_values(monkeypatch, value):
    monkeypatch.setenv("SECURITY_BATCH_BUDGET_SECONDS", value)
    assert api._batch_budget_seconds() == 18.0
