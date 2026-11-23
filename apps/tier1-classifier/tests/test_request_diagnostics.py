import asyncio
import json
import threading
import pytest
import app.main as main
from app.bounded_work import BoundedWorkPool
from starlette.requests import Request

def test_server_honors_smaller_authenticated_caller_budget(monkeypatch):
    monkeypatch.setenv("TIER1_INFERENCE_TIMEOUT_SECONDS","1")
    request=Request({"type":"http","headers":[(b"x-jjdguard-inference-budget-ms",b"20")]})
    assert main._request_budget_seconds(request)==pytest.approx(.02)
    request=Request({"type":"http","headers":[(b"x-jjdguard-inference-budget-ms",b"20000")]})
    assert main._request_budget_seconds(request)==1

def test_queue_timeout_is_distinct_and_does_not_execute_queued_text(monkeypatch):
    entered=threading.Event();release=threading.Event();calls=[]
    class Scorer:
        def score(self,text):
            calls.append(text)
            entered.set()
            assert release.wait(2)
            return .1,"benign"
    monkeypatch.setattr(main.classifier,"get_scorer",lambda:Scorer())
    monkeypatch.setattr(main,"_INFERENCE_POOL",BoundedWorkPool("diagnostic-test",1,2))
    monkeypatch.setenv("TIER1_INFERENCE_TIMEOUT_SECONDS","1")
    async def run():
        first=asyncio.create_task(main.classify(main.ClassifyRequest(text="first")))
        assert await asyncio.to_thread(entered.wait,1)
        req=Request({"type":"http","headers":[(b"x-jjdguard-inference-budget-ms",b"20")]})
        try:
            result=await main.classify(main.ClassifyRequest(text="queued"),req)
            body=json.loads(result.body)
            assert result.status_code==503
            assert body["error"]["code"]=="inference_queue_timeout"
            assert body["coverage_complete"] is False
            assert body["timing"]["inference_started"] is False
            assert calls==["first"]
        finally:release.set()
        assert (await first)["coverage_complete"] is True
    asyncio.run(run())

def test_diagnostics_accounts_for_failure_separately_from_success(monkeypatch):
    monkeypatch.setattr(main.classifier,"get_scorer",lambda:None)
    result=asyncio.run(main.classify(main.ClassifyRequest(text="private text")))
    assert result.status_code==503
    stats=asyncio.run(main.diagnostics())
    assert stats["requests"]["failed"]["model_not_loaded"]>=1
    assert "private text" not in json.dumps(stats)

@pytest.mark.parametrize("raw", [b"0",b"-1",b"abc"])
def test_invalid_deadline_does_not_invoke_model(monkeypatch,raw):
    class Scorer:
        def score(self,text):raise AssertionError("invalid request reached inference")
    monkeypatch.setattr(main.classifier,"get_scorer",lambda:Scorer())
    request=Request({"type":"http","headers":[(b"x-jjdguard-inference-budget-ms",raw)]})
    result=asyncio.run(main.classify(main.ClassifyRequest(text="private"),request))
    assert result.status_code==422
    assert json.loads(result.body)["coverage_complete"] is False

def test_diagnostics_endpoint_requires_internal_auth(monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv("JJD_TIER1_INTERNAL_TOKEN","fixture-only")
    client=TestClient(main.app)
    assert client.get("/diagnostics").status_code==401
    response=client.get("/diagnostics",headers={"X-JJDGuard-Internal-Token":"fixture-only"})
    assert response.status_code==200
    assert "pool" in response.json()

def test_invalid_model_score_is_not_counted_as_completed(monkeypatch):
    class Scorer:
        def score(self,text):return float("nan"),"benign"
    monkeypatch.setattr(main.classifier,"get_scorer",lambda:Scorer())
    before=main.request_diagnostics.snapshot()["completed"]
    result=asyncio.run(main.classify(main.ClassifyRequest(text="normal")))
    assert result.status_code==503
    assert main.request_diagnostics.snapshot()["completed"]==before
