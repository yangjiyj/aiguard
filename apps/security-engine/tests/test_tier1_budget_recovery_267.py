"""Controlled Tier1 budget/queue experiments; no real model or production traffic."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time

import pytest
from app.bounded_work import execution_budget
from app.detectors import semantic
from app.detectors import tier1_client
from app.detectors.semantic import SemanticDetector
from app.detectors.tier1_client import Tier1Client

@pytest.fixture(autouse=True)
def reset_breaker():
    tier1_client._reset_breakers()
    yield
    tier1_client._reset_breakers()

@contextmanager
def upstream(monkeypatch, delay=.08, status=200):
    state={"delay":delay,"status":status,"requests":0,"score_ms":[]}
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length","0")))
            state["requests"]+=1
            started=time.monotonic()
            time.sleep(state["delay"])
            state["score_ms"].append((time.monotonic()-started)*1000)
            body=json.dumps({"score":.01,"label":"benign","coverage_complete":True}).encode()
            try:
                self.send_response(state["status"])
                self.send_header("Content-Length",str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError,ConnectionResetError):
                pass
        def log_message(self,*args):
            pass
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    server.daemon_threads=True
    thread=threading.Thread(target=server.serve_forever,kwargs={"poll_interval":.01},daemon=True)
    thread.start()
    url="http://127.0.0.1:"+str(server.server_port)+"/classify"
    # Injection is restricted to this test process; production URL validation
    # remains exact bundled URL only.
    monkeypatch.setattr(tier1_client,"_validated_url",lambda _:url)
    state["url"]=url
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

def detector(client,total=.5):
    return SemanticDetector(url="http://unused-judge/",model="fixture",api_key="",
                            op_timeout=1,total_timeout=total,tier1_enabled=True,
                            tier1_client=client,tier1_low_threshold=.3,tier1_high_threshold=.7)

def reason(findings):
    return [f.get("triage",{}).get("semantic_reason") for f in findings]

def test_short_request_budget_does_not_poison_healthy_tier1_breaker(monkeypatch):
    with upstream(monkeypatch,delay=.08) as state:
        client=Tier1Client(url=tier1_client.BUNDLED_TIER1_URL,token="synthetic",timeout=.5)
        for _ in range(5):
            assert client.classify("ordinary text",timeout=.015) is None
        breaker=tier1_client._breaker_for(state["url"])
        assert breaker.allow(), "local shortened deadline must not mark healthy upstream down"
        assert client.classify("ordinary text",timeout=.5)==(.01,"benign")
        assert breaker.fails==0

def test_full_tier1_timeout_still_opens_breaker_and_recovers(monkeypatch):
    with upstream(monkeypatch,delay=.08) as state:
        client=Tier1Client(url=tier1_client.BUNDLED_TIER1_URL,token="synthetic",timeout=.015)
        for _ in range(5):
            assert client.classify("ordinary text") is None
        breaker=tier1_client._breaker_for(state["url"])
        assert not breaker.allow()
        assert client.classify("ordinary text") is None
        state["delay"]=0
        breaker.clock=lambda:breaker.open_until+1
        assert client.classify("ordinary text")==(.01,"benign")
        assert breaker.fails==0

def test_short_budget_immediate_service_failure_still_counts(monkeypatch):
    # A prompt, explicit service failure is upstream health evidence even when
    # this request has a smaller budget than the normal per-operation limit.
    with upstream(monkeypatch,delay=0,status=503) as state:
        client=Tier1Client(url=tier1_client.BUNDLED_TIER1_URL,token="synthetic",timeout=1)
        for _ in range(5):
            assert client.classify("ordinary text",timeout=.5) is None
        assert not tier1_client._breaker_for(state["url"]).allow()

def test_client_queue_timeout_can_happen_without_any_model_call(monkeypatch):
    with upstream(monkeypatch,delay=0) as state, ThreadPoolExecutor(max_workers=1) as pool:
        blocked=threading.Event()
        entered=threading.Event()
        def hold():
            entered.set()
            blocked.wait(2)
        held=pool.submit(hold)
        assert entered.wait(1)
        monkeypatch.setattr(semantic,"_TIER1_EXECUTOR",pool)
        monkeypatch.setattr(semantic,"_TIER1_CAPACITY",threading.BoundedSemaphore(2))
        client=Tier1Client(url=tier1_client.BUNDLED_TIER1_URL,token="synthetic",timeout=.5)
        try:
            findings=detector(client,total=.025).detect("ordinary text","input")
            assert "tier1_timeout" in reason(findings)
            assert state["requests"]==0
            triage=findings[0]["triage"]
            assert triage["tier1_client_call_started"] is False
            assert triage["tier1_client_queue_ms"]>0
            assert triage["tier1_client_call_elapsed_ms"]==0
        finally:
            blocked.set()
            held.result(timeout=1)
        assert detector(client).detect("ordinary text","input")==[]
        assert state["requests"]==1

def test_short_parent_budget_overrides_semantic_total(monkeypatch):
    with upstream(monkeypatch,delay=.10) as state:
        client=Tier1Client(url=tier1_client.BUNDLED_TIER1_URL,token="synthetic",timeout=.5)
        with execution_budget(time.monotonic()+.025):
            findings=detector(client,total=1).detect("ordinary text","input")
        assert any(value in {"tier1_timeout","tier1_unavailable"} for value in reason(findings))
        assert not any(f["counts_as_security_finding"] for f in findings)
        triage=findings[0]["triage"]
        assert 0 < triage["tier1_budget_ms"] < 100
        assert triage["tier1_client_call_started"] is True
        # Enough budget later can recover without changing the model/config.
        assert detector(client).detect("ordinary text","input")==[]

def test_individually_fast_windows_can_exhaust_one_total_budget(monkeypatch):
    from app.detectors.llm_judge import SemanticOpinion
    def slow_judge(*args, **kwargs):
        time.sleep(.025)
        return SemanticOpinion("benign", "none", .9, "normal")
    monkeypatch.setattr(semantic, "judge_semantic", slow_judge)
    with upstream(monkeypatch,delay=.025) as state:
        client=Tier1Client(url=tier1_client.BUNDLED_TIER1_URL,token="synthetic",timeout=.5)
        # Distinct windows exercise inference deadlines rather than history reuse.
        text = "".join(str(i)*1000 for i in range(9))
        findings=detector(client,total=.06).detect(text,"input")
        assert any(value in {"judge_timeout", "window_timeout"} for value in reason(findings))
        assert state["requests"] == 0, "multi-window input bypasses Tier-1 skips"
        telemetry=next(f for f in findings if f["type"]=="semantic_telemetry")
        assert telemetry["triage"]["windows_attempted"]>=2
        assert telemetry["triage"]["scanned_chars"]<telemetry["triage"]["total_chars"]
