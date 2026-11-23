import concurrent.futures
import io
import json
import threading
import urllib.error
import app.detectors.tier1_client as t1

def test_busy_sidecar_does_not_poison_health_breaker(monkeypatch):
    calls=[]
    def post(*args):
        calls.append(1)
        if len(calls)<=6:
            return t1.Tier1Failure("tier1_capacity_overflow", retryable=True, http_status=503)
        return '{"coverage_complete":true,"score":0.1,"label":"benign"}'
    monkeypatch.setattr(t1,"_http_post",post)
    t1._reset_breakers()
    client=t1.Tier1Client(url=t1.BUNDLED_TIER1_URL,token="fixture",timeout=1)
    for _ in range(6):
        result=client.classify_detailed("ordinary request")
        assert isinstance(result,t1.Tier1Failure)
        assert result.reason=="tier1_capacity_overflow"
    assert client.classify("ordinary request")==(.1,"benign")
    assert len(calls)==7

def test_real_backend_failure_still_trips_breaker(monkeypatch):
    calls=[]
    monkeypatch.setattr(t1,"_http_post",lambda *args: calls.append(1))
    t1._reset_breakers()
    client=t1.Tier1Client(url=t1.BUNDLED_TIER1_URL,token="fixture",timeout=1)
    for _ in range(8):assert client.classify("x") is None
    assert len(calls)==t1._BREAKER_THRESHOLD

def test_client_admission_keeps_network_calls_within_local_worker_count(monkeypatch):
    entered=threading.Event();release=threading.Event();both_started=threading.Event()
    lock=threading.Lock();active=0;peak=0;calls=0
    def post(*args):
        nonlocal active,peak,calls
        with lock:active+=1;peak=max(peak,active);calls+=1;which=calls
        if which==1:
            entered.set()
            assert release.wait(2)
        with lock:active-=1
        return '{"coverage_complete":true,"score":0.1,"label":"benign"}'
    monkeypatch.setattr(t1,"_http_post",post)
    monkeypatch.setenv("SECURITY_TIER1_MAX_INFLIGHT","1")
    t1._reset_breakers()
    client=t1.Tier1Client(url=t1.BUNDLED_TIER1_URL,token="fixture",timeout=1)
    def second():
        both_started.set()
        return client.classify("second",timeout=2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        first=pool.submit(client.classify,"first",timeout=2)
        assert entered.wait(1)
        later=pool.submit(second)
        assert both_started.wait(1)
        release.set()
        assert first.result()==(.1,"benign")
        assert later.result()==(.1,"benign")
    assert peak==1 and calls==2

def test_queue_expiry_does_not_call_sidecar_or_mark_backend_unhealthy(monkeypatch):
    entered=threading.Event();release=threading.Event();calls=[]
    def post(*args):
        calls.append(1);entered.set();assert release.wait(2)
        return '{"coverage_complete":true,"score":0.1,"label":"benign"}'
    monkeypatch.setattr(t1,"_http_post",post)
    monkeypatch.setenv("SECURITY_TIER1_MAX_INFLIGHT","1")
    t1._reset_breakers()
    client=t1.Tier1Client(url=t1.BUNDLED_TIER1_URL,token="fixture",timeout=1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        first=pool.submit(client.classify,"first",timeout=2)
        assert entered.wait(1)
        try:
            result=client.classify_detailed("queued",timeout=.02)
            assert isinstance(result,t1.Tier1Failure)
            assert result.reason=="tier1_client_queue_timeout"
            assert len(calls)==1
            assert t1._breaker_for(t1.BUNDLED_TIER1_URL).fails==0
        finally:release.set()
        assert first.result()==(.1,"benign")

def test_overload_error_body_is_bounded_and_not_returned_as_model_output(monkeypatch):
    class Opener:
        def open(self,*args,**kwargs):
            raise urllib.error.HTTPError(t1.BUNDLED_TIER1_URL,503,"busy",{},
                io.BytesIO(b'{"error":{"code":"inference_queue_timeout","private_text":"not-for-output"}}'))
    monkeypatch.setattr(t1.urllib.request,"build_opener",lambda *args:Opener())
    result=t1._http_post(t1.BUNDLED_TIER1_URL,b'{}',"fixture",1)
    assert isinstance(result,t1.Tier1Failure)
    assert result.reason=="tier1_queue_timeout"
    assert "not-for-output" not in repr(result)

def test_semantic_result_preserves_busy_reason_and_incomplete_status(monkeypatch):
    from app.detectors.semantic import SemanticDetector
    monkeypatch.setattr(t1,"_http_post",lambda *args:t1.Tier1Failure("tier1_capacity_overflow",retryable=True,http_status=503))
    t1._reset_breakers()
    client=t1.Tier1Client(url=t1.BUNDLED_TIER1_URL,token="fixture",timeout=1)
    detector=SemanticDetector(url="http://127.0.0.1:8091/v1/chat/completions",model="fixture",api_key="fixture",op_timeout=1,total_timeout=2,
        tier1_enabled=True,tier1_client=client)
    findings=detector.detect("ordinary business request","input",content_source="user")
    assert findings and all(f.get("counts_as_security_finding") is False for f in findings)
    assert findings[0]["triage"]["semantic_status"]=="incomplete"
    assert findings[0]["triage"]["semantic_reason"]=="tier1_capacity_overflow"

def test_enclosing_deadline_caps_transport_even_for_direct_client_use(monkeypatch):
    import time
    from app.bounded_work import execution_budget
    seen=[]
    def post(url,body,token,timeout):
        seen.append(timeout)
        return '{"coverage_complete":true,"score":0.1,"label":"benign"}'
    monkeypatch.setattr(t1,"_http_post",post)
    t1._reset_breakers()
    client=t1.Tier1Client(url=t1.BUNDLED_TIER1_URL,token="fixture",timeout=1)
    with execution_budget(time.monotonic()+.02):
        assert client.classify("normal",timeout=2)==(.1,"benign")
    assert 0 < seen[0] <= .02

def test_parent_budget_expiry_does_not_count_as_normal_backend_timeout(monkeypatch):
    import time
    from app.bounded_work import execution_budget
    def post(*args):
        time.sleep(.02)
        return None
    monkeypatch.setattr(t1,"_http_post",post)
    t1._reset_breakers()
    client=t1.Tier1Client(url=t1.BUNDLED_TIER1_URL,token="fixture",timeout=1)
    with execution_budget(time.monotonic()+.01):
        assert client.classify("normal",timeout=2) is None
    assert t1._breaker_for(t1.BUNDLED_TIER1_URL).fails==0
