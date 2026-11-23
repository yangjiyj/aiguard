"""Judge 后端槽位自适应：对同一后端的并发不超过它上报的 total_slots。

09-23 事故：引擎放 16 路并发打到只有 2 槽的 CPU 3B，其余在 llama.cpp 内部排队、
8 秒超时被取消，约 65% 的裁判工作白做。这里按后端 /props 上报的槽位数限流。
"""
import json
import threading
import time

from app.detectors import llm_judge

URL = "http://judge.internal:8080/v1/chat/completions"


class _Resp:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, size=-1):
        return self._body


def _chat_body(text="ok"):
    return json.dumps({"choices": [{"message": {"content": text}}]}).encode()


def _fake_backend(slots, hold=0.05, props_ok=True):
    state = {"active": 0, "peak": 0, "props_calls": 0}
    lock = threading.Lock()

    def _open(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url.endswith("/props"):
            state["props_calls"] += 1
            if not props_ok:
                raise OSError("props unavailable")
            return _Resp(json.dumps({"total_slots": slots}).encode())
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        time.sleep(hold)
        with lock:
            state["active"] -= 1
        return _Resp(_chat_body())

    return _open, state


def _run_parallel(n, timeout=5.0):
    results = []
    lock = threading.Lock()

    def call():
        text = llm_judge._post_chat(URL, b"{}", "k", timeout)
        with lock:
            results.append(text)

    threads = [threading.Thread(target=call) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_concurrency_never_exceeds_backend_reported_slots(monkeypatch):
    llm_judge._reset_breakers()
    opener, state = _fake_backend(slots=2)
    monkeypatch.setattr(llm_judge.urllib.request, "urlopen", opener)
    results = _run_parallel(8)
    assert state["peak"] <= 2, f"sent {state['peak']} concurrent calls to a 2-slot backend"
    assert results.count("ok") == 8, "calls beyond the slot count must wait and succeed, not be dropped"


def test_slot_probe_failure_keeps_existing_unthrottled_behaviour(monkeypatch):
    llm_judge._reset_breakers()
    opener, state = _fake_backend(slots=2, props_ok=False)
    monkeypatch.setattr(llm_judge.urllib.request, "urlopen", opener)
    results = _run_parallel(6)
    assert results.count("ok") == 6
    assert state["peak"] > 2, "an unknown slot count must not throttle below today's behaviour"


def test_slot_count_is_probed_once_per_backend(monkeypatch):
    llm_judge._reset_breakers()
    opener, state = _fake_backend(slots=4, hold=0.01)
    monkeypatch.setattr(llm_judge.urllib.request, "urlopen", opener)
    _run_parallel(6)
    _run_parallel(6)
    assert state["props_calls"] == 1


def test_waiting_for_a_slot_respects_the_call_deadline(monkeypatch):
    llm_judge._reset_breakers()
    opener, state = _fake_backend(slots=1, hold=0.4)
    monkeypatch.setattr(llm_judge.urllib.request, "urlopen", opener)
    started = time.monotonic()
    results = _run_parallel(3, timeout=0.5)
    elapsed = time.monotonic() - started
    assert state["peak"] <= 1
    assert results.count("ok") >= 1
    assert None in results, "a call that cannot get a slot before its deadline must fail open"
    assert elapsed < 1.5, "waiting for a slot must not extend a call past its own deadline"


def test_full_slots_do_not_trip_the_circuit_breaker(monkeypatch):
    # 槽位满是本侧容量问题，不是后端故障：大量等不到槽位的调用不能把熔断打开。
    llm_judge._reset_breakers()
    opener, state = _fake_backend(slots=1, hold=0.3)
    monkeypatch.setattr(llm_judge.urllib.request, "urlopen", opener)
    _run_parallel(12, timeout=0.2)
    lease = llm_judge._breaker_for(URL).acquire()
    assert lease is not None, "capacity waits must not open the breaker"
    llm_judge._breaker_for(URL).record_neutral(lease)


def test_concurrent_first_calls_probe_the_backend_only_once(monkeypatch):
    # 启动或切换后端时大量请求同时首调，不能对后端发出同样数量的 /props 探测。
    llm_judge._reset_breakers()
    opener, state = _fake_backend(slots=2, hold=0.05)

    def slow_props_opener(req, timeout=None):
        if req.full_url.endswith("/props"):
            time.sleep(0.05)
        return opener(req, timeout)

    monkeypatch.setattr(llm_judge.urllib.request, "urlopen", slow_props_opener)
    _run_parallel(12)
    assert state["props_calls"] == 1, f"probed {state['props_calls']} times"
    assert state["peak"] <= 2


def test_failed_probe_is_retried_after_backend_finishes_loading(monkeypatch):
    # 随包 llama-server 加载模型期间 /props 返回 503；首轮探测失败不能被永久缓存，
    # 否则整个进程生命周期都不再限流。
    llm_judge._reset_breakers()
    state = {"props_ok": False, "props_calls": 0, "active": 0, "peak": 0}
    lock = threading.Lock()

    def _open(req, timeout=None):
        if req.full_url.endswith("/props"):
            state["props_calls"] += 1
            if not state["props_ok"]:
                raise OSError("503 Loading model")
            return _Resp(json.dumps({"total_slots": 2}).encode())
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        time.sleep(0.05)
        with lock:
            state["active"] -= 1
        return _Resp(_chat_body())

    monkeypatch.setattr(llm_judge.urllib.request, "urlopen", _open)
    monkeypatch.setattr(llm_judge, "_SLOT_PROBE_RETRY_SECONDS", 0.05)
    _run_parallel(2)
    state["props_ok"] = True
    time.sleep(0.06)
    state["peak"] = 0
    _run_parallel(8)
    assert state["peak"] <= 2, "after the backend recovers, the slot count must be probed again and enforced"



# ---------------------------------------------------------------------------
# 容量跳过 vs 后端故障的归因。全部用 Event 控制占槽/放槽，不靠 sleep 赌时序。
# 规则：槽位等不到、或排队显著缩短预算后在截止时刻被截断 → 容量（中性、不计健康失败、
# 语义层报容量饱和）；没排队或只短暂排队后的超时、排队后的非超时错误 → 后端故障。
# ---------------------------------------------------------------------------

class _ScriptedBackend:
    """/props 报 1 槽；聊天请求按线程名执行预设行为。"""

    def __init__(self, slots=1):
        self.slots = slots
        self.behaviors = {}
        self.chat_calls = 0
        self.entered = {}

    def __call__(self, req, timeout=None):
        if req.full_url.endswith("/props"):
            return _Resp(json.dumps({"total_slots": self.slots}).encode())
        self.chat_calls += 1
        name = threading.current_thread().name
        self.entered.setdefault(name, threading.Event()).set()
        return self.behaviors[name](timeout)


def _ok(_timeout):
    return _Resp(_chat_body('{"verdict":"benign","category":"none","confidence":0.9,"reason":"ok"}'))


def _hold_until(event):
    def run(timeout):
        assert event.wait(5), "test never released the occupying call"
        return _ok(timeout)
    return run


def _backend_times_out(timeout):
    # 真实 socket 超时：阻塞到客户端给的超时再抛。
    time.sleep(max(0.0, timeout))
    raise TimeoutError("timed out")


def _backend_refuses(_timeout):
    raise llm_judge.urllib.error.URLError(ConnectionRefusedError(111, "refused"))


def _occupy(backend, release, name="occupier"):
    """占住唯一槽位，直到 release 被 set。返回已启动的线程。"""
    backend.behaviors[name] = _hold_until(release)
    t = threading.Thread(target=lambda: llm_judge._post_chat(URL, b"{}", "k", 5.0), name=name)
    backend.entered[name] = threading.Event()
    t.start()
    assert backend.entered[name].wait(2), "occupier never reached the backend"
    return t


def _in_thread(name, fn):
    out = {}

    def run():
        out["value"] = fn()
        out["capacity"] = llm_judge.judge_capacity_skipped()

    t = threading.Thread(target=run, name=name)
    t.start()
    return t, out


def _health():
    return llm_judge._semantic_judge_health.get(URL, {})


def _gate():
    return llm_judge._slot_gates.get(URL)


def _setup(monkeypatch):
    llm_judge._reset_breakers()
    backend = _ScriptedBackend(slots=1)
    monkeypatch.setattr(llm_judge.urllib.request, "urlopen", backend)
    return backend


def test_unqueued_backend_timeout_is_a_backend_failure(monkeypatch):
    backend = _setup(monkeypatch)
    backend.behaviors["caller"] = _backend_times_out
    t, out = _in_thread("caller", lambda: llm_judge.judge_semantic("x", url=URL, model="m", api_key="k", timeout=0.2))
    t.join(5)
    assert out["value"] is None
    assert out["capacity"] is False, "a timeout without any queueing is the backend's, not capacity"
    assert _health().get("consecutive_failures") == 1
    assert llm_judge._breaker_for(URL).fails == 1
    assert _gate()._value == 1, "slot must be returned"


def test_slot_never_available_is_capacity_not_failure(monkeypatch):
    backend = _setup(monkeypatch)
    release = threading.Event()
    occ = _occupy(backend, release)
    backend.behaviors["caller"] = _ok
    t, out = _in_thread("caller", lambda: llm_judge.judge_semantic("x", url=URL, model="m", api_key="k", timeout=0.15))
    t.join(5)
    release.set()
    occ.join(5)
    assert out["value"] is None and out["capacity"] is True
    assert "caller" not in backend.entered or not backend.entered["caller"].is_set(), "must not reach the backend"
    assert _health().get("consecutive_failures", 0) == 0
    assert llm_judge._breaker_for(URL).fails == 0
    assert _gate()._value == 1


def test_queue_that_consumed_most_budget_then_deadline_timeout_is_capacity(monkeypatch):
    backend = _setup(monkeypatch)
    release = threading.Event()
    occ = _occupy(backend, release)
    backend.behaviors["caller"] = _backend_times_out
    t, out = _in_thread("caller", lambda: llm_judge.judge_semantic("x", url=URL, model="m", api_key="k", timeout=0.4))
    time.sleep(0.2)  # 排队吃掉一半预算（阈值 max(0.05, 10%)=0.05s，远离边界）
    release.set()
    t.join(5)
    occ.join(5)
    assert backend.entered["caller"].is_set(), "fixture must actually send the queued request"
    assert out["value"] is None and out["capacity"] is True
    assert _health().get("consecutive_failures", 0) == 0
    assert llm_judge._breaker_for(URL).fails == 0
    # 容量超时在窗口里单独可见，但不进成功率分母：既不算成功，也不把裁判判成不可运行。
    summary = llm_judge.get_semantic_judge_health(URL)
    assert summary["window_capacity_timeouts"] == 1
    assert summary["window_timeouts"] == 0
    assert _gate()._value == 1


def test_brief_queue_then_backend_timeout_is_still_a_backend_failure(monkeypatch):
    backend = _setup(monkeypatch)
    release = threading.Event()
    occ = _occupy(backend, release)
    backend.behaviors["caller"] = _backend_times_out
    # 预算 0.6s → 显著排队阈值 max(0.05, 0.06)=0.06s；只排约 0.01s。
    t, out = _in_thread("caller", lambda: llm_judge.judge_semantic("x", url=URL, model="m", api_key="k", timeout=0.6))
    time.sleep(0.01)
    release.set()
    t.join(5)
    occ.join(5)
    assert backend.entered["caller"].is_set()
    assert out["value"] is None
    assert out["capacity"] is False, "a short queue must not launder a real backend timeout"
    assert _health().get("consecutive_failures") == 1
    assert llm_judge._breaker_for(URL).fails == 1
    assert _gate()._value == 1


def test_queued_then_non_timeout_backend_error_is_a_failure(monkeypatch):
    backend = _setup(monkeypatch)
    release = threading.Event()
    occ = _occupy(backend, release)
    backend.behaviors["caller"] = _backend_refuses
    t, out = _in_thread("caller", lambda: llm_judge.judge_semantic("x", url=URL, model="m", api_key="k", timeout=0.4))
    time.sleep(0.2)
    release.set()
    t.join(5)
    occ.join(5)
    assert out["value"] is None and out["capacity"] is False
    assert _health().get("consecutive_failures") == 1
    assert llm_judge._breaker_for(URL).fails == 1
    assert _gate()._value == 1


def test_capacity_flag_is_reset_on_every_call_including_early_returns(monkeypatch):
    backend = _setup(monkeypatch)
    release = threading.Event()
    occ = _occupy(backend, release)
    results = {}

    def run():
        llm_judge.judge_semantic("x", url=URL, model="m", api_key="k", timeout=0.1)
        results["after_skip"] = llm_judge.judge_capacity_skipped()
        # 早退路径：空内容 / URL 不合法 / 熔断打开都不能沿用上一次的 True。
        llm_judge.judge_semantic("", url=URL, model="m", api_key="k", timeout=0.1)
        results["after_empty"] = llm_judge.judge_capacity_skipped()
        llm_judge.judge_semantic("x", url="ftp://bad/x", model="m", api_key="k", timeout=0.1)
        results["after_bad_url"] = llm_judge.judge_capacity_skipped()

    t = threading.Thread(target=run, name="caller")
    t.start()
    t.join(5)
    release.set()
    occ.join(5)
    assert results == {"after_skip": True, "after_empty": False, "after_bad_url": False}

    # 熔断打开时 _post_chat 在占槽前早退，同样必须清零。
    breaker = llm_judge._breaker_for(URL)
    breaker.fails = breaker.threshold
    breaker.open_until = time.monotonic() + 60
    llm_judge._capacity_skipped.set(True)
    assert llm_judge._post_chat(URL, b"{}", "k", 0.1) is None
    assert llm_judge.judge_capacity_skipped() is False


def test_capacity_flag_is_isolated_between_concurrent_callers(monkeypatch):
    backend = _setup(monkeypatch)
    release = threading.Event()
    occ = _occupy(backend, release)
    backend.behaviors["refused"] = _backend_refuses
    skipped_t, skipped = _in_thread(
        "skipped", lambda: llm_judge.judge_semantic("x", url=URL, model="m", api_key="k", timeout=0.1))
    skipped_t.join(5)
    release.set()
    occ.join(5)
    refused_t, refused = _in_thread(
        "refused", lambda: llm_judge.judge_semantic("x", url=URL, model="m", api_key="k", timeout=0.5))
    refused_t.join(5)
    assert skipped["capacity"] is True
    assert refused["capacity"] is False
    assert _health().get("consecutive_failures") == 1, "only the real failure counts"


def test_semantic_layer_reports_capacity_skip_as_capacity_not_unavailable(monkeypatch):
    from app.detectors import semantic

    backend = _setup(monkeypatch)
    release = threading.Event()
    occ = _occupy(backend, release)
    out = {}

    def run():
        out["v"] = semantic._judge_with_health_budget(0.1, "x", url=URL, model="m", api_key="k", timeout=0.1)

    t = threading.Thread(target=run, name="caller")
    t.start()
    t.join(5)
    release.set()
    occ.join(5)
    assert out["v"] is semantic._OVERFLOW

    # 真实故障仍返回 None，由上层报 judge_unavailable。
    backend.behaviors["caller2"] = _backend_refuses

    def run2():
        out["v2"] = semantic._judge_with_health_budget(0.5, "x", url=URL, model="m", api_key="k", timeout=0.5)

    t2 = threading.Thread(target=run2, name="caller2")
    t2.start()
    t2.join(5)
    assert out["v2"] is None


def test_capacity_timeouts_do_not_make_judge_non_operational(monkeypatch):
    _setup(monkeypatch)
    for _ in range(3):
        llm_judge._record_semantic_judge_window(URL, success=True, timed_out=False, latency_ms=10)
    for _ in range(20):
        llm_judge._record_semantic_judge_window(URL, success=False, timed_out=True, latency_ms=400, capacity=True)
    llm_judge._record_semantic_judge_attempt(URL, True)
    health = llm_judge.get_semantic_judge_health(URL)
    assert health["window_attempts"] == 3 and health["window_successes"] == 3
    assert health["window_capacity_timeouts"] == 20
    assert health["operational"] is True
    # 对照：同样数量的真实超时必须把裁判判成不可运行。
    for _ in range(20):
        llm_judge._record_semantic_judge_window(URL, success=False, timed_out=True, latency_ms=400)
    assert llm_judge.get_semantic_judge_health(URL)["operational"] is False
