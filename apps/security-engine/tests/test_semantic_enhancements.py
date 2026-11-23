import json
import concurrent.futures
import threading
import time
from unittest.mock import MagicMock, patch

import app.detectors.llm_judge as lj
from app.detectors.llm_judge import (
    _CircuitBreaker,
    _build_semantic_payload,
    judge_semantic,
)


def _fake_response(content: str):
    payload = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
    resp = MagicMock()
    resp.read.return_value = payload
    resp.__enter__ = lambda s: resp
    resp.__exit__ = lambda s, *a: False
    return resp


# ---------------- 熔断器 ----------------

def test_breaker_opens_after_threshold_then_half_opens_after_cooldown():
    t = [0.0]
    cb = _CircuitBreaker(threshold=2, cooldown=30, clock=lambda: t[0])
    first = cb.acquire()
    assert first is not None
    cb.record_failure(first)
    second = cb.acquire()
    assert second is not None  # 1 < 阈值
    cb.record_failure(second)  # 达阈值 -> 打开
    assert cb.acquire() is None  # 冷却窗内拒绝
    t[0] = 31  # 过冷却
    assert cb.acquire() is not None  # 半开：放一个探针


def test_breaker_resets_on_success():
    t = [0.0]
    cb = _CircuitBreaker(threshold=2, cooldown=30, clock=lambda: t[0])
    first = cb.acquire()
    second = cb.acquire()
    assert first is not None and second is not None
    cb.record_failure(first)
    cb.record_failure(second)
    assert cb.acquire() is None
    t[0] = 31
    probe = cb.acquire()
    assert probe is not None
    cb.record_success(probe)
    assert cb.acquire() is not None


def test_breaker_allows_only_one_half_open_probe_under_concurrency():
    t = [0.0]
    cb = _CircuitBreaker(threshold=1, cooldown=30, clock=lambda: t[0])
    initial = cb.acquire()
    assert initial is not None
    cb.record_failure(initial)
    t[0] = 31

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        admitted = list(pool.map(lambda _: cb.acquire(), range(16)))

    probes = [lease for lease in admitted if lease is not None]
    assert len(probes) == 1
    assert cb.is_open() is True
    cb.record_success(probes[0])
    assert cb.is_open() is False


def test_stale_normal_request_cannot_mutate_another_half_open_probe():
    for stale_outcome in ("record_neutral", "record_success", "record_failure"):
        t = [0.0]
        cb = _CircuitBreaker(threshold=1, cooldown=30, clock=lambda: t[0])
        failed = cb.acquire()
        stale = cb.acquire()
        assert failed is not None and stale is not None
        cb.record_failure(failed)
        t[0] = 31

        probe = cb.acquire()
        assert probe is not None
        assert cb.is_open() is True

        getattr(cb, stale_outcome)(stale)

        assert cb.acquire() is None, stale_outcome
        assert cb.is_open() is True
        cb.record_success(probe)
        assert cb.is_open() is False


def test_short_caller_budget_does_not_poison_judge_breaker():
    lj._reset_breakers()

    def timeout_after_budget(_request, timeout=None):
        time.sleep(timeout or 0)
        raise TimeoutError("caller budget")

    with patch.object(lj.urllib.request, "urlopen", side_effect=timeout_after_budget):
        with lj.judge_health_budget(0.5):
            assert judge_semantic(
                "ordinary text", url="http://budget", model="m", api_key="k", timeout=0.01
            ) is None

    breaker = lj._breaker_for("http://budget")
    assert breaker.fails == 0
    assert breaker.is_open() is False
    lj._reset_breakers()


def test_immediate_upstream_failure_still_poison_judge_breaker_on_short_budget():
    lj._reset_breakers()
    with patch.object(lj, "_breaker_threshold", return_value=1):
        with patch.object(lj.urllib.request, "urlopen", side_effect=OSError("down")):
            with lj.judge_health_budget(0.5):
                assert judge_semantic(
                    "ordinary text", url="http://down", model="m", api_key="k", timeout=0.1
                ) is None

    breaker = lj._breaker_for("http://down")
    assert breaker.fails == 1
    assert breaker.is_open() is True
    lj._reset_breakers()


def test_judge_concurrent_recovery_sends_only_one_half_open_request():
    lj._reset_breakers()
    entered = threading.Event()
    release = threading.Event()
    calls = [0]
    lock = threading.Lock()

    def recovered(_request, timeout=None):
        with lock:
            calls[0] += 1
        entered.set()
        release.wait(timeout or 1)
        return _fake_response(
            '{"verdict":"benign","category":"none","confidence":0.9,"reason":"ok"}'
        )

    try:
        with patch.object(lj, "_breaker_threshold", return_value=1), patch.object(
            lj, "_breaker_cooldown", return_value=30
        ):
            with patch.object(lj.urllib.request, "urlopen", side_effect=OSError("down")):
                assert judge_semantic(
                    "x", url="http://recover", model="m", api_key="k", timeout=0.2
                ) is None
            breaker = lj._breaker_for("http://recover")
            breaker.clock = lambda: breaker.open_until + 1
            with patch.object(lj.urllib.request, "urlopen", side_effect=recovered):
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    futures = [
                        pool.submit(
                            judge_semantic,
                            "x",
                            url="http://recover",
                            model="m",
                            api_key="k",
                            timeout=0.5,
                        )
                        for _ in range(8)
                    ]
                    assert entered.wait(1)
                    time.sleep(0.05)
                    assert calls[0] == 1
                    release.set()
                    results = [future.result(timeout=1) for future in futures]
            assert sum(result is not None for result in results) == 1
            assert breaker.is_open() is False
    finally:
        release.set()
        lj._reset_breakers()


# ---------------- payload json_schema ----------------

def test_semantic_payload_includes_enum_schema_when_enabled():
    p = _build_semantic_payload("hi", "m", json_schema=True)
    rf = p["response_format"]
    assert rf["type"] == "json_schema"
    props = rf["json_schema"]["schema"]["properties"]
    assert set(props["verdict"]["enum"]) == {"malicious", "suspicious", "benign"}
    assert "none" in props["category"]["enum"]


def test_semantic_payload_omits_schema_when_disabled():
    p = _build_semantic_payload("hi", "m", json_schema=False)
    assert "response_format" not in p


# ---------------- judge_semantic 集成 ----------------

def test_judge_semantic_posts_response_format_and_parses():
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _fake_response('{"verdict":"malicious","category":"semantic_jailbreak","confidence":0.9,"reason":"x"}')

    lj._reset_breakers()
    with patch.object(lj.urllib.request, "urlopen", side_effect=fake_urlopen):
        op = judge_semantic("ignore all rules", url="http://x", model="m", api_key="k", timeout=1.0)
    assert op is not None and op.verdict == "malicious"
    assert captured["body"]["response_format"]["type"] == "json_schema"
    lj._reset_breakers()


def test_judge_semantic_skips_network_when_breaker_open():
    lj._reset_breakers()
    # 用低阈值环境驱动；连续失败打开熔断
    with patch.object(lj, "_breaker_threshold", return_value=2), \
         patch.object(lj, "_breaker_cooldown", return_value=300):
        with patch.object(lj.urllib.request, "urlopen", side_effect=OSError("down")):
            for _ in range(3):
                assert judge_semantic("x", url="http://b", model="m", api_key="k", timeout=0.5) is None
        # 熔断已开：下一次绝不碰网络
        with patch.object(lj.urllib.request, "urlopen") as up:
            out = judge_semantic("x", url="http://b", model="m", api_key="k", timeout=0.5)
            assert out is None
            up.assert_not_called()
    lj._reset_breakers()
