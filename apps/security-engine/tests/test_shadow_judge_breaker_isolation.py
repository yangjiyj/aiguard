"""影子裁判 / 复核类调用的超时不能熔断决策用的语义检测。

现场（2.9.15，SECURITY_LLM_JUDGE_MODE=shadow）：同一后端 URL 下，语义检测调用会把
_breakers[safe_url] 别名到语义熔断器；影子 llm_judge / judge_triage 不带身份，按
safe_url 取到的正是这只熔断器。影子调用连续超时 5 次就把语义检测一起熔断 30s，
语义窗口全部记为 breaker_open（现场 11-02 有 140 条）。
"""
import io
import json
import urllib.error

from app.detectors import llm_judge

URL = "http://judge.internal:8080/v1/chat/completions"
_SEMANTIC_OK = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": json.dumps({
    "assessment": "ok", "verdict": "benign", "category": "none", "confidence": 0.9, "reason": "ok"})}}]})


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _transport(monkeypatch, behaviour):
    calls = []

    def fake_urlopen(req, timeout=None):
        if req.full_url.endswith("/props"):
            raise urllib.error.URLError("no props")
        calls.append(json.loads(req.data)["messages"][0]["content"][:40])
        return behaviour(req)

    monkeypatch.setattr(llm_judge.urllib.request, "urlopen", fake_urlopen)
    return calls


def _semantic():
    return llm_judge.judge_semantic("hello", url=URL, model="m", api_key="k", timeout=2.0)


def test_shadow_timeouts_do_not_open_semantic_breaker(monkeypatch):
    monkeypatch.setenv("SECURITY_SEMANTIC_BREAKER_THRESHOLD", "5")
    _transport(monkeypatch, lambda req: _Resp(_SEMANTIC_OK.encode()))
    assert _semantic() is not None  # 语义检测先成功一次，建立熔断器别名

    def timeout(_req):
        raise TimeoutError("timed out")

    _transport(monkeypatch, timeout)
    for _ in range(6):
        assert llm_judge.judge("some content", url=URL, model="m", api_key="k", timeout=0.5) is None

    calls = _transport(monkeypatch, lambda req: _Resp(_SEMANTIC_OK.encode()))
    assert llm_judge.get_semantic_judge_health(URL)["breaker_open"] is False
    assert _semantic() is not None
    assert len(calls) == 1, "语义检测被影子调用的超时熔断，未发出请求"


def test_shadow_calls_still_have_their_own_breaker(monkeypatch):
    """隔离不等于不设防：影子调用自身连续失败仍会熔断自己，不再打满后端。"""
    monkeypatch.setenv("SECURITY_SEMANTIC_BREAKER_THRESHOLD", "5")

    def timeout(_req):
        raise TimeoutError("timed out")

    calls = _transport(monkeypatch, timeout)
    for _ in range(8):
        llm_judge.judge("some content", url=URL, model="m", api_key="k", timeout=0.5)
    assert len(calls) == 5


def test_semantic_failures_still_open_semantic_breaker(monkeypatch):
    monkeypatch.setenv("SECURITY_SEMANTIC_BREAKER_THRESHOLD", "5")

    def timeout(_req):
        raise TimeoutError("timed out")

    calls = _transport(monkeypatch, timeout)
    for _ in range(7):
        assert _semantic() is None
    assert len(calls) == 5
    assert llm_judge.get_semantic_judge_health(URL)["breaker_open"] is True
