import importlib

from fastapi.testclient import TestClient


class _Stub:
    def score(self, text):
        return 0.5, "attack"

    def runtime_info(self):
        return {
            "configured_provider": "cpu",
            "execution_provider": "cpu",
            "onnx_provider": "CPUExecutionProvider",
            "threads": 2,
        }


def _fresh_main(monkeypatch):
    monkeypatch.delenv("JJD_TIER1_INTERNAL_TOKEN", raising=False)
    monkeypatch.delenv("JJD_INTERNAL_API_SECRET", raising=False)
    import app.classifier as clf
    import app.model as model
    import app.main as m
    importlib.reload(clf)
    importlib.reload(model)
    importlib.reload(m)
    return clf, model, m


def test_lifespan_loads_scorer_into_classifier(monkeypatch):
    clf, model, m = _fresh_main(monkeypatch)
    stub = _Stub()
    monkeypatch.setattr(m, "load_model_scorer", lambda: stub)
    assert clf.get_scorer() is None  # 装配前
    with TestClient(m.app) as c:
        assert clf.get_scorer() is stub  # lifespan 已注入
        r = c.get("/health")
        assert r.json()["model_loaded"] is True
        assert r.json()["runtime"]["execution_provider"] == "cpu"


def test_lifespan_survives_loader_exception(monkeypatch):
    clf, model, m = _fresh_main(monkeypatch)

    def _boom():
        raise RuntimeError("oom while loading onnx")

    monkeypatch.setattr(m, "load_model_scorer", _boom)
    with TestClient(m.app) as c:  # 不得抛
        r = c.get("/health")
        assert r.status_code == 200
        assert r.json()["model_loaded"] is False
        # 没有打分器就没有 ONNX 事实，但容量仍要上报（S1）。
        runtime = r.json()["runtime"]
        assert "execution_provider" not in runtime
        assert runtime["inference_capacity"] > 0
    assert clf.get_scorer() is None


def test_lifespan_loader_returns_none(monkeypatch):
    clf, model, m = _fresh_main(monkeypatch)
    monkeypatch.setattr(m, "load_model_scorer", lambda: None)
    with TestClient(m.app) as c:
        assert c.get("/health").json()["model_loaded"] is False
