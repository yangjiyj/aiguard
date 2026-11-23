"""MCP 描述投毒 llm-judge 语义复核层测试。

覆盖：judge 命中→finding（malicious/suspicious 映射）、裁判返回 None→[]、
异常→[]（fail-open）、feature flag 关→engine 不调用 judge_semantic。
全程用 monkeypatch mock judge_semantic，不打真实裁判后端。
"""
import app.detectors.agent_guard as ag
from app.detectors.agent_guard import judge_mcp_description_poison
from app.detectors.llm_judge import SemanticOpinion


def test_malicious_verdict_maps_to_high_confidence_09(monkeypatch):
    monkeypatch.setattr(
        ag, "judge_semantic",
        lambda *a, **k: SemanticOpinion("malicious", "semantic_instruction_override", 0.95, "x"),
    )
    out = judge_mcp_description_poison("weather", "看似正常但语义在指挥 agent 越权")
    assert len(out) == 1
    assert out[0].category == "mcp_description_poison_semantic"
    assert out[0].severity == "high"
    assert out[0].confidence == 0.9
    assert out[0].rule_id == "mcp_description_poison_semantic"


def test_suspicious_verdict_maps_to_medium_confidence_05(monkeypatch):
    monkeypatch.setattr(
        ag, "judge_semantic",
        lambda *a, **k: SemanticOpinion("suspicious", "none", 0.4, "x"),
    )
    out = judge_mcp_description_poison("tool", "边界描述")
    assert len(out) == 1
    assert out[0].severity == "medium"
    assert out[0].confidence == 0.5


def test_benign_verdict_produces_no_finding(monkeypatch):
    monkeypatch.setattr(
        ag, "judge_semantic",
        lambda *a, **k: SemanticOpinion("benign", "none", 0.1, "ok"),
    )
    assert judge_mcp_description_poison("weather", "Return the weather for a city.") == []


def test_judge_returns_none_yields_empty(monkeypatch):
    # 裁判不可达 / 超时 / 解析失败 → None → []（fail-open）
    monkeypatch.setattr(ag, "judge_semantic", lambda *a, **k: None)
    assert judge_mcp_description_poison("tool", "任意描述") == []


def test_judge_exception_is_fail_open(monkeypatch):
    # detect 永不抛异常：judge_semantic 抛异常也必须返回 []
    def _boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(ag, "judge_semantic", _boom)
    assert judge_mcp_description_poison("tool", "任意描述") == []


def test_empty_description_never_calls_judge(monkeypatch):
    called = {"n": 0}

    def _spy(*a, **k):
        called["n"] += 1
        return SemanticOpinion("malicious", "none", 0.9, "x")

    monkeypatch.setattr(ag, "judge_semantic", _spy)
    assert judge_mcp_description_poison("tool", "") == []
    assert called["n"] == 0


def test_scan_mcp_description_stays_pure_regex(monkeypatch):
    # 铁律：正则初筛不受语义层影响——即便 judge 会命中，纯正则对良性描述仍不误报。
    monkeypatch.setattr(
        ag, "judge_semantic",
        lambda *a, **k: SemanticOpinion("malicious", "none", 0.9, "x"),
    )
    assert ag.scan_mcp_description("weather", "Return the weather for a city.") == []


# —— engine 侧 gate：开关关→不调用；开关开→附加 finding ——


def _build_engine(monkeypatch, enabled, spy):
    monkeypatch.setenv("SECURITY_AGENT_GUARD_ENABLED", "true")
    monkeypatch.setenv("SECURITY_MCP_POISON_JUDGE_ENABLED", "true" if enabled else "false")
    monkeypatch.setattr(ag, "judge_semantic", spy)
    from app.detectors.engine import SecurityEngine
    return SecurityEngine()


def test_engine_flag_off_never_calls_judge(monkeypatch):
    called = {"n": 0}

    def _spy(*a, **k):
        called["n"] += 1
        return SemanticOpinion("malicious", "none", 0.9, "x")

    eng = _build_engine(monkeypatch, enabled=False, spy=_spy)
    ctx = {"mcp_tools": [{"name": "t1", "description": "语义投毒但正则未命中的描述"}]}
    result = eng.check_input("req-off", "hello", context=ctx)
    assert called["n"] == 0
    assert not [f for f in result.findings if f.category == "mcp_description_poison_semantic"]


def test_engine_flag_on_appends_semantic_finding(monkeypatch):
    def _judge(*a, **k):
        return SemanticOpinion("malicious", "semantic_instruction_override", 0.9, "x")

    eng = _build_engine(monkeypatch, enabled=True, spy=_judge)
    ctx = {"mcp_tools": [{"name": "t1", "description": "语义投毒但正则未命中的描述"}]}
    result = eng.check_input("req-on", "hello", context=ctx)
    sem = [f for f in result.findings if f.category == "mcp_description_poison_semantic"]
    assert sem, "开关开时应附加语义复核 finding"
    assert sem[0].severity == "high"
    assert sem[0].confidence == 0.9
 # observe-only：语义 finding 绝不 
