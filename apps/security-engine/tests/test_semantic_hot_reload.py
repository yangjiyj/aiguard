"""B1 回归：语义/裁判配置热重配必须灌进 live 单例（免重启）。

证明 SecurityEngine.reconfigure_semantic() 把 feature_flags 的最新读数
（override 优先）反映到引擎缓存属性 + 重建的 SemanticDetector 上。
"""
import app.feature_flags as ff
from app.detectors import engine as eng_mod


def _clear():
    ff.apply_overrides({})


def test_reconfigure_semantic_applies_override_live(monkeypatch):
    # 基线：env 关闭语义，无 override
    monkeypatch.setenv("SECURITY_SEMANTIC_ENABLED", "false")
    _clear()
    e = eng_mod.SecurityEngine()
    e.reconfigure_semantic()
    assert e.semantic_enabled is False
    assert e.semantic_output_enabled is False

    # loader 注入 DB 配置 → reconfigure → live 生效（无重启）
    ff.apply_overrides({
        "SECURITY_SEMANTIC_ENABLED": "true",
        "SECURITY_SEMANTIC_INPUT_ENABLED": "true",
        "SECURITY_SEMANTIC_OUTPUT_ENABLED": "true",
        "SECURITY_LLM_JUDGE_URL": "http://db-judge/v1/",
        "SECURITY_LLM_JUDGE_MODEL": "db-judge-model",
        "SECURITY_LLM_JUDGE_API_KEY": "db-key",
        "SECURITY_SEMANTIC_SAMPLE_RATE": "0.5",
        "SECURITY_SEMANTIC_TOTAL_TIMEOUT": "12.5",
    })
    e.reconfigure_semantic()
    # 开关随之 live 改变
    assert e.semantic_enabled is True
    assert e.semantic_output_enabled is True
    # 裁判 url/model/key 缓存属性随之更新
    assert e._judge_url == "http://db-judge/v1/"
    assert e._judge_model == "db-judge-model"
    assert e._judge_api_key == "db-key"
    assert e._semantic_sample_rate == 0.5
    assert e._semantic_total_timeout == 12.5
    # 重建的 SemanticDetector 也持有最新裁判配置（否则检测仍用旧值）
    assert e.semantic._url == "http://db-judge/v1/"
    assert e.semantic._model == "db-judge-model"
    assert e.semantic._api_key == "db-key"
    assert e.semantic._sample_rate == 0.5

    _clear()


def test_init_matches_reconfigure(monkeypatch):
    """DRY 自证：__init__ 的语义初值必须与紧随其后的 reconfigure 等价。"""
    monkeypatch.setenv("SECURITY_SEMANTIC_ENABLED", "true")
    monkeypatch.setenv("SECURITY_SEMANTIC_INPUT_ENABLED", "true")
    monkeypatch.setenv("SECURITY_LLM_JUDGE_MODEL", "env-model")
    _clear()
    e = eng_mod.SecurityEngine()
    before = (
        e.semantic_enabled, e.semantic_output_enabled,
        e._judge_url, e._judge_model, e._judge_api_key,
        e._semantic_total_timeout, e._semantic_sample_rate,
        e.semantic._url, e.semantic._model, e.semantic._sample_rate,
    )
    e.reconfigure_semantic()
    after = (
        e.semantic_enabled, e.semantic_output_enabled,
        e._judge_url, e._judge_model, e._judge_api_key,
        e._semantic_total_timeout, e._semantic_sample_rate,
        e.semantic._url, e.semantic._model, e.semantic._sample_rate,
    )
    assert before == after
    _clear()


def test_reconfigure_injects_tier1_when_enabled(monkeypatch):
    from app import feature_flags as ff
    ff.apply_overrides({})
    monkeypatch.setenv("SECURITY_TIER1_ENABLED", "true")
    monkeypatch.setenv("SECURITY_TIER1_API_TOKEN", "hot-reload-tier1-token")
    monkeypatch.setenv("SECURITY_TIER1_URL", "http://tier1-classifier:8000/classify")
    monkeypatch.setenv("SECURITY_TIER1_LOW_THRESHOLD", "0.15")
    monkeypatch.setenv("SECURITY_TIER1_HIGH_THRESHOLD", "0.85")
    from app.detectors.engine import SecurityEngine
    eng = SecurityEngine()
    sem = eng.semantic
    assert sem._tier1_enabled is True
    assert sem._tier1_client is not None
    assert sem._tier1_low == 0.15
    assert sem._tier1_high == 0.85
    assert sem._tier1_client._url == "http://tier1-classifier:8000/classify"


def test_tier1_high_direct_disabled_for_all_modes(monkeypatch):
    from app import feature_flags as ff
    from app.detectors.engine import SecurityEngine

    ff.apply_overrides({
        "SECURITY_TIER1_ENABLED": "true",
        "SECURITY_AUDIT_ONLY": "true",
    })
    audit_engine = SecurityEngine()
    assert audit_engine.semantic._tier1_high_direct is False

    ff.apply_overrides({
        "SECURITY_TIER1_ENABLED": "true",
        "SECURITY_AUDIT_ONLY": "false",
    })
    enforcing_engine = SecurityEngine()
    assert enforcing_engine.semantic._tier1_high_direct is False
    ff.apply_overrides({})


def test_reconfigure_prefers_dedicated_tier1_token(monkeypatch):
    """Tier-1 不能误用 security-engine 自身接口鉴权密钥。"""
    from app import feature_flags as ff
    from app.detectors.engine import SecurityEngine

    ff.apply_overrides({})
    monkeypatch.setenv("SECURITY_TIER1_ENABLED", "true")
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "engine-api-token")
    monkeypatch.setenv("SECURITY_TIER1_API_TOKEN", "tier1-api-token")

    eng = SecurityEngine()

    assert eng.semantic._tier1_client is not None
    assert eng.semantic._tier1_client._token == "tier1-api-token"


def test_reconfigure_tier1_disabled_default(monkeypatch):
    from app import feature_flags as ff
    ff.apply_overrides({})
    monkeypatch.delenv("SECURITY_TIER1_ENABLED", raising=False)
    from app.detectors.engine import SecurityEngine
    eng = SecurityEngine()
    sem = eng.semantic
    assert sem._tier1_enabled is False
    assert sem._tier1_client is None  # 默认关 → 不构造 client


def test_reconfigure_tier1_hot_reload_via_override(monkeypatch):
    from app import feature_flags as ff
    from app.detectors.engine import SecurityEngine
    ff.apply_overrides({})
    eng = SecurityEngine()
    assert eng.semantic._tier1_enabled is False
    ff.apply_overrides({
        "SECURITY_TIER1_ENABLED": "true",
        "SECURITY_TIER1_URL": "http://tier1-classifier:8000/classify",
    })
    monkeypatch.setenv("SECURITY_TIER1_API_TOKEN", "hot-reload-tier1-token")
    eng.reconfigure_semantic()
    assert eng.semantic._tier1_enabled is True
    assert eng.semantic._tier1_client is not None
    ff.apply_overrides({})  # 复位，避免污染其它测试
