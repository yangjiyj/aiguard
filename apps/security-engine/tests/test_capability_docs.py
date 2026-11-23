import json
import re
from pathlib import Path

import pytest

from app import capability_docs, feature_flags
from app.capability_docs import CapabilityDocError, display_kind, load_capability_docs, parse_docs
from app.detectors.engine import SecurityEngine


COMPOSE_FILE = Path(__file__).resolve().parents[3] / "deploy" / "docker-compose" / "docker-compose.yml"

# 一致性测试用的引擎开关：与 docker-compose.yml 里 security-engine 服务的生产默认值一致。
PRODUCTION_ENGINE_ENV = {
    # 来自 compose
    "SECURITY_PII_CHECKSUM_ENABLED": "true",
    "SECURITY_PII_CHECKSUM_DROP_INVALID": "true",
    "SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED": "true",
    "SECURITY_CONFIDENCE_GATING_ENABLED": "true",
    "SECURITY_SOURCE_AWARE_ENABLED": "true",
    "SECURITY_AUDIT_ONLY": "false",
    "SECURITY_FILE_CONTENT_DLP_ENABLED": "false",
    "SECURITY_FP_SUPPRESSION_ENABLED": "false",
    # 例外：测试环境没有模型服务，语义级联与分类器关闭，靠 AI 判断的条目不实测
    "SECURITY_SEMANTIC_ENABLED": "false",
    "SECURITY_TIER1_ENABLED": "false",
    # compose 未设，生产取代码默认值（与生产一致，不是例外）：LLM 裁判模式默认 off，检测范围全开，其余能力默认关
    "SECURITY_LLM_JUDGE_MODE": "off",
    "SECURITY_INSPECT_USER_INPUT": "true",
    "SECURITY_INSPECT_MODEL_OUTPUT": "true",
    "SECURITY_INSPECT_BUILTIN_CONTEXT": "true",
    "SECURITY_INSPECT_HISTORY": "true",
    "SECURITY_INSPECT_TOOL_RESULTS": "true",
    "SECURITY_NORMALIZE_ENABLED": "false",
    "SECURITY_DECODE_RESCAN_ENABLED": "false",
    "SECURITY_AGENT_GUARD_ENABLED": "false",
    "SECURITY_LOWRESOURCE_ENABLED": "false",
    "SECURITY_MCP_POISON_JUDGE_ENABLED": "false",
}
TEST_ENV_EXCEPTIONS = {"SECURITY_SEMANTIC_ENABLED", "SECURITY_TIER1_ENABLED"}
NOT_IN_COMPOSE = {
    "SECURITY_LLM_JUDGE_MODE", "SECURITY_INSPECT_USER_INPUT", "SECURITY_INSPECT_MODEL_OUTPUT",
    "SECURITY_INSPECT_BUILTIN_CONTEXT", "SECURITY_INSPECT_HISTORY", "SECURITY_INSPECT_TOOL_RESULTS",
    "SECURITY_NORMALIZE_ENABLED", "SECURITY_DECODE_RESCAN_ENABLED", "SECURITY_AGENT_GUARD_ENABLED",
    "SECURITY_LOWRESOURCE_ENABLED", "SECURITY_MCP_POISON_JUDGE_ENABLED",
}


# compose 未设的开关由引擎里哪个函数读：on = is_enabled_default_on（默认开），off = is_enabled（默认关），
# mode = feature_flags.llm_judge_mode()（只读环境变量，默认 off）
CODE_DEFAULT_READERS = {
    "SECURITY_LLM_JUDGE_MODE": "mode",
    "SECURITY_INSPECT_USER_INPUT": "on",
    "SECURITY_INSPECT_MODEL_OUTPUT": "on",
    "SECURITY_INSPECT_BUILTIN_CONTEXT": "on",
    "SECURITY_INSPECT_HISTORY": "on",
    "SECURITY_INSPECT_TOOL_RESULTS": "on",
    "SECURITY_NORMALIZE_ENABLED": "off",
    "SECURITY_DECODE_RESCAN_ENABLED": "off",
    "SECURITY_AGENT_GUARD_ENABLED": "off",
    "SECURITY_LOWRESOURCE_ENABLED": "off",
    "SECURITY_MCP_POISON_JUDGE_ENABLED": "off",
}


def _isolate_overrides(monkeypatch) -> None:
    monkeypatch.setattr(feature_flags, "_OVERRIDES", dict(feature_flags.snapshot_overrides()))
    feature_flags.apply_overrides({})


def _engine(monkeypatch) -> SecurityEngine:
    _isolate_overrides(monkeypatch)
    for name, value in PRODUCTION_ENGINE_ENV.items():
        monkeypatch.setenv(name, value)
    return SecurityEngine()


def _compose_engine_defaults() -> dict:
    return _parse_compose_defaults(COMPOSE_FILE.read_text(encoding="utf-8"))


def _parse_compose_defaults(text: str) -> dict:
    lines = text.splitlines()
    start = lines.index("  security-engine:")
    defaults = {}
    for line in lines[start + 1:]:
        if re.match(r"^  \S", line):
            break
        match = re.match(r"^\s*-\s*\"?([A-Z0-9_]+)=\$\{\1:-([^}]*)\}\"?\s*$", line)
        if match:
            defaults[match.group(1)] = match.group(2)
    return defaults


def test_production_engine_env_matches_compose():
    compose = _compose_engine_defaults()
    assert compose["SECURITY_PII_CHECKSUM_ENABLED"] == "true"
    for name, value in PRODUCTION_ENGINE_ENV.items():
        if name in NOT_IN_COMPOSE:
            assert name not in compose, f"{name} 现在 compose 里有了，请改用 compose 的默认值"
        elif name in TEST_ENV_EXCEPTIONS:
            continue
        else:
            assert compose.get(name) == value, f"{name}：测试用 {value!r}，compose 默认 {compose.get(name)!r}"
    for name in TEST_ENV_EXCEPTIONS - NOT_IN_COMPOSE:
        assert name in compose


def test_compose_parser_accepts_quoted_entries():
    text = "services:\n  security-engine:\n    environment:\n      - A=${A:-1}\n      - \"B=${B:-two}\"\n  other:\n    - C=${C:-3}\n"
    assert _parse_compose_defaults(text) == {"A": "1", "B": "two"}


def test_flags_missing_from_compose_equal_code_defaults(monkeypatch):
    _isolate_overrides(monkeypatch)
    for name in NOT_IN_COMPOSE:
        monkeypatch.delenv(name, raising=False)
    assert set(CODE_DEFAULT_READERS) == NOT_IN_COMPOSE
    for name, reader in CODE_DEFAULT_READERS.items():
        value = PRODUCTION_ENGINE_ENV[name]
        if reader == "mode":
            assert feature_flags.llm_judge_mode() == value, name
        else:
            read = feature_flags.is_enabled_default_on if reader == "on" else feature_flags.is_enabled
            assert read(name) == (value == "true"), f"{name}：测试用 {value!r}，引擎代码默认不同"


def test_consistency_path_ignores_control_plane_overrides(monkeypatch):
    original = feature_flags.snapshot_overrides()
    monkeypatch.setattr(feature_flags, "_OVERRIDES", {"SECURITY_INSPECT_USER_INPUT": "false"})
    engine = _engine(monkeypatch)
    result = engine.check_input("doc-override", "-----BEGIN RSA PRIVATE KEY-----", content_source="user")
    assert "ssh_private_key" in {finding.category for finding in result.findings}
    assert feature_flags.snapshot_overrides() == {}
    monkeypatch.undo()
    assert feature_flags.snapshot_overrides() == original


def test_openssh_doc_does_not_claim_two_alerts():
    assert "两条告警" not in load_capability_docs()["openssh_private_key"].matches


def test_checksum_invalid_id_number_is_not_reported_under_production_flags(monkeypatch):
    engine = _engine(monkeypatch)
    result = engine.check_input("doc-checksum", "110101199001011234", content_source="user")
    assert {finding.category for finding in result.findings} == set()


def _entry(**overrides):
    entry = {
        "category": "demo_key", "display": "credential", "matches": "演示用。",
        "hit_examples": ["demo-AAAA1111"], "miss_examples": ["普通句子"],
        "judged_by_ai": False, "check": "input",
    }
    entry.update(overrides)
    return entry


def test_shipped_docs_load():
    docs = load_capability_docs()
    assert "ssh_private_key" in docs
    assert docs["ssh_private_key"].display == "marker"
    assert display_kind("ssh_private_key") == "marker"
    assert display_kind("no_such_capability") is None


@pytest.mark.parametrize(
    "bad,reason",
    [
        (_entry(display="loud"), "display"),
        (_entry(matches=""), "matches"),
        (_entry(matches="长" * 201), "matches"),
        (_entry(hit_examples=[]), "hit_examples"),
        (_entry(hit_examples=["x"] * 4), "hit_examples"),
        (_entry(miss_examples=[]), "miss_examples"),
        (_entry(judged_by_ai=True), "check"),
        (_entry(check="sometimes"), "check"),
        (_entry(hit_examples=["x" * 301]), "hit_examples"),
        (_entry(display=["marker"]), "display"),
        (_entry(display={"a": 1}), "display"),
        (_entry(check=["input"]), "check"),
        (_entry(check={"a": 1}), "check"),
        (_entry(category=["demo"]), "category"),
        (_entry(category=" demo_key"), "category"),
        (_entry(category="   "), "category"),
        (_entry(matches=" 演示用。"), "matches"),
        (_entry(matches="演示用。 "), "matches"),
        (_entry(matches="   "), "matches"),
        (_entry(hit_examples=[" demo"]), "hit_examples"),
        (_entry(hit_examples=["demo "]), "hit_examples"),
        (_entry(hit_examples=["  "]), "hit_examples"),
        (_entry(miss_examples=[" x"]), "miss_examples"),
        (_entry(miss_examples=["  "]), "miss_examples"),
        (_entry(hit_examples=["a", "a"]), "重复"),
        (_entry(miss_examples=["a", "a"]), "重复"),
        (_entry(hit_examples=["a"], miss_examples=["a"]), "重复"),
        (dict(_entry(), extra_field=1), "extra_field"),
        ({k: v for k, v in _entry().items() if k != "matches"}, "matches"),
        ("demo_key", "demo.json"),
        (None, "demo.json"),
        (7, "demo.json"),
    ],
)
def test_parse_rejects_invalid_entries(bad, reason):
    with pytest.raises(CapabilityDocError) as error:
        parse_docs({"demo.json": json.dumps([bad])})
    assert reason in str(error.value)


def test_parse_rejects_json_syntax_error_with_file_name():
    with pytest.raises(CapabilityDocError) as error:
        parse_docs({"broken.json": "[{"})
    assert "broken.json" in str(error.value)


def test_loaded_docs_are_read_only():
    with pytest.raises(TypeError):
        load_capability_docs()["x"] = None


def test_parse_rejects_duplicate_category_across_files():
    with pytest.raises(CapabilityDocError) as error:
        parse_docs({"a.json": json.dumps([_entry()]), "b.json": json.dumps([_entry()])})
    assert "demo_key" in str(error.value)


def test_ai_judged_entry_needs_no_miss_example():
    docs = parse_docs({"demo.json": json.dumps([_entry(judged_by_ai=True, check="none", miss_examples=[])])})
    assert docs["demo_key"].judged_by_ai is True


def _checked_docs():
    return [doc for doc in load_capability_docs().values() if doc.check != "none"]


@pytest.mark.parametrize("doc", _checked_docs(), ids=lambda doc: doc.category)
def test_examples_agree_with_the_engine(doc, monkeypatch):
    engine = _engine(monkeypatch)

    def findings(text: str, index: int):
        request_id = f"doc-{doc.category}-{index}"
        if doc.check == "output":
            result = engine.check_output(request_id, text)
        else:
            result = engine.check_input(request_id, text, content_source="user")
        return [finding for finding in result.findings if finding.category == doc.category]

    for index, example in enumerate(doc.hit_examples):
        found = findings(example, index)
        assert found, f"说明写着会命中，引擎没有该类别的 finding：{example!r}"
        assert any(f.counts_as_security_finding for f in found), (
            f"说明写着会命中，引擎只留证、不计入告警（counts_as_security_finding 为假）：{example!r}"
        )
    for index, example in enumerate(doc.miss_examples):
        assert not findings(example, 100 + index), f"说明写着不会命中，引擎出了该类别的 finding：{example!r}"


def test_docs_dir_is_inside_the_app_package():
    assert capability_docs.DOCS_DIR.is_dir()
    assert "app" in capability_docs.DOCS_DIR.parts
