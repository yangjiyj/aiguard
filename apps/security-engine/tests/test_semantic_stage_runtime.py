from __future__ import annotations

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app import feature_flags as ff
from app.api.check_input import CheckInputRequest, CheckInputResponse
from app.detectors.engine import SecurityEngine
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet


@pytest.fixture(autouse=True)
def _reset_runtime_overrides():
    ff.apply_overrides({})
    yield
    ff.apply_overrides({})


def _semantic_finding(stage: str) -> list[dict]:
    return [{
        "type": "semantic_attack",
        "category": "semantic_jailbreak",
        "severity": "high",
        "confidence": 0.9,
        "rule_id": "semantic_semantic_jailbreak",
        "rule_name": "语义攻击·越狱",
        "rule_type": "semantic",
        "matched_text_preview": f"semantic_jailbreak:{stage}",
        "matched_location": stage,
        "redacted_evidence": "语义裁判判定：越狱（malicious）",
    }]


def test_agent_stage_is_independent_from_input_stage(monkeypatch):
    monkeypatch.setenv(ff.ENV_SEMANTIC_ENABLED, "true")
    monkeypatch.setenv(ff.ENV_SEMANTIC_INPUT_ENABLED, "false")
    monkeypatch.setenv("SECURITY_SEMANTIC_AGENT_ENABLED", "true")
    engine = SecurityEngine()

    with patch.object(engine.semantic, "detect", side_effect=lambda _, stage, **kwargs: _semantic_finding(stage)) as detect:
        agent = engine.check_input(
            "agent-rid", "dangerous tool arguments", semantic_only=True, semantic_stage="agent",
            content_source="tool_result", context={"user_task": "inspect tool result"}
        )
        input_result = engine.check_input(
            "input-rid", "dangerous prompt", semantic_only=True, semantic_stage="input"
        )

    assert any(f.type == "semantic_attack" for f in agent.findings)
    assert all(f.type != "semantic_attack" for f in input_result.findings)
    detect.assert_called_once_with("dangerous tool arguments", "agent",
                                   content_source="tool_result",
                                   task_context={"user_task": "inspect tool result"})


def test_semantic_only_never_bypasses_master_switch(monkeypatch):
    monkeypatch.setenv(ff.ENV_SEMANTIC_ENABLED, "false")
    monkeypatch.setenv(ff.ENV_SEMANTIC_INPUT_ENABLED, "true")
    monkeypatch.setenv("SECURITY_SEMANTIC_AGENT_ENABLED", "true")
    engine = SecurityEngine()

    with patch.object(engine.semantic, "detect") as detect:
        result = engine.check_input(
            "rid", "dangerous prompt", semantic_only=True, semantic_stage="input"
        )

    detect.assert_not_called()
    assert all(f.type != "semantic_attack" for f in result.findings)


def test_api_response_exposes_the_applied_semantic_revision():
    assert "semantic_config_revision" in CheckInputResponse.model_fields


def test_unknown_semantic_stage_is_rejected_at_api_and_engine(monkeypatch):
    with pytest.raises(ValidationError):
        CheckInputRequest(request_id="rid", content="x", semantic_stage="output")

    engine = SecurityEngine()
    with pytest.raises(ValueError, match="semantic_stage"):
        engine.check_input("rid", "x", semantic_only=True, semantic_stage="output")


def test_request_uses_one_runtime_snapshot_across_hot_reload(monkeypatch):
    monkeypatch.setenv(ff.ENV_SEMANTIC_ENABLED, "false")
    monkeypatch.setenv(ff.ENV_AUDIT_ONLY, "false")
    engine = SecurityEngine()
    engine.load_policies(PolicySet([
        CompiledPolicy(
            policy_code="test.synthetic-critical",
            policy_id="policy.test.synthetic-critical",
            policy_name="请求快照测试策略",
            policy_type="scene_policy",
            scene="data_leak",
            action="block",
            enabled=True,
            binding_mode="any",
            capabilities=[
                CompiledPolicyCapability(
                    category="synthetic-critical",
                    supported_stages=["input"],
                    allowed_actions=["audit", "block"],
                    mask_capable=False,
                )
            ],
        )
    ]))
    engine.reconfigure_semantic(revision="old-revision")

    def flip_runtime_mid_request(_content: str):
        ff.apply_overrides({ff.ENV_AUDIT_ONLY: "true"})
        engine.reconfigure_semantic(revision="new-revision")
        return [{
            "type": "pii",
            "category": "synthetic-critical",
            "severity": "critical",
            "confidence": 1.0,
            "rule_id": "synthetic-critical",
            "matched_text_preview": "redacted",
        }]

    with patch.object(engine.prompt_injection, "detect", side_effect=flip_runtime_mid_request):
        result = engine.check_input("rid", "ordinary text")

    assert result.action == "block", "请求中途切到 audit-only 不得改变已抓取快照的动作"
    assert result.semantic_config_revision == "old-revision"
    assert engine.semantic_config_revision == "new-revision"
