"""引擎 ↔ 网关契约：「仅记录」类观察的 finding 形态。

网关只对 disposition=observation 且 disposition_reason 属于
{policy_semantic_observe, quoted_profanity_reference, bare_profanity_reference} 的观察
单独写一条观察事件（gateway-core chat_fingerprint_cache.go retainedObservationReasons）。
这里锁住引擎侧的标记，改名会让观察事件再次丢失。
"""
import pytest

from app import feature_flags
from app.detectors.engine import SecurityEngine, SecurityFinding
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet

RETAINED = {"policy_semantic_observe", "quoted_profanity_reference", "bare_profanity_reference"}


def _policy(category, *, action="audit", semantic_action="audit"):
    return CompiledPolicy(
        policy_code=f"p.{category}", policy_id=f"id.{category}", policy_name="策略",
        policy_type="scene_policy", scene="content_safety", action=action, semantic_action=semantic_action,
        enabled=True, binding_mode="any",
        capabilities=[CompiledPolicyCapability(category=category, supported_stages=["input", "output"],
                                               allowed_actions=["audit", "block"], mask_capable=False)],
    )


def _assert_retained(finding):
    assert finding.counts_as_security_finding is False
    assert finding.action == "allow"
    assert finding.triage["disposition"] == "observation"
    assert finding.triage["disposition_reason"] in RETAINED
    assert finding.raw_evidence or finding.redacted_evidence


def test_policy_semantic_observe_marks_retained_observation():
    finding = SecurityFinding(
        type="semantic_attack", category="prompt_input_semantic_risk", severity="high", confidence=0.9,
        rule_id="semantic_prompt_input_semantic_risk", rule_name="语义攻击·上下文语义风险", rule_type="semantic",
        matched_text_preview="prompt_input_semantic_risk:input", matched_location="content[0:8]",
        redacted_evidence="语义裁判判定：上下文语义风险（malicious）",
        triage={"semantic_run_status": "completed"},
    )
    policies = PolicySet([_policy("semantic_jailbreak", semantic_action="observe")])
    [observed] = policies.apply([finding], stage="input")
    _assert_retained(observed)
    assert observed.triage["disposition_reason"] == "policy_semantic_observe"
    assert observed.policy_code == "p.semantic_jailbreak"


@pytest.mark.parametrize("text", ["请把脏话“傻逼”翻译成英文", "“傻逼”这个词是脏话吗"])
@pytest.mark.parametrize("bound", [False, True])
def test_profanity_discussion_marks_retained_observation(text, bound):
    feature_flags.apply_overrides({})
    engine = SecurityEngine()
    if bound:  # 内置辱骂策略配置为阻断：讨论类仍只观察
        engine.load_policies(PolicySet([_policy("content_profanity_abuse", action="block")]))
    result = engine.check_input("req-profanity-discussion", text, skip_semantic=True)
    profanity = [f for f in result.findings if f.category == "content_profanity_abuse"]
    assert profanity, result.findings
    _assert_retained(profanity[0])
    assert result.action != "block"
