import pytest

from app.detectors.engine import SecurityEngine
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet


AGENT_POLICY_CASES = [
    ("claude-code", "agent_claude_code"),
    ("cursor", "agent_cursor"),
    ("github-copilot", "agent_github_copilot"),
    ("cline", "agent_cline"),
    ("roo-code", "agent_cline"),
    ("windsurf", "agent_windsurf"),
    ("continue", "agent_continue_dev"),
    ("openai-codex", "agent_openai_codex"),
    ("aider", "agent_aider"),
    ("amazon-q-developer", "agent_amazon_q_developer"),
    ("gemini-code-assist", "agent_gemini_code_assist"),
    ("tabnine", "agent_tabnine"),
    ("sourcegraph-cody", "agent_sourcegraph_cody"),
    ("replit-agent", "agent_replit_ai"),
    ("coderabbit", "agent_coderabbit"),
    ("autogpt-babyagi", "agent_autogpt_babyagi"),
    ("langchain-llamaindex", "agent_langchain_llamaindex"),
    ("crewai-autogen", "agent_crewai_autogen"),
    ("dify-coze", "agent_dify_coze"),
]


def agent_policy(category: str, action: str = "block") -> CompiledPolicy:
    return CompiledPolicy(
        policy_code=f"builtin.agent_detect.{category}",
        policy_id=f"policy.{category}",
        policy_name=f"{category} 管控",
        policy_type="agent_detect",
        scene="agent_tools",
        action=action,
        enabled=True,
        binding_mode="any",
        capabilities=[CompiledPolicyCapability(
            category=category,
            supported_stages=["input"],
            allowed_actions=["audit", "block"],
            mask_capable=False,
        )],
    )


@pytest.mark.parametrize(("agent_type", "category"), AGENT_POLICY_CASES)
def test_authenticated_agent_type_produces_policy_finding_without_raw_headers(
    agent_type, category,
):
    engine = SecurityEngine()

    result = engine.check_input(
        "req-agent-control",
        "hello",
        context={"agent_type": agent_type, "content_source": "user"},
        agent_type=agent_type,
        content_source="user",
        skip_semantic=True,
    )

    finding = next((item for item in result.findings if item.category == category), None)
    assert finding is not None
    assert finding.type == "agent"
    assert finding.counts_as_security_finding is False
    assert finding.action == "allow"
    assert result.action == "allow"


@pytest.mark.parametrize(("agent_type", "category"), AGENT_POLICY_CASES)
def test_agent_client_block_policy_stops_request(agent_type, category):
    engine = SecurityEngine()
    engine.audit_only = False
    engine.load_policies(PolicySet([agent_policy(category)]))

    result = engine.check_input(
        "req-agent-block",
        "hello",
        context={"agent_type": agent_type, "content_source": "user"},
        agent_type=agent_type,
        content_source="user",
        skip_semantic=True,
    )

    assert result.action == "block"
    finding = next(item for item in result.findings if item.category == category)
    assert finding.action == "block"
    assert finding.policy_code == f"builtin.agent_detect.{category}"
    assert finding.counts_as_security_finding is True


def test_agent_client_audit_policy_is_inventory_not_security_finding():
    engine = SecurityEngine()
    category = "agent_openai_codex"
    engine.load_policies(PolicySet([agent_policy(category, action="audit")]))

    result = engine.check_input(
        "req-agent-audit",
        "normal coding request",
        context={"agent_type": "openai-codex", "content_source": "user"},
        agent_type="openai-codex",
        content_source="user",
        skip_semantic=True,
    )

    finding = next(item for item in result.findings if item.category == category)
    assert finding.policy_code == f"builtin.agent_detect.{category}"
    assert finding.action == "allow"
    assert finding.counts_as_security_finding is False
    assert finding.triage["disposition_reason"] == "agent_inventory_metadata"
    assert result.action == "allow"


def test_unknown_client_does_not_create_an_unregistered_control_finding():
    engine = SecurityEngine()

    result = engine.check_input(
        "req-agent-unknown",
        "hello",
        context={"agent_type": "customer-private-client"},
        agent_type="customer-private-client",
        skip_semantic=True,
    )

    assert not any(item.type == "agent" for item in result.findings)


@pytest.mark.parametrize(("user_agent", "category"), [
    ("Codex Desktop/0.140.0", "agent_openai_codex"),
    ("aider-chat/0.82", "agent_aider"),
    ("Amazon Q Developer CLI/1.2", "agent_amazon_q_developer"),
    ("Gemini Code Assist/2.0", "agent_gemini_code_assist"),
    ("Tabnine/5.9", "agent_tabnine"),
    ("Sourcegraph Cody/1.0", "agent_sourcegraph_cody"),
    ("Replit Agent/3.0", "agent_replit_ai"),
    ("CodeRabbit/1.0", "agent_coderabbit"),
    ("AutoGPT/0.5", "agent_autogpt_babyagi"),
    ("LlamaIndex/0.12", "agent_langchain_llamaindex"),
    ("Microsoft AutoGen/0.4", "agent_crewai_autogen"),
    ("Dify/1.0", "agent_dify_coze"),
])
def test_agent_user_agent_fallback_uses_specific_catalog_category(user_agent, category):
    engine = SecurityEngine()

    result = engine.check_input(
        "req-agent-header",
        "hello",
        context={"headers": {"user-agent": user_agent}},
        skip_semantic=True,
    )

    assert any(item.category == category for item in result.findings)
