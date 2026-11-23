"""模板文件（.env.example 等）不再按路径触发网关安全底线后，内容兜底仍然成立。

网关只凭文件名把 .env.example 视为模板；若模板里实际写了真实密钥，Read 的工具结果
在回传模型前以 content_source=tool_result 进入输入检测，这里锁定该兜底：
真实格式的密钥照常是安全发现，文件名/路径里的 example 字样不构成豁免；
只有占位符的模板不产生安全发现。
"""

from app import feature_flags
from app.detectors.engine import SecurityEngine

TEMPLATE_PATH = "/home/workspace/devhub-agent-platform/agent-eval/.env.example"
AWS_KEY = "AKIA" + "4B7C9D2E8F6G1H3J"
OPENAI_KEY = "sk-" + "proj" + "Qm7Lw2Xz9Vb4Nc8Rt6Yh3Kp5Jd1Sg0Fa"
OPENSSH_KEY = (
    "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "-----END OPENSSH " + "PRIVATE KEY-----"
)


def _engine(monkeypatch):
    feature_flags.apply_overrides({})
    monkeypatch.setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "true")
    monkeypatch.delenv("SECURITY_AUDIT_ONLY", raising=False)
    monkeypatch.delenv("SECURITY_CONFIDENCE_GATING_ENABLED", raising=False)
    return SecurityEngine()


def _read_result(*lines):
    # Claude Code Read 工具结果形态：行号 + 制表符。
    body = [f"# {TEMPLATE_PATH}", *lines]
    return "\n".join(f"{index:6d}\t{line}" for index, line in enumerate(body, start=1))


def _security_findings(result):
    return {f.rule_id: f for f in result.findings if f.counts_as_security_finding}


def test_real_keys_inside_env_example_tool_result_remain_findings(monkeypatch):
    engine = _engine(monkeypatch)
    result = engine.check_input(
        "req-env-example-real-keys",
        _read_result(f"AWS_ACCESS_KEY_ID={AWS_KEY}", f"OPENAI_API_KEY={OPENAI_KEY}"),
        context={"agent_type": "claude-code"},
        agent_type="claude-code",
        content_source="tool_result",
    )
    findings = _security_findings(result)
    assert findings["secret_aws_access_key"].severity == "critical"
    assert findings["secret_openai_key"].severity == "critical"
    assert result.action != "allow"


def test_private_key_inside_env_example_tool_result_remains_finding(monkeypatch):
    engine = _engine(monkeypatch)
    result = engine.check_input(
        "req-env-example-private-key",
        _read_result(f'SSH_KEY="{OPENSSH_KEY}"'),
        context={"agent_type": "claude-code"},
        agent_type="claude-code",
        content_source="tool_result",
    )
    findings = _security_findings(result)
    assert "code_openssh_private_key" in findings
    assert findings["code_openssh_private_key"].severity == "critical"


def test_placeholder_only_env_example_is_not_a_security_finding(monkeypatch):
    engine = _engine(monkeypatch)
    result = engine.check_input(
        "req-env-example-placeholders",
        _read_result("AWS_ACCESS_KEY_ID=your-access-key-id", "OPENAI_API_KEY=sk-xxxx", "DB_PASSWORD="),
        context={"agent_type": "claude-code"},
        agent_type="claude-code",
        content_source="tool_result",
    )
    assert _security_findings(result) == {}
