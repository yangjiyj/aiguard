"""openai/anthropic sk- 密钥占位符识别：真钥仍 high_risk 命中 + 示例占位不再误报。"""
from pathlib import Path

from app.detectors.engine import SecurityEngine

eng = SecurityEngine()


def _ids(text):
    return {f.rule_id for f in eng.check_input("r-sk", text).findings}


def test_real_openai_key_still_fires():
    # 真实形态密钥（高熵）仍命中
    assert "secret_openai_key" in _ids("key: sk-proj-Ab3Xy9Qr7Tz2Kw8Lm4Np6Vd1Fh5Jc0")


def test_real_anthropic_key_still_fires():
    # anthropic 真钥（高熵）仍命中，占位守卫不误伤真攻击样本
    assert "secret_anthropic_key" in _ids(
        "ANTHROPIC_API_KEY=sk-ant-api03-Ab3Xy9Qr7Tz2Kw8Lm4Np6Vd1Fh5Jc0aB"
    )


def test_placeholder_sk_xxx_no_longer_fires():
    assert "secret_openai_key" not in _ids("export OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxx")


def test_placeholder_sk_your_key_no_longer_fires():
    assert "secret_openai_key" not in _ids("set your key: sk-your-api-key-here-placeholder")


def test_cc_system_prompt_placeholder_no_longer_fires():
    # Claude Code / 开发场景系统提示词里的示例占位符不再误报
    assert "secret_openai_key" not in _ids(
        "In your config set OPENAI_API_KEY to sk-your-key-here and restart the agent."
    )


# --- 反规避：真钥被"占位词前缀"伪装时占位守卫不能放行（否则成外泄绕过通道）---


def test_real_key_disguised_with_test_prefix_still_fires():
    # 攻击者把真钥体拼在 test- 前缀后，占位守卫不能吞掉它
    assert "secret_openai_key" in _ids("sk-test-Ab3Xy9Qr7Tz2Kw8Lm4Np6Vd1Fh5Jc0")


def test_real_key_disguised_with_example_prefix_still_fires():
    assert "secret_openai_key" in _ids("sk-example-Ab3Xy9Qr7Tz2Kw8Lm4Np6Vd1Fh5Jc0")


def test_real_key_disguised_with_your_prefix_still_fires():
    assert "secret_openai_key" in _ids("sk-your-Ab3Xy9Qr7Tz2Kw8Lm4Np6Vd1Fh5Jc0")


def test_real_key_disguised_with_xxx_prefix_still_fires():
    assert "secret_openai_key" in _ids("token=sk-xxxAb3Xy9Qr7Tz2Kw8Lm4Np6Vd1Fh5Jc0")


def test_real_anthropic_key_disguised_with_test_prefix_still_fires():
    assert "secret_anthropic_key" in _ids("sk-ant-test-Ab3Xy9Qr7Tz2Kw8Lm4Np6Vd1Fh5Jc0")


# --- README 常见占位短语（纯字母多词、无数字）不误报，但不放松到能藏真钥 ---


def test_readme_multiword_placeholder_no_digit_no_fire():
    # 无数字、多段短词的英文占位短语（真钥必含数字，故不会藏真钥）
    assert "secret_openai_key" not in _ids("OPENAI_API_KEY=sk-your-openai-api-key-here")


def test_readme_replace_me_placeholder_no_fire():
    assert "secret_openai_key" not in _ids("sk-replace-me-with-your-key")


def test_multiword_shape_with_long_random_segment_still_fires():
    # 多词外形但中间夹一段长随机串（>12 字符）不放松，仍按真钥告警
    assert "secret_openai_key" in _ids("sk-my-QrTzKwLmNpVdFhJcSsRpWqUvBg-here")


def _finding_for_coding_tool_result(text, rule_id):
    engine = SecurityEngine()
    result = engine.check_input(
        "r-coding-tool-placeholder",
        text,
        context={"agent_type": "openai-codex"},
        agent_type="openai-codex",
        content_source="tool_result",
    )
    return result, next((f for f in result.findings if f.rule_id == rule_id), None)


def test_official_aws_example_in_coding_tool_result_is_observation(monkeypatch):
    monkeypatch.setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "true")
    result, finding = _finding_for_coding_tool_result(
        "test fixture uses AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "secret_aws_access_key",
    )
    assert finding is not None
    assert finding.counts_as_security_finding is False
    assert finding.triage["disposition_reason"] == "coding_context_placeholder_secret"
    assert result.action == "allow"


def test_repeated_aws_placeholder_in_coding_tool_result_is_observation(monkeypatch):
    # 线上 Codex 工具结果里的明显重复占位符，不应形成极高危凭据告警。
    monkeypatch.setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "true")
    result, finding = _finding_for_coding_tool_result(
        "tool output contains ASIAESIAESIAESIAESIA",
        "secret_aws_access_key",
    )
    assert finding is not None
    assert finding.counts_as_security_finding is False
    assert finding.triage["disposition_reason"] == "coding_context_placeholder_secret"
    assert result.action == "allow"


def test_real_aws_key_in_coding_tool_result_is_not_source_exempt(monkeypatch):
    monkeypatch.setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "true")
    result, finding = _finding_for_coding_tool_result(
        "leaked AWS_ACCESS_KEY_ID=AKIA" "4B7C9D2E8F6G1H3J",
        "secret_aws_access_key",
    )
    assert finding is not None
    assert finding.cannot_downgrade()
    assert finding.counts_as_security_finding is True
    assert finding.action != "allow"
    assert finding.triage.get("disposition") != "observation"
    assert result.action == "audit"
def test_sequential_live_fixture_no_longer_fires():
    # A recognizable Codex/IDE fixture value is not a real random credential.
    assert "secret_openai_key" not in _ids(
        "OPENAI_API_KEY=sk-live1234567890ABCDEF"
    )


def test_teststream_alphabet_fixture_no_longer_fires():
    """验收/流式测试使用的固定字母序列不是 OpenAI 生产密钥。"""
    assert "secret_openai_key" not in _ids(
        "without explanation: sk-teststreamABCDEFGHIJKLMNOPQRST"
    )


def test_sample_numeric_sequence_fixture_no_longer_fires():
    """不是只豁免某一条固定测试串，其他明显合成序列也按占位数据处理。"""
    assert "secret_openai_key" not in _ids(
        "sample credential: sk-sample-01234567890123456789"
    )


def test_bare_alphabet_numeric_sequence_fixture_no_longer_fires():
    assert "secret_openai_key" not in _ids(
        "const secret = 'sk-abcdefghijklmnopqrstuvwxyz123456'"
    )


def test_test_prefix_with_random_body_still_fires_after_sequence_generalization():
    """测试语义只能辅助确认低熵序列，不能掩盖高熵真钥体。"""
    assert "secret_openai_key" in _ids(
        "sample credential: sk-test-Ab3Xy9Qr7Tz2Kw8Lm4Np6Vd1Fh5Jc0"
    )


def test_project_fixture_real_secret_shape_remains_active(monkeypatch):
    """A fixture path cannot exempt a high-entropy threat credential shape."""
    monkeypatch.setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "true")

    fixture = (
        Path(__file__).resolve().parents[3]
        / "scripts"
        / "security"
        / "fp_reduction_report.py"
    )
    result, finding = _finding_for_coding_tool_result(
        fixture.read_text(encoding="utf-8"),
        "secret_openai_key",
    )

    assert finding is not None
    assert finding.cannot_downgrade()
    assert finding.counts_as_security_finding is True
    assert finding.action != "allow"
    assert finding.triage.get("disposition") != "observation"
    assert result.action == "audit"
