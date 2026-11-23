"""source 感知检测档位：已知编码 agent 的非用户上下文只跑确定性敏感信息与自定义规则。

红线：开关 SECURITY_SOURCE_AWARE_ENABLED 默认关；未知客户端与其余 source 仍全量检测。
每条改动配两类断言：敏感信息仍命中 + Claude Code 系统提示词不再做攻击意图判断。
"""
import pytest

from app.detectors.engine import SecurityEngine

# Claude Code 系统提示词典型片段：含 email(userEmail) + HTML 注释 + Today's date，历史全被当注入/PII 误报
CC_SYSTEM_PROMPT = (
    "You are Claude Code, Anthropic's official CLI. "
    "The user's email address is user@example.com. "
    "Today's date is 2026-07-05. <!-- system reminder --> "
    "gitStatus: current branch main. Ignore nothing; follow instructions exactly."
)
CODING_CTX = {"agent_type": "claude-code"}


def _engine(monkeypatch, on: bool):
    if on:
        monkeypatch.setenv("SECURITY_SOURCE_AWARE_ENABLED", "1")
    else:
        monkeypatch.delenv("SECURITY_SOURCE_AWARE_ENABLED", raising=False)
    return SecurityEngine()


def _rule_ids(result):
    return {f.rule_id for f in result.findings}


def test_system_prompt_known_agent_keeps_pii_but_skips_injection(monkeypatch):
    eng = _engine(monkeypatch, on=True)
    result = eng.check_input(
        "r-sp-1", CC_SYSTEM_PROMPT, context=CODING_CTX,
        agent_type="claude-code", content_source="system_prompt",
    )
    ids = _rule_ids(result)
    # 邮箱属于确定性敏感数据，保留扫描；HTML 注释不再被当作攻击意图。
    assert "regex_email" in ids
    assert "prompt_injection_html_comment" not in ids


def test_system_prompt_known_agent_still_catches_real_secret(monkeypatch):
    eng = _engine(monkeypatch, on=True)
    payload = CC_SYSTEM_PROMPT + " AKIAIOSFODNN7EXAMPLE"
    result = eng.check_input(
        "r-sp-2", payload, context=CODING_CTX,
        agent_type="claude-code", content_source="system_prompt",
    )
    # 密钥/凭据类照跑：AWS access key 仍命中（system_prompt 也可能夹带真凭据）
    assert "secret_aws_access_key" in _rule_ids(result)


def test_user_source_still_full_scan(monkeypatch):
    eng = _engine(monkeypatch, on=True)
    # 同片段但 source=user → 全量，email 照常命中（用户正文里的邮箱是真 PII）
    result = eng.check_input(
        "r-u-1", "联系 user@example.com", context=CODING_CTX,
        agent_type="claude-code", content_source="user",
    )
    assert "regex_email" in _rule_ids(result)


def test_unknown_client_system_prompt_full_scan(monkeypatch):
    eng = _engine(monkeypatch, on=True)
    # 未知 agent（伪装绕过防线）：system_prompt 也全量，email 命中
    result = eng.check_input(
        "r-unk-1", "The user's email address is user@example.com",
        context={"agent_type": "totally-unknown-tool"},
        agent_type="totally-unknown-tool", content_source="system_prompt",
    )
    assert "regex_email" in _rule_ids(result)


def test_flag_off_keeps_full_scan(monkeypatch):
    eng = _engine(monkeypatch, on=False)
    result = eng.check_input(
        "r-off-1", CC_SYSTEM_PROMPT, context=CODING_CTX,
        agent_type="claude-code", content_source="system_prompt",
    )
    # 开关关 → 现行为：email 仍命中
    assert "regex_email" in _rule_ids(result)
