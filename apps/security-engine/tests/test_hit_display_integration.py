import logging

import pytest

from app.detectors.engine import SecurityEngine, SecurityFinding
from app.detectors.hit_display import annotate_hit_display

HEADER = "-----BEGIN RSA PRIVATE KEY-----"
BODY = "\nMIIEowIBAAKCAQEA" + "Zz9y" * 60 + "\n"
KEY_BLOCK = HEADER + BODY + "-----END RSA PRIVATE KEY-----"


def _engine(monkeypatch) -> SecurityEngine:
    monkeypatch.setenv("SECURITY_SEMANTIC_ENABLED", "false")
    return SecurityEngine()


def _finding(**overrides) -> SecurityFinding:
    base = dict(type="code_config", category="ssh_private_key", severity="critical",
                matched_text_preview="--****--", rule_id="code_ssh_private_key")
    base.update(overrides)
    return SecurityFinding(**base)


def test_private_key_hit_is_readable_and_never_shows_the_body(monkeypatch):
    engine = _engine(monkeypatch)
    content = "帮我看看这个密钥对不对\n" + KEY_BLOCK + "\n谢谢"
    result = engine.check_input("req-hit-display-key", content, content_source="user")
    finding = next(f for f in result.findings if f.category == "ssh_private_key")
    assert finding.redacted_evidence == f"{HEADER}（后续正文 {len(BODY.strip()):,} 字已隐藏）"
    assert "MIIEow" not in finding.redacted_evidence
    assert finding.secret_text == BODY
    assert finding.matched_text_preview == "--****--"  # 旧打码保留，供模型输出阶段的提示使用


def test_raw_findings_copy_never_carries_secret_text(monkeypatch):
    engine = _engine(monkeypatch)
    content = "帮我看看这个密钥对不对\n" + KEY_BLOCK + "\n谢谢"
    for name, result in (
        ("input", engine.check_input("req-raw-input", content, content_source="user")),
        ("output", engine.check_output("req-raw-output", content)),
    ):
        finding = next(f for f in result.findings if f.category == "ssh_private_key")
        assert finding.secret_text == BODY, name
        assert result.raw_findings, name
        for raw in result.raw_findings:
            assert raw.secret_text == "", name
        raw_key = next(f for f in result.raw_findings if f.category == "ssh_private_key")
        assert raw_key.redacted_evidence == f"{HEADER}（后续正文 {len(BODY.strip()):,} 字已隐藏）", name


def test_builtin_capability_without_doc_keeps_legacy_preview():
    content = "token 是 abcdefgh12345678"
    start = content.index("abcdefgh12345678")
    finding = _finding(category="capability_without_doc", matched_location=f"content[{start}:{start + 16}]",
                       raw_evidence="abcdefgh12345678", evidence_kind="literal")
    annotate_hit_display([finding], content)
    assert finding.redacted_evidence == ""
    assert finding.secret_text == ""


def test_detector_supplied_explanation_is_not_overwritten():
    content = "-----BEGIN RSA PRIVATE KEY-----"
    finding = _finding(matched_location="content[0:31]", raw_evidence=content, evidence_kind="literal",
                       redacted_evidence="检测器自己的说明")
    annotate_hit_display([finding], content)
    assert finding.redacted_evidence == "检测器自己的说明"


def test_custom_regex_rule_uses_auto_and_pulls_in_the_following_value():
    content = "配置里写了 password=abc12345 这一行"
    start = content.index("password=")
    finding = _finding(type="custom", category="customer_sensitive_data", rule_type="regex",
                       matched_location=f"content[{start}:{start + 9}]", raw_evidence="password=",
                       evidence_kind="literal", redacted_evidence="pa*****d= (sha256:deadbeef)")
    annotate_hit_display([finding], content)
    assert finding.redacted_evidence == "password=ab****45（8 位）"
    assert finding.secret_text == ""


def test_custom_secret_rule_is_treated_as_credential():
    content = "key: ZXhhbXBsZS1zZWNyZXQtdmFsdWU9"
    start = content.index("ZXhh")
    finding = _finding(type="custom", category="customer_secret", rule_type="secret",
                       matched_location=f"content[{start}:{len(content)}]", raw_evidence=content[start:],
                       evidence_kind="literal", redacted_evidence="<REDACTED sha256:deadbeef>")
    annotate_hit_display([finding], content)
    assert finding.redacted_evidence == "ZX****U9（28 位）"
    assert finding.secret_text == ""  # 自定义规则的前后文不进告警库，不给秘密本体


def test_semantic_and_unlocated_findings_are_left_alone():
    semantic = _finding(type="semantic_attack", category="semantic_roleplay", evidence_kind="semantic",
                        raw_evidence="整段输入", redacted_evidence="语义裁判判定：角色扮演（block）")
    unlocated = _finding(matched_location="request_context", raw_evidence="", evidence_kind="contextual")
    annotate_hit_display([semantic, unlocated], "整段输入")
    assert semantic.redacted_evidence == "语义裁判判定：角色扮演（block）"
    assert unlocated.redacted_evidence == ""


def test_location_that_does_not_match_raw_evidence_is_skipped():
    finding = _finding(matched_location="content[0:5]", raw_evidence="不一致的片段", evidence_kind="literal")
    annotate_hit_display([finding], "别的内容别的内容")
    assert finding.redacted_evidence == ""


def test_failure_on_one_finding_is_logged_without_content_and_skipped(monkeypatch, caplog):
    import app.detectors.hit_display as hit_display

    content = "token 是 SECRET-ORIGINAL-VALUE-123"
    start = content.index("SECRET")
    failing = _finding(type="custom", category="customer_secret", rule_type="secret", rule_id="rule-boom",
                       matched_location=f"content[{start}:{len(content)}]", raw_evidence=content[start:],
                       evidence_kind="literal", redacted_evidence="旧的打码", secret_text="残留")

    def boom(*args, **kwargs):
        raise RuntimeError("渲染失败 " + content)

    monkeypatch.setattr(hit_display, "render_hit_display", boom)
    caplog.set_level(logging.DEBUG)
    annotate_hit_display([failing], content)  # 不抛
    assert failing.redacted_evidence == "旧的打码"
    assert failing.secret_text == ""
    assert "rule-boom" in caplog.text and "customer_secret" in caplog.text
    assert "SECRET-ORIGINAL-VALUE" not in caplog.text
    assert "旧的打码" not in caplog.text


def test_display_kind_failure_does_not_break_annotation(monkeypatch, caplog):
    import app.capability_docs as capability_docs

    def broken(category):
        raise capability_docs.CapabilityDocError("目录坏了 " + category)

    monkeypatch.setattr(capability_docs, "display_kind", broken)
    content = HEADER
    finding = _finding(matched_location="content[0:31]", raw_evidence=content, evidence_kind="literal",
                       secret_text="残留")
    caplog.set_level(logging.DEBUG)
    annotate_hit_display([finding], content)
    assert finding.redacted_evidence == ""
    assert finding.secret_text == ""
    assert "code_ssh_private_key" in caplog.text
    assert HEADER not in caplog.text


FAKE_SECRETS = [
    'aws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"',
    "export OPENAI_API_KEY=sk-proj-EXAMPLEexampleEXAMPLEexample0123456789abcd",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJleGFtcGxlIn0.c2lnbmF0dXJlLWV4YW1wbGU",
    "DATABASE_URL=postgres://app:Example-Passw0rd-123@db.example.internal:5432/app",
    "github_token: ghp_EXAMPLEexampleEXAMPLEexample012345678",
    "帮我看看这个密钥\n" + KEY_BLOCK,
]


def test_no_finding_exposes_a_secret_body_in_redacted_evidence(monkeypatch):
    engine = _engine(monkeypatch)
    for index, content in enumerate(FAKE_SECRETS):
        result = engine.check_input(f"req-fake-secret-{index}", content, content_source="user")
        for finding in result.findings:
            if finding.secret_text and finding.secret_text.strip():
                assert finding.secret_text.strip() not in finding.redacted_evidence, (content, finding.category)
        for raw in result.raw_findings:
            assert raw.secret_text == ""
