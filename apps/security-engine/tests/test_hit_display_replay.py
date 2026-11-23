import logging
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import app.main as main_module
from app.detectors.engine import SecurityEngine, SecurityFinding
from app.detectors.hit_display import render_hit_display, restore_secret_text

HEADER = "-----BEGIN RSA PRIVATE KEY-----"
TAIL = "-----END RSA PRIVATE KEY-----"


def _key_block(chars: int) -> str:
    body = "MIIEowIBAAKCAQEA" + ("Zz9y" * (chars // 4 + 1))
    return HEADER + "\n" + body[:chars] + "\n" + TAIL


def _engine(monkeypatch) -> SecurityEngine:
    monkeypatch.setenv("SECURITY_SEMANTIC_ENABLED", "false")
    return SecurityEngine()


def _replay(raw_findings):
    client = TestClient(main_module.app)
    response = client.post(
        "/apply-context/",
        headers={"X-JJD-Want-Secret-Text": "1"},
        json={
            "tenant_id": "tenant_default",
            "raw_findings": [f.model_dump(mode="json") for f in raw_findings],
            "context": {"content_source": "user"},
        },
    )
    assert response.status_code == 200, response.text
    return SimpleNamespace(findings=[SecurityFinding(**item) for item in response.json()["findings"]])


def _key(findings):
    return next(f for f in findings if f.category == "ssh_private_key")


@pytest.mark.parametrize("chars", [300, 2000])
def test_replay_restores_private_key_secret_text(monkeypatch, chars):
    engine = _engine(monkeypatch)
    content = "帮我看看这个密钥对不对\n" + _key_block(chars) + "\n谢谢"
    first = engine.check_input("req-replay-key", content, content_source="user")
    first_key = _key(first.findings)
    assert first_key.secret_text
    assert _key(first.raw_findings).secret_text == ""
    response = _replay(first.raw_findings)  # 模型转 JSON 再校验：ApplyContextFinding 必须接受 secret_text 键
    replayed = _key(response.findings)
    assert replayed.redacted_evidence == first_key.redacted_evidence
    assert replayed.secret_text
    assert replayed.secret_text in _key(first.raw_findings).evidence_context
    assert replayed.secret_text.strip().startswith("MIIEow")
    assert replayed.secret_text == first_key.secret_text


def _located(content, raw, **overrides):
    start = content.index(raw)
    base = dict(type="code_config", category="ssh_private_key", severity="critical",
                matched_text_preview="--****--", rule_id="r1", matched_location=f"content[{start}:{start + len(raw)}]",
                raw_evidence=raw, evidence_kind="literal")
    base.update(overrides)
    return SecurityFinding(**base)


def test_custom_secret_rule_never_gets_secret_text_on_replay():
    raw = "ZXhhbXBsZS1zZWNyZXQtdmFsdWU9"
    finding = _located("key: " + raw, raw, type="custom", category="customer_secret", rule_type="secret",
                       redacted_evidence="ZX****U9（28 位）")
    restore_secret_text([finding])
    assert finding.secret_text == ""
    assert finding.redacted_evidence == "ZX****U9（28 位）"


def test_credential_display_of_a_custom_secret_rule_is_unchanged_but_has_no_secret_text():
    raw = "ZXhhbXBsZS1zZWNyZXQtdmFsdWU9"
    assert render_hit_display("credential", raw).secret_text == raw  # 显示函数本身不变，是否带出由调用方决定


def test_existing_secret_text_is_kept():
    finding = _located(HEADER, HEADER, secret_text="已有", evidence_context=HEADER + "\nABCDEFGH\n")
    restore_secret_text([finding])
    assert finding.secret_text == "已有"


def test_marker_without_context_is_skipped():
    finding = _located(HEADER, HEADER, evidence_context="")
    other = _located(HEADER, HEADER, evidence_context="完全不含命中的上下文")
    restore_secret_text([finding, other])
    assert finding.secret_text == "" and other.secret_text == ""


def test_other_kinds_and_unqualified_findings_are_left_empty():
    content = "token 是 abcdefgh12345678 password=abc12345"
    custom_auto = _located(content, "password=", type="custom", category="c", rule_type="regex",
                           evidence_context=content)
    custom_keyword = _located(content, "abcdefgh12345678", type="custom", category="c", rule_type="keyword",
                              evidence_context=content)
    no_doc = _located(content, "abcdefgh12345678", category="capability_without_doc", evidence_context=content)
    semantic = _located(content, "token", type="semantic_attack", category="semantic_roleplay",
                        evidence_kind="semantic", evidence_context=content)
    no_raw = _located(content, "token", raw_evidence="", evidence_context=content)
    findings = [custom_auto, custom_keyword, no_doc, semantic, no_raw]
    restore_secret_text(findings)
    assert [f.secret_text for f in findings] == [""] * 5


def test_failure_is_logged_without_content_and_leaves_secret_text_empty(monkeypatch, caplog):
    import app.capability_docs as capability_docs
    import app.detectors.hit_display as hit_display

    monkeypatch.setattr(capability_docs, "display_kind", lambda category: "credential")

    raw = "SECRET-ORIGINAL-VALUE-123"
    finding = _located("key: " + raw, raw, type="secret", category="customer_secret", rule_id="rule-boom")
    monkeypatch.setattr(hit_display, "render_hit_display",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("坏了 " + raw)))
    caplog.set_level(logging.DEBUG)
    restore_secret_text([finding])
    assert finding.secret_text == ""
    assert "rule-boom" in caplog.text and "customer_secret" in caplog.text
    assert raw not in caplog.text


def test_replay_uses_the_exact_position_not_an_earlier_identical_header():
    from app.detectors.engine import SecurityEngine as Engine

    quoted = "请问 " + HEADER + " 是什么格式？\n"
    block = _key_block(300)
    content = quoted + block
    start = content.index(HEADER, len(quoted))
    finding = _located(content, HEADER, evidence_context="")
    finding.matched_location = f"content[{start}:{start + len(HEADER)}]"
    Engine._annotate_admin_evidence([finding], content, "user", "input")
    assert finding.evidence_context.count("-----BEGIN") == 2
    restore_secret_text([finding])
    assert finding.secret_text, "第二个头之后明明有正文"
    assert "-----BEGIN" not in finding.secret_text
    assert finding.secret_text.strip().startswith("MIIEow")


def test_replay_leaves_secret_text_empty_when_location_does_not_match_context():
    content = "前言 " + _key_block(300)
    start = content.index(HEADER)
    finding = _located(content, HEADER)
    from app.detectors.engine import SecurityEngine as Engine
    Engine._annotate_admin_evidence([finding], content, "user", "input")
    finding.matched_location = f"content[{start + 3}:{start + 3 + len(HEADER)}]"
    restore_secret_text([finding])
    assert finding.secret_text == ""


def test_context_offset_accounts_for_ellipsis_prefix_on_long_prefix():
    from app.detectors.engine import SecurityEngine as Engine

    content = "前" * 800 + HEADER + "\nMIIEowAAAA" + "Zz9y" * 20 + "\n" + TAIL
    start = content.index(HEADER)
    finding = _located(content, HEADER)
    Engine._annotate_admin_evidence([finding], content, "user", "input")
    assert finding.evidence_context.startswith("…")
    restore_secret_text([finding])
    assert finding.secret_text.strip().startswith("MIIEow")


def test_placeholder_redacted_evidence_does_not_block_the_new_display(monkeypatch):
    import app.capability_docs as capability_docs
    from app.detectors.hit_display import annotate_hit_display

    monkeypatch.setattr(capability_docs, "display_kind", lambda category: "credential")
    raw = "password=Example-Passw0rd-123"
    content = "配置 " + raw + " 结束"
    start = content.index(raw)
    finding = _located(content, raw, type="secret", category="plain_password",
                       redacted_evidence="plain_password:<MASKED>")
    finding.matched_location = f"content[{start}:{start + len(raw)}]"
    from app.detectors.engine import SecurityEngine as Engine
    Engine._annotate_admin_evidence([finding], content, "user", "input")
    annotate_hit_display([finding], content)
    assert finding.redacted_evidence != "plain_password:<MASKED>"
    assert finding.secret_text
    first = finding.secret_text
    finding.secret_text = ""
    restore_secret_text([finding])
    assert finding.secret_text == first


@pytest.mark.parametrize("start", [499, 500, 501])
def test_raw_offset_in_context_at_the_window_boundary(start):
    from app.detectors.hit_display import evidence_context_for, raw_offset_in_context

    content = "前" * start + "目标" + "后" * 600
    context = evidence_context_for(content, start, start + 2)
    offset = raw_offset_in_context(start)
    assert context[offset:offset + 2] == "目标"
    assert context.startswith("…") is (start > 500)


def test_apply_context_without_header_clears_secret_text_supplied_by_the_caller():
    client = TestClient(main_module.app)
    content = "帮我看看\n" + _key_block(300)
    first = client.post("/check-input/", json={"request_id": "r-sup", "content": content, "content_source": "user",
                                              "skip_semantic": True}).json()
    raw = first["raw_findings"]
    for item in raw:
        item["secret_text"] = "调用方塞进来的残留"
    response = client.post("/apply-context/", json={"tenant_id": "tenant_default", "raw_findings": raw,
                                                    "context": {"content_source": "user"}})
    assert response.status_code == 200, response.text
    assert response.json()["findings"]
    assert all(f["secret_text"] == "" for f in response.json()["findings"])
