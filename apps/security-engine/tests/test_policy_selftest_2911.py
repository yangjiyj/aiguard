"""2.9.11 开发 VM 安全策略实测缺陷回归（用例 A11/A11c/A11e、N03/N10/N12/N13）。"""
from __future__ import annotations

import base64
import io
import zipfile

from app import feature_flags as ff
from app.detectors.engine import SecurityEngine, SecurityFinding
from app.custom_rules import CompiledRule
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet

CARD = "6217001234567893"
PHONE = "13812345678"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _policy(policy_id: str, name: str, category: str) -> CompiledPolicy:
    return CompiledPolicy(
        policy_code=f"builtin.data_leak.{policy_id}", policy_id=policy_id, policy_name=name,
        policy_type="builtin_capability", scene="data_leak", action="mask", enabled=True,
        binding_mode="any",
        capabilities=[CompiledPolicyCapability(
            category=category, supported_stages=["input", "output"],
            allowed_actions=["audit", "mask", "block"], mask_capable=True,
        )],
    )


def _docx(text: str) -> bytes:
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    body = f'<w:body xmlns:w="{ns}"><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body>'
    doc = f'<?xml version="1.0"?><w:document xmlns:w="{ns}">{body}</w:document>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="text/xml"/></Types>',
        )
        archive.writestr("word/document.xml", doc)
    return buf.getvalue()


class TestMaskOnlyConfiguredSpans:
    """A11：语义裁判的整句命中没有动作，不得把"请汇款到"一起替换掉。"""

    def _engine(self) -> SecurityEngine:
        engine = SecurityEngine()
        engine.load_custom_rules([CompiledRule(
            rule_id="rule_g_bankcard", rule_name="银行卡号", rule_type="regex",
            category="pii_bankcard", severity="high", action="audit",
            regex=r"(?<!\d)[3-6]\d{15,18}(?!\d)",
        )])
        engine.policies = PolicySet([_policy("a3048f2177b99395", "银行卡号检测", "bank_card_cn")])
        return engine

    @staticmethod
    def _semantic_window(content: str) -> SecurityFinding:
        # 与 VM 事件一致：语义命中没有 action，位置覆盖整条消息。
        return SecurityFinding(
            type="semantic_attack", category="prompt_input_semantic_risk", severity="high",
            matched_text_preview="prompt_input_semantic_risk:input",
            rule_id="semantic_prompt_input_semantic_risk", rule_type="semantic",
            confidence=0.9, matched_location=f"content[0:{len(content)}]", evidence_kind="semantic",
        )

    def test_mask_content_ignores_findings_without_mask_action(self):
        engine = self._engine()
        for text, expected in [
            (f"请汇款到 {CARD}", "请汇款到 <MASKED>"),
            (f"汇款到{CARD}，谢谢", "汇款到<MASKED>，谢谢"),
            (f"请转账到 {CARD} 谢谢", "请转账到 <MASKED> 谢谢"),
        ]:
            result = engine.check_input("req-a11", text, skip_semantic=True)
            assert result.action == "mask"
            findings = [*result.findings, self._semantic_window(text)]
            masked = engine._mask_content(text, findings, {}, engine.policies, engine.custom_rules)
            assert masked == expected

    def test_check_input_with_semantic_window_keeps_prefix(self, monkeypatch):
        engine = self._engine()
        text = f"请汇款到 {CARD}"
        original = engine._apply_finding_triage

        def with_semantic(content, findings, *args, **kwargs):
            return original(content, [*findings, self._semantic_window(content)], *args, **kwargs)

        monkeypatch.setattr(engine, "_apply_finding_triage", with_semantic)
        result = engine.check_input("req-a11-check", text, skip_semantic=True)
        assert result.action == "mask"
        assert result.masked_content == "请汇款到 <MASKED>"


class TestMaskTextBesideUnmaskableAttachment:
    """N03 同类：消息文本可脱敏时照常脱敏，只有附件正文降级为原样放行 + 告警。"""

    def _engine(self, monkeypatch) -> SecurityEngine:
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
        engine = SecurityEngine()
        engine.load_file_policy({"content_dlp_enabled": True})
        engine.policies = PolicySet([_policy("phone", "手机号检测", "phone_cn")])
        return engine

    @staticmethod
    def _ctx(text: str) -> dict:
        return {"tenant_id": "t1", "attachments": [{
            "file_name": "a.docx", "content_type": DOCX,
            "data_base64": base64.b64encode(_docx(text)).decode(),
        }]}

    def test_text_pii_is_masked_when_attachment_is_clean(self, monkeypatch):
        engine = self._engine(monkeypatch)
        result = engine.check_input("req-n03-clean", f"看附件，手机号{PHONE}", context=self._ctx("会议纪要"))
        assert result.action == "mask"
        assert result.masked_content == "看附件，手机号<MASKED>"

    def test_only_attachment_findings_are_marked_unavailable(self, monkeypatch):
        engine = self._engine(monkeypatch)
        result = engine.check_input(
            "req-n03-both", f"手机号{PHONE}", context=self._ctx("另一个手机13912345678"),
        )
        assert result.action == "mask"
        # 网关按消息文本替换，不能把附件正文拼进 masked_content。
        assert result.masked_content == "手机号<MASKED>"
        masks = [f for f in result.findings if f.action == "mask"]
        attachment = [f for f in masks if f.content_source == "file_attachment"]
        text = [f for f in masks if f.content_source != "file_attachment"]
        assert attachment and text
        assert all(f.triage.get("mask_unavailable") for f in attachment)
        assert not any(f.triage.get("mask_unavailable") for f in text)

    def test_attachment_only_hit_still_downgrades_to_audit(self, monkeypatch):
        engine = self._engine(monkeypatch)
        result = engine.check_input("req-n03-file", "请看附件", context=self._ctx(f"手机{PHONE}"))
        assert result.action == "audit"
        assert result.masked_content is None
        assert any(f.triage.get("mask_unavailable") for f in result.findings if f.action == "mask")
