"""P2-2 文件格式管控接入 SecurityEngine.check_input/check_output 的集成测试（TDD 先行）。

验证：
  1) 附件命中进入统一 findings（type="file"），证据脱敏；
  2) 文件命中的显式 action 纳入网关决策（_determine_action 对 file 同样权威）；
  3) 关键红线：仅上送文件、无文本（content 为空）时，附件检视仍然执行并能 block；
     2.9.22 起可执行、伪装可执行等按文件策略处置：缺省告警放行，配成禁止时拦；
  4) check_output 同样覆盖附件（委托 check_input）；
  5) 无附件时完全向后兼容；普通图片不产噪、不改变 allow。
"""
import base64

import pytest

from app.custom_rules import CompiledException
from app.detectors.engine import SecurityEngine
from app.file_inspector import load_file_policy

PNG_MAGIC = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
PE_MAGIC = b"MZ\x90\x00\x03" + b"\x00" * 60
ELF_MAGIC = b"\x7fELF\x02\x01\x01" + b"\x00" * 60


def _att(data: bytes, content_type="application/octet-stream", file_name="f.bin"):
    return {
        "file_name": file_name,
        "content_type": content_type,
        "data_base64": base64.b64encode(data).decode(),
    }


def _ctx(*attachments):
    return {"attachments": list(attachments)}


BLOCK_FILE_RISKS = {
    "executable_action": "block",
    "disguised_executable_action": "block",
    "script_action": "block",
    "unknown_action": "block",
    "zip_bomb_action": "block",
}


@pytest.fixture
def block_file_risks():
    """管理员把文件风险类别都配成“禁止”。2.9.22 前这些是写死的阻断。"""
    load_file_policy(BLOCK_FILE_RISKS)
    try:
        yield
    finally:
        load_file_policy({})


class TestEngineFileIntegration:
    def test_default_policy_alerts_and_forwards_executable_attachment(self):
        # 2.9.22：没有规则包或文件策略没配这几项时，可执行与伪装可执行只告警放行。
        load_file_policy({})
        engine = SecurityEngine()
        for att in (_att(PE_MAGIC, "image/png", "cat.png"), _att(ELF_MAGIC, "application/octet-stream", "tool.bin")):
            result = engine.check_input("req-f0", "附件给你", _ctx(att))
            files = [f for f in result.findings if f.type == "file"]
            assert result.action == "audit"
            assert files and all(f.action == "alert" for f in files)

    @pytest.mark.parametrize("data,content_type,name,rule_id", [
        (PE_MAGIC, "image/png", "cat.png", "file-disguised-exec"),
        (ELF_MAGIC, "application/octet-stream", "tool.bin", "file-executable"),
        (bytes.fromhex("00010203") + b"opaque", "application/octet-stream", "blob.bin", "file-unknown"),
    ])
    def test_file_risk_block_released_by_content_exception_rule_ref(
        self, block_file_risks, data, content_type, name, rule_id
    ):
        # 文件类命中能被内容例外按 rule_ref 放开（2.9.22 任务 4.1）。
        engine = SecurityEngine()
        blocked = engine.check_input("req-fx-0", "附件", _ctx(_att(data, content_type, name)))
        assert blocked.action == "block"
        assert any(f.rule_id == rule_id and f.action == "block" for f in blocked.findings)
        engine.load_content_audit_exceptions([CompiledException(
            exception_id="exc-file", scope_type="rule", rule_id=rule_id,
            decision="audit", reason="内部工具包，确认放行",
        )])
        released = engine.check_input("req-fx-1", "附件", _ctx(_att(data, content_type, name)))
        hit = [f for f in released.findings if f.rule_id == rule_id]
        assert released.action == "audit"
        assert hit and hit[0].action == "audit" and hit[0].exception_id == "exc-file"

    def test_disguised_executable_attachment_drives_block(self, block_file_risks):
        engine = SecurityEngine()
        result = engine.check_input(
            "req-f1", "请看这张图片", _ctx(_att(PE_MAGIC, "image/png", "cat.png"))
        )
        assert result.action == "block"
        files = [f for f in result.findings if f.type == "file"]
        assert len(files) == 1
        assert files[0].category == "file_disguised_executable"
        assert files[0].action == "block"

    def test_real_executable_high_drives_block_via_widened_action(self, block_file_risks):
        # ELF 声明为二进制 → severity=high（非 critical），仅靠内置分支不会 block，
        # 必须靠 _determine_action 把 file 的显式 action 纳入决策才能 block。
        engine = SecurityEngine()
        result = engine.check_input(
            "req-f2", "附件给你", _ctx(_att(ELF_MAGIC, "application/octet-stream", "tool.bin"))
        )
        assert result.action == "block"
        assert any(f.category == "file_executable" for f in result.findings)

    def test_file_inspection_runs_with_empty_content(self, block_file_risks):
        # 红线：仅上送文件、无文本（content 为空）时，附件检视仍须执行并 block。
        engine = SecurityEngine()
        result = engine.check_input("req-f3", "", _ctx(_att(PE_MAGIC, "image/png", "x.png")))
        assert result.action == "block"
        assert any(f.type == "file" for f in result.findings)

    def test_file_inspection_runs_with_none_content(self, block_file_risks):
        engine = SecurityEngine()
        result = engine.check_input("req-f4", None, _ctx(_att(ELF_MAGIC, "application/octet-stream")))
        assert result.action == "block"
        assert any(f.type == "file" for f in result.findings)

    def test_evidence_redacted_no_raw_bytes_in_findings(self):
        engine = SecurityEngine()
        result = engine.check_input("req-f5", "图", _ctx(_att(PE_MAGIC, "image/png", "cat.png")))
        f = [x for x in result.findings if x.type == "file"][0]
        assert "sha256:" in f.redacted_evidence
        assert "MZ" not in f.redacted_evidence
        assert "MZ" not in f.matched_text_preview

    def test_check_output_also_inspects_attachments(self, block_file_risks):
        engine = SecurityEngine()
        result = engine.check_output("req-f6", "", _ctx(_att(PE_MAGIC, "image/png", "x.png")))
        assert result.action == "block"
        assert any(f.type == "file" for f in result.findings)

    def test_plain_png_no_file_finding_allows(self):
        engine = SecurityEngine()
        result = engine.check_input("req-f7", "正常文本", _ctx(_att(PNG_MAGIC, "image/png", "ok.png")))
        assert result.action == "allow"
        assert all(f.type != "file" for f in result.findings)

    def test_no_attachments_backward_compatible(self):
        engine = SecurityEngine()
        r1 = engine.check_input("req-f8", "今天天气不错，没有敏感信息")
        assert r1.action == "allow"
        r2 = engine.check_input("req-f9", "正常文本", {"headers": {}})
        assert all(f.type != "file" for f in r2.findings)

    def test_empty_content_no_attachments_still_allows(self):
        engine = SecurityEngine()
        result = engine.check_input("req-f10", "", {"attachments": []})
        assert result.action == "allow"
        assert result.findings == []


# ---- 代码质量审查第三轮：运行时“执行”和“留证”分成两个判定 ----

def _runtime_finding(type_, category, action):
    from app.detectors.engine import SecurityFinding

    return SecurityFinding(
        type=type_, category=category, severity="medium", confidence=0.5, action=action,
        rule_id="r", rule_name="r", matched_text_preview="", redacted_evidence="",
        evidence_kind="runtime", counts_as_security_finding=False,
    )


def test_runtime_enforcement_and_runtime_evidence_are_separate():
    unknown_alert = _runtime_finding("file", "file_unknown_type", "alert")
    unknown_block = _runtime_finding("file", "file_unknown_type", "block")
    regex_block = _runtime_finding("regex_timeout", "custom_regex_timeout", "block")
    # 未知类型告警放行：不是执行，只是要留 audit 的运行时证据。
    assert not SecurityEngine._is_runtime_enforcement(unknown_alert)
    assert SecurityEngine._is_runtime_evidence(unknown_alert)
    assert SecurityEngine._is_runtime_enforcement(unknown_block)
    assert SecurityEngine._is_runtime_enforcement(regex_block)
    assert not SecurityEngine._is_runtime_evidence(regex_block)
    engine = SecurityEngine()
    assert engine._determine_action([unknown_alert]) == "audit"


# ---- r2922 对抗复核：文件类型“禁止”命中按文件类型出规则编号，可被内容例外放开 ----

PDF_MAGIC = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"0" * 32


@pytest.fixture
def block_pdf_type():
    load_file_policy({"blocked_types": ["pdf"]})
    try:
        yield
    finally:
        load_file_policy({})


def _blocked_type_hits(result):
    return [f for f in result.findings if f.category == "file_policy_blocked_type"]


def test_blocked_type_rule_id_carries_file_type(block_pdf_type):
    engine = SecurityEngine()
    result = engine.check_input("req-bt-0", "附件", _ctx(_att(PDF_MAGIC, "application/pdf", "report.pdf")))
    hits = _blocked_type_hits(result)
    assert result.action == "block"
    assert [f.rule_id for f in hits] == ["file-policy-blocked-type:pdf"]
    assert hits[0].action == "block" and not hits[0].exception_id


def test_metadata_only_blocked_type_rule_id_carries_file_type(block_pdf_type):
    engine = SecurityEngine()
    ctx = {"attachments": [{"file_name": "report.pdf", "content_type": "application/pdf", "source": "json_file_metadata"}]}
    hits = _blocked_type_hits(engine.check_input("req-bt-1", "附件", ctx))
    assert [f.rule_id for f in hits] == ["file-policy-blocked-type:pdf"]


@pytest.mark.parametrize("exception_rule", [
    "file-policy-blocked-type:pdf",
    # 旧编号建的例外按别名对全部禁止类型生效，已建例外不失效。
    "file-policy-blocked-type",
])
def test_blocked_type_released_by_content_exception(block_pdf_type, exception_rule):
    engine = SecurityEngine()
    engine.load_content_audit_exceptions([CompiledException(
        exception_id="exc-type", scope_type="tenant", rule_id=exception_rule,
        decision="audit", reason="合同扫描件需要发给模型",
    )])
    result = engine.check_input("req-bt-2", "附件", _ctx(_att(PDF_MAGIC, "application/pdf", "report.pdf")))
    hits = _blocked_type_hits(result)
    assert result.action == "audit"
    assert hits and all(f.action == "audit" and f.exception_id == "exc-type" for f in hits)


def test_exception_for_another_file_type_does_not_release(block_pdf_type):
    engine = SecurityEngine()
    engine.load_content_audit_exceptions([CompiledException(
        exception_id="exc-docx", scope_type="tenant", rule_id="file-policy-blocked-type:docx",
        decision="audit", reason="只放开 DOCX",
    )])
    result = engine.check_input("req-bt-3", "附件", _ctx(_att(PDF_MAGIC, "application/pdf", "report.pdf")))
    hits = _blocked_type_hits(result)
    assert result.action == "block"
    assert hits and all(f.action == "block" and not f.exception_id for f in hits)


def test_legacy_alias_does_not_match_other_rules():
    from app.custom_rules import ExceptionSet
    from app.detectors.engine import SecurityFinding

    other = SecurityFinding(
        type="file", category="file_policy_blocked_typeX", severity="high", action="block",
        rule_id="file-policy-blocked-typex", rule_name="r", matched_text_preview="",
    )
    exceptions = ExceptionSet([CompiledException(
        exception_id="exc-legacy", scope_type="tenant", rule_id="file-policy-blocked-type",
        decision="audit", reason="旧例外",
    )])
    assert exceptions.apply([other])[0].exception_id == ""
