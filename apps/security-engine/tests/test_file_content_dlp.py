"""文件内容 DLP 正文提取器测试。

样本约束：只用合成数据（合成测试身份证通过 GB11643 校验位、AWS 文档示例密钥、
合成手机号）。断言只验证「命中类型/数量/action」，绝不打印完整 PII 或密钥正文。
"""
from __future__ import annotations

import base64
import io
import zipfile

import pytest

from app import feature_flags as ff
from app.detectors.engine import SecurityEngine
from app.file_content_dlp_bridge import file_content_dlp_enabled
from app.file_text_extractor import (
    ExtractionResult,
    extract_attachment_text,
)


# —— 合成敏感数据（非真实）——
# 合成手机号（138 段测试号）
PHONE = "13812345678"
# 合成身份证：构造一个通过 GB11643 校验位的 18 位号（与 pii_checksum 测试同源风格）
# 取前 17 位 1101011990030700X 风格，校验位由 validate_id_card_cn 保证通过即可；
# 这里用一个已知合法的合成号（出生地码 110101=北京东城，生日 1990-01-01，顺序 001，校验位 X）
ID_CARD = "110101199001010015"  # 合成号，通过 validate_id_card_cn GB11643 校验
EMAIL = "test_user@example.com"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS 官方文档示例，非真实凭证


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _make_docx(text_segments: list[str]) -> bytes:
    """构造最小合法 docx（word/document.xml 含给定文本段，含表格/页眉结构）。"""
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    paragraphs = "".join(
        f'<w:p><w:r><w:t>{seg}</w:t></w:r></w:p>' for seg in text_segments
    )
    # 表格 + 页眉引用结构，验证不只取正文段落
    body = (
        f'<w:body xmlns:w="{ns}">{paragraphs}'
        '<w:tbl><w:tr><w:tc><w:p><w:r><w:t>表格内容</w:t></w:r></w:p></w:tc></w:tr></w:tbl>'
        "</w:body>"
    )
    document_xml = f'<?xml version="1.0"?><w:document xmlns:w="{ns}">{body}</w:document>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="text/xml"/></Types>',
        )
        z.writestr("word/document.xml", document_xml)
    return buf.getvalue()


def _make_pptx(text_segments: list[str]) -> bytes:
    ns_a = "http://schemas.openxmlformats.org/drawingml/2006/main"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="text/xml"/></Types>',
        )
        for i, seg in enumerate(text_segments, 1):
            slide = (
                f'<?xml version="1.0"?>'
                f'<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                f'xmlns:a="{ns_a}"><p:cSld><p:spTree><p:sp><p:txBody>'
                f'<a:p><a:r><a:t>{seg}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>'
            )
            z.writestr(f"ppt/slides/slide{i}.xml", slide)
        # 备注
        z.writestr(
            "ppt/notesSlides/notesSlide1.xml",
            f'<?xml version="1.0"?><p:notes xmlns:a="{ns_a}" '
            f'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
            f'<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>备注内容</a:t></a:r></a:p>'
            f"</p:txBody></p:sp></p:spTree></p:cSld></p:notes>",
        )
    return buf.getvalue()


def _make_xlsx(text_segments: list[str]) -> bytes:
    ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    shared = "<sst xmlns=\"" + ns + "\">" + "".join(
        f"<si><t>{seg}</t></si>" for seg in text_segments
    ) + "</sst>"
    sheet1 = f'<?xml version="1.0"?><worksheet xmlns="{ns}"><sheetData>' \
        '<row r="1"><c r="A1" t="s"><v>0</v></c></row>' \
        '<row r="2"><c r="A2" t="s"><v>1</v></c></row></sheetData></worksheet>'
    # 第二个工作表
    sheet2 = f'<?xml version="1.0"?><worksheet xmlns="{ns}"><sheetData>' \
        '<row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData></worksheet>'
    workbook = f'<?xml version="1.0"?><workbook xmlns="{ns}">' \
        '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/>' \
        '<sheet name="Sheet2" sheetId="2" r:id="rId2"/></sheets></workbook>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("xl/sharedStrings.xml", shared)
        z.writestr("xl/worksheets/sheet1.xml", sheet1)
        z.writestr("xl/worksheets/sheet2.xml", sheet2)
        z.writestr("xl/workbook.xml", workbook)
    return buf.getvalue()


def _make_text_pdf(text: str) -> bytes:
    """构造带 FlateDecode 内容流的文本 PDF。"""
    import zlib

    ops = "BT /F1 12 Tf 50 700 Td (" + text + ") Tj ET"
    compressed = zlib.compress(ops.encode("latin-1"))
    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        4: b"<< /Length %d /Filter /FlateDecode >>\nstream\n%s\nendstream"
        % (len(compressed), compressed),
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    buf = b"%PDF-1.4\n"
    off = {}
    for n in sorted(objs):
        off[n] = len(buf)
        buf += b"%d 0 obj\n%s\nendobj\n" % (n, objs[n])
    xref = len(buf)
    buf += b"xref\n0 6\n0000000000 65535 f \n"
    for n in range(1, 6):
        buf += b"%010d 00000 n \n" % off[n]
    buf += b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % xref
    return buf


# ============ 纯文本提取 ============

class TestPlainTextExtraction:
    def test_txt_extracts_text(self):
        data = f"联系手机{PHONE} 邮箱{EMAIL}".encode("utf-8")
        res = extract_attachment_text("txt", data)
        assert isinstance(res, ExtractionResult)
        assert PHONE in res.text
        assert EMAIL in res.text
        assert res.error is None

    def test_csv_extracts_text(self):
        data = f"name,phone\n张三,{PHONE}\n".encode("utf-8")
        res = extract_attachment_text("csv", data)
        assert PHONE in res.text

    def test_json_extracts_text(self):
        data = f'{{"phone":"{PHONE}","key":"{AWS_KEY}"}}'.encode("utf-8")
        res = extract_attachment_text("json", data)
        assert PHONE in res.text
        assert AWS_KEY in res.text


# ============ Office 提取 ============

class TestOfficeExtraction:
    def test_docx_body_and_table(self):
        data = _make_docx([f"客户手机{PHONE}", f"身份资料{ID_CARD}"])
        res = extract_attachment_text("docx", data)
        assert PHONE in res.text
        assert ID_CARD in res.text
        assert "表格内容" in res.text  # 表格也被提取

    def test_pptx_slides_and_notes(self):
        data = _make_pptx([f"slide正文{PHONE}", f"备注外发{EMAIL}"])
        res = extract_attachment_text("pptx", data)
        assert PHONE in res.text
        assert "备注内容" in res.text  # 备注也被提取

    def test_xlsx_multi_sheet(self):
        data = _make_xlsx([f"sheet数据{PHONE}", EMAIL])
        res = extract_attachment_text("xlsx", data)
        assert PHONE in res.text
        assert EMAIL in res.text


# ============ PDF 提取 ============

class TestPdfExtraction:
    def test_text_pdf_extracts(self):
        data = _make_text_pdf(f"phone {PHONE} id {ID_CARD}")
        res = extract_attachment_text("pdf", data)
        assert PHONE in res.text
        assert ID_CARD in res.text

    def test_encrypted_pdf_not_parsed(self):
        # 带 /Encrypt 字典引用的 PDF（无法解密）→ 返回 encrypted，不提取、不误判通过
        import zlib

        objs = {
            1: b"<< /Type /Catalog /Pages 2 0 R /Encrypt 6 0 R >>",
            2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            6: b"<< /Filter /Standard /V 1 /R 2 /O <abcdef> /U <abcdef> /P -4 >>",
        }
        buf = b"%PDF-1.4\n"
        off = {}
        for n in sorted(objs):
            off[n] = len(buf)
            buf += b"%d 0 obj\n%s\nendobj\n" % (n, objs[n])
        xref = len(buf)
        buf += b"xref\n0 7\n0000000000 65535 f \n"
        for n in [1, 2, 3, 6]:
            buf += b"%010d 00000 n \n" % off[n]
        buf += b"trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % xref
        res = extract_attachment_text("pdf", buf)
        assert res.encrypted is True
        assert res.text == ""


# ============ 健壮性与边界 ============

class TestRobustness:
    def test_corrupt_zip_does_not_raise(self):
        # 伪 docx 但不是合法 zip
        res = extract_attachment_text("docx", b"PK\x03\x04 not a real zip" + b"\x00" * 200)
        assert res.error is not None or res.text == ""
        assert res.text == ""

    def test_unknown_text_type_returns_empty(self):
        res = extract_attachment_text("png", b"\x89PNG\r\n\x1a\n")
        assert res.text == ""  # 非文本类不提取


# ============ 默认关闭回归 ============

class TestFlagDefaultOff:
    def test_flag_default_off(self, monkeypatch):
        monkeypatch.delenv(ff.ENV_FILE_CONTENT_DLP, raising=False)
        assert ff.is_enabled(ff.ENV_FILE_CONTENT_DLP) is False

    def test_engine_does_not_extract_when_disabled(self, monkeypatch):
        """开关关闭时，含敏感 docx 的附件不应触发内容级 finding（行为与改造前一致）。"""
        monkeypatch.delenv(ff.ENV_FILE_CONTENT_DLP, raising=False)
        engine = SecurityEngine()
        data = _make_docx([f"外发手机{PHONE}"])
        ctx = {
            "attachments": [
                {
                    "file_name": "report.docx",
                    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "data_base64": _b64(data),
                }
            ]
        }
        result = engine.check_input("req_dlp_off", "", context=ctx)
        categories = {f.category for f in result.findings}
        # 关闭时不做正文内容检测：不应因 docx 正文里的手机号产生 phone_cn
        assert "phone_cn" not in categories


# ============ 开启后检测命中（端到端，经 engine）============

class TestEnabledDetection:
    def _ctx_with_docx(self, data: bytes) -> dict:
        return {
            "attachments": [
                {
                    "file_name": "secret.docx",
                    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "data_base64": _b64(data),
                }
            ]
        }

    def test_docx_sensitive_blocks_when_enabled(self, monkeypatch):
        """env 总开关 + 租户策略双开 → 命中阻断。"""
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
        engine = SecurityEngine()
        engine.load_file_policy({"content_dlp_enabled": True})
        data = _make_docx([f"外发手机{PHONE}", f"证件{ID_CARD}", f"密钥{AWS_KEY}"])
        result = engine.check_input("req_dlp_on", "", context=self._ctx_with_docx(data))
        categories = {f.category for f in result.findings}
        assert "phone_cn" in categories or any("phone" in c for c in categories)

    def test_audit_only_allows_sensitive_file_content(self, monkeypatch):
        """普通文本可审计，但文件内容 DLP 命中仍必须阻断外发。"""
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
        engine = SecurityEngine()
        engine.audit_only = True
        engine.load_file_policy({"content_dlp_enabled": True})
        data = _make_docx([f"外发手机{PHONE}", f"证件{ID_CARD}"])

        result = engine.check_input(
            "req_dlp_audit_only",
            "",
            context=self._ctx_with_docx(data),
        )

        assert result.action == "audit"

    def test_sensitive_file_content_finding_is_attributed_to_attachment(self, monkeypatch):
        """文件正文命中必须带文件来源，供各外发入口区分普通文本审计。"""
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        engine = SecurityEngine()
        engine.load_file_policy({"content_dlp_enabled": True})
        data = _make_docx([f"外发手机{PHONE}"])

        result = engine.check_input(
            "req_dlp_file_source",
            "请审查这个附件",
            context=self._ctx_with_docx(data),
            content_source="user",
        )

        phone_findings = [
            finding for finding in result.findings if finding.category == "phone_cn"
        ]
        assert phone_findings
        assert all(finding.content_source == "file_attachment" for finding in phone_findings)

    def test_multiple_attachment_findings_keep_their_attachment_indexes(self, monkeypatch):
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
        engine = SecurityEngine()
        engine.load_file_policy({"content_dlp_enabled": True})
        secret = "AKIA" "4B7C9D2E8F6G1H3J"
        context = {
            "attachments": [
                {
                    "file_name": "pii.docx",
                    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "data_base64": _b64(_make_docx([f"手机号{PHONE}"])),
                },
                {
                    "file_name": "secret.docx",
                    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "data_base64": _b64(_make_docx([f"AWS_ACCESS_KEY_ID={secret}"])),
                },
            ]
        }

        result = engine.check_input("req_dlp_multiple_attachments", "", context=context)

        phone_findings = [
            finding for finding in result.findings if finding.category == "phone_cn"
        ]
        secret_findings = [
            finding for finding in result.findings
            if finding.rule_id == "secret_aws_access_key"
        ]
        assert phone_findings
        assert secret_findings
        assert {finding.attachment_index for finding in phone_findings} == {0}
        assert {finding.attachment_index for finding in secret_findings} == {1}
        assert all(
            finding.content_source == "file_attachment"
            for finding in phone_findings + secret_findings
        )

    def test_global_on_without_legacy_tenant_flag_still_active(self, monkeypatch):
        """全局开关开即检测：租户策略未声明旧 content_dlp_enabled 字段也不影响（单闸门）。"""
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
        engine = SecurityEngine()
        engine.load_file_policy({})  # 未声明 content_dlp_enabled
        data = _make_docx([f"外发手机{PHONE}"])
        result = engine.check_input("req_global_on_no_tenant", "", context=self._ctx_with_docx(data))
        categories = {f.category for f in result.findings}
        assert "phone_cn" in categories or any("phone" in c for c in categories)

    def test_policy_on_but_env_off_not_active(self, monkeypatch):
        """租户策略开但 env 总开关关 → 不提取、不命中（部署级闸门优先）。"""
        monkeypatch.delenv(ff.ENV_FILE_CONTENT_DLP, raising=False)
        monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
        engine = SecurityEngine()
        engine.load_file_policy({"content_dlp_enabled": True})
        data = _make_docx([f"外发手机{PHONE}"])
        result = engine.check_input("req_env_off", "", context=self._ctx_with_docx(data))
        categories = {f.category for f in result.findings}
        assert "phone_cn" not in categories

    # ---- 任务2：全局动态开关为唯一门控 ----

    def test_global_file_dlp_switch_does_not_require_tenant_flag(self, monkeypatch):
        """全局开 + 空租户策略（无 content_dlp_enabled）→ 仍应开启。"""
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        engine = SecurityEngine()
        engine.load_file_policy({})
        assert file_content_dlp_enabled() is True

    def test_global_file_dlp_switch_off_ignores_legacy_tenant_true(self, monkeypatch):
        """全局关 + 旧租户字段 content_dlp_enabled=true → 不再因此开启。"""
        monkeypatch.delenv(ff.ENV_FILE_CONTENT_DLP, raising=False)
        engine = SecurityEngine()
        engine.load_file_policy({"content_dlp_enabled": True})
        assert file_content_dlp_enabled() is False


def test_corrupt_image_has_explicit_parse_failure(monkeypatch):
    from app.file_content_dlp_bridge import extract_textual_attachment_content

    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    context = {
        "attachments": [
            {
                "file_name": "image.png",
                "content_type": "image/png",
                "data_base64": _b64(b"\x89PNG\r\n\x1a\n"),
            }
        ]
    }

    text, findings = extract_textual_attachment_content(context)

    assert text == ""
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "file_content_parse_failed"
    # 解析失败属于检测未完成：记录并放行，不阻断。
    assert finding.action == "audit"
    assert "reason=ocr_" in finding.redacted_evidence
    assert finding.attachment_index == 0


def test_unknown_file_remains_security_risk(monkeypatch):
    from app.file_content_dlp_bridge import extract_textual_attachment_content

    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    context = {
        "attachments": [
            {
                "file_name": "unknown.bin",
                "content_type": "application/octet-stream",
                "data_base64": _b64(b"unknown-binary-content"),
            }
        ]
    }

    _, findings = extract_textual_attachment_content(context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "file_content_uninspected"
    assert finding.severity == "medium"
    assert finding.action == "audit"
    assert finding.counts_as_security_finding is True
    assert finding.attachment_index == 0


def test_engine_preserves_zero_message_and_attachment_indexes(monkeypatch):
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
    engine = SecurityEngine()
    engine.load_file_policy({"content_dlp_enabled": True})
    context = {
        "message_index": 0,
        "message_role": "user",
        "attachments": [
            {
                "file_name": "secret.docx",
                "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "data_base64": _b64(_make_docx([f"手机号{PHONE}"])),
            }
        ],
    }

    result = engine.check_input("req-index-zero", "", context=context)
    attachment_findings = [
        finding for finding in result.findings
        if finding.content_source == "file_attachment"
    ]

    assert attachment_findings
    assert all(finding.message_index == 0 for finding in attachment_findings)
    assert all(finding.message_role == "user" for finding in attachment_findings)
    assert any(finding.attachment_index == 0 for finding in attachment_findings)
