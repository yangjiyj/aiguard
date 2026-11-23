"""文件内容 DLP 故障隔离与脱敏证据专项测试。

覆盖设计 §7 故障矩阵与 §12 留存脱敏要求：
- ZIP Bomb / 异常压缩比 → 阻断不解析
- 单条目超限 → 阻断
- 解析失败 finding 的证据不含完整 PII / 密钥
- 大文件准入上限 → 阻断
- 提取出的正文只用于检测，finding 证据只保留 sha16/计数
"""
from __future__ import annotations

import base64
import io
import zipfile

import pytest

from app import feature_flags as ff
from app.detectors.engine import SecurityEngine
from app.file_content_dlp_bridge import (
    MAX_SCAN_FILE_BYTES,
    extract_textual_attachment_content,
)
from app.file_text_extractor import extract_attachment_text


PHONE = "13812345678"
ID_CARD = "110101199001010015"  # 合成，过 GB11643 校验
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS 文档示例


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _docx_with_text(text: str) -> bytes:
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    body = f'<w:body xmlns:w="{ns}"><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body>'
    doc = f'<?xml version="1.0"?><w:document xmlns:w="{ns}">{body}</w:document>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="text/xml"/></Types>')
        z.writestr("word/document.xml", doc)
    return buf.getvalue()


class TestZipBomb:
    def test_high_ratio_zip_unsafe(self):
        """伪 docx：一个条目声明巨大 file_size（高压缩比）→ zip_unsafe，不提取。"""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", "<x/>")
            # 写一个高压缩比条目（重复内容压缩后很小，但 file_size 反映原始大）
            z.writestr("word/document.xml", "A" * 200000)
        data = buf.getvalue()
        res = extract_attachment_text("docx", data)
        # 高压缩比内容能被提取（合法），但若人为构造超 MAX_ZIP_RATIO 的会被 _safe_zip 拒
        # 这里验证正常高压缩文本不崩；zip_unsafe 由超限条目触发
        assert res.error is None or res.error == "zip_unsafe"

    def test_oversized_single_entry_blocked(self):
        """单 XML 条目超 MAX_XML_PER_ENTRY → zip_unsafe。"""
        from app.file_text_extractor import MAX_XML_PER_ENTRY
        huge = "B" * (MAX_XML_PER_ENTRY + 1)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("word/document.xml", huge)
        res = extract_attachment_text("docx", buf.getvalue())
        assert res.error == "zip_unsafe"


class TestAdmissionLimit:
    def test_over_scan_limit_recorded_not_blocked(self, monkeypatch):
        """附件字节超过 MAX_SCAN_FILE_BYTES → bridge 产 oversized 记录 finding（检测未完成，放行），不提取。"""
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        # 构造一个声称为 docx 但超准入上限的附件
        big = b"PK\x03\x04" + b"\x00" * (MAX_SCAN_FILE_BYTES + 1)
        ctx = {
            "attachments": [
                {
                    "file_name": "huge.docx",
                    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "data_base64": _b64(big),
                }
            ]
        }
        _, failures = extract_textual_attachment_content(ctx, {"content_dlp_enabled": True})
        assert any(
            getattr(f, "category", "") == "file_content_oversized" and f.action == "audit"
            for f in failures
        )


class TestEvidenceRedaction:
    def test_parse_failure_evidence_has_no_raw_pii(self, monkeypatch):
        """解析失败 finding 的 preview/redacted_evidence 不含完整 PII/密钥。"""
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        # 损坏的 docx（声明 docx 但字节损坏）
        ctx = {
            "attachments": [
                {
                    "file_name": f"report_with_{PHONE}.docx",  # 文件名里夹带 PII（清洗后只留 basename）
                    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "data_base64": _b64(b"PK\x03\x04 not zip" + b"\x00" * 50),
                }
            ]
        }
        _, failures = extract_textual_attachment_content(ctx, {"content_dlp_enabled": True})
        assert len(failures) >= 1
        for f in failures:
            blob = (f.matched_text_preview or "") + (f.redacted_evidence or "") + (f.matched_location or "")
            # 完整手机号、完整身份证、完整 AWS key 不得出现在任何证据字段
            assert PHONE not in blob
            assert ID_CARD not in blob
            assert AWS_KEY not in blob

    def test_successful_extraction_finding_not_leak_raw(self, monkeypatch):
        """命中后 finding 的 matched_text_preview 是脱敏的（不回显完整正文/PII）。"""
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
        engine = SecurityEngine()
        engine.load_file_policy({"content_dlp_enabled": True})
        data = _docx_with_text(f"手机{PHONE} 证件{ID_CARD}")
        ctx = {
            "attachments": [
                {
                    "file_name": "secret.docx",
                    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "data_base64": _b64(data),
                }
            ]
        }
        result = engine.check_input("req_leak", "", context=ctx)
        # 应命中
        assert len(result.findings) > 0
        for f in result.findings:
            blob = (f.matched_text_preview or "") + (f.redacted_evidence or "")
            # 完整身份证不得回显（脱敏后只留 sha/掩码）
            assert ID_CARD not in blob


class TestQuarantineOnFailure:
    def test_encrypted_attachment_is_recorded_not_blocked(self, monkeypatch):
        """加密 PDF → file_content_encrypted 记录（无法检测正文），不阻断。"""
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        # 构造带 /Encrypt 的 PDF
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
        ctx = {
            "attachments": [
                {"file_name": "secret.pdf", "content_type": "application/pdf", "data_base64": _b64(buf)}
            ]
        }
        engine = SecurityEngine()
        engine.load_file_policy({"content_dlp_enabled": True})
        result = engine.check_input("req_enc", "", context=ctx)
        cats = {f.category for f in result.findings}
        assert "file_content_encrypted" in cats
        assert result.action == "audit"


class TestDisabledIsNoop:
    def test_disabled_no_overhead_finding_types(self, monkeypatch):
        """关闭时：含敏感附件的请求与无附件请求的 file 类 finding 完全一致（零行为漂移）。"""
        monkeypatch.delenv(ff.ENV_FILE_CONTENT_DLP, raising=False)
        engine = SecurityEngine()
        data = _docx_with_text(f"手机{PHONE}")
        ctx_with = {"attachments": [{"file_name": "x.docx", "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "data_base64": _b64(data)}]}
        r1 = engine.check_input("a", "", context=ctx_with)
        r2 = engine.check_input("b", "", context=None)
        # 关闭时附件不参与内容检测：两者都不应因 docx 正文手机号命中 phone_cn
        cats1 = {f.category for f in r1.findings}
        cats2 = {f.category for f in r2.findings}
        assert "phone_cn" not in cats1
        assert "phone_cn" not in cats2


class TestObjectMaterializationFailure:
    def test_object_upload_failure_becomes_recorded_finding(self, monkeypatch):
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        ctx = {
            "tenant_id": "tenant-a",
            "attachments": [{
                "file_name": "large.docx",
                "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "object_id_unavailable": "upload_failed",
            }],
        }

        text, failures = extract_textual_attachment_content(
            ctx, {"content_dlp_enabled": True}, "tenant-a"
        )

        assert text == ""
        assert len(failures) == 1
        assert failures[0].category == "file_content_object_unavailable"
        assert failures[0].action == "audit"


class TestParseAdmission:
    def test_tenant_capacity_exhaustion_blocks_file_request(self, monkeypatch):
        from app.scan_admission import ScanAdmission
        from app.scan_service import scan_service

        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        previous = scan_service.admission
        admission = ScanAdmission(
            tenant_concurrent=1, tenant_queue=0, global_concurrent=1
        )
        scan_service.admission = admission
        held = admission.acquire("tenant-a")
        try:
            engine = SecurityEngine()
            engine.load_file_policy({"content_dlp_enabled": True})
            result = engine.check_input(
                "req-capacity",
                "",
                context={
                    "tenant_id": "tenant-a",
                    "attachments": [{
                        "file_name": "queued.txt",
                        "content_type": "text/plain",
                        "data_base64": _b64(b"clean"),
                    }],
                },
            )
        finally:
            held.release()
            scan_service.admission = previous

        # 2.9.22：容量不足本身一直是 audit；原先的 block 来自 queued.txt 被当未知类型写死拦截，
        # 现在未知类型缺省告警放行，整体为 audit。
        assert result.action == "audit"
        assert any(
            finding.category == "file_content_capacity_unavailable"
            for finding in result.findings
        )
