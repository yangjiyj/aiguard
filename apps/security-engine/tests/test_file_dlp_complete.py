"""Regression tests for the complete attachment contract."""

from __future__ import annotations

import base64
import gzip
import io
import tarfile
import zipfile

import pytest

from app import feature_flags as ff
from app.detectors.engine import SecurityEngine
from app.file_inspector import inspect_attachments, load_file_policy


PHONE = "13812345678"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _attachment(data: bytes, content_type: str, file_name: str) -> dict:
    return {
        "data_base64": _b64(data),
        "content_type": content_type,
        "file_name": file_name,
    }


@pytest.fixture
def dlp_engine(monkeypatch):
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    engine = SecurityEngine()
    engine.load_file_policy({"content_dlp_enabled": True})
    yield engine
    load_file_policy({})


def test_reference_only_attachment_is_recorded_when_dlp_is_enabled(dlp_engine):
    # A referenced file the engine cannot read is an inspection gap: recorded,
    # never blocked (only a configured block interrupts traffic).
    result = dlp_engine.check_input(
        "req-reference-only",
        "",
        context={
            "attachments": [
                {
                    "file_name": "report.pdf",
                    "content_type": "application/pdf",
                    "reference_id": "file-remote-1",
                }
            ]
        },
    )
    assert any(
        finding.category == "file_content_object_unavailable"
        and finding.action == "audit"
        for finding in result.findings
    )
    assert result.action == "audit"


def test_zip_text_member_is_scanned_for_sensitive_content(dlp_engine):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.txt", f"客户手机 {PHONE}")
    result = dlp_engine.check_input(
        "req-zip-text",
        "",
        context={
            "attachments": [
                _attachment(buf.getvalue(), "application/zip", "report.zip")
            ]
        },
    )
    assert any(finding.category == "phone_cn" for finding in result.findings)
    # 未绑定阻断策略的内置检测只告警。
    assert result.action == "audit"


@pytest.mark.parametrize("archive_kind", ["tar", "gzip"])
def test_readable_archive_text_member_is_scanned_for_sensitive_content(
    dlp_engine, archive_kind
):
    payload = f"客户手机 {PHONE}".encode()
    if archive_kind == "tar":
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as archive:
            info = tarfile.TarInfo("report.txt")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        data = buf.getvalue()
        content_type = "application/x-tar"
        file_name = "report.tar"
    else:
        data = gzip.compress(payload)
        content_type = "application/gzip"
        file_name = "report.txt.gz"

    result = dlp_engine.check_input(
        f"req-{archive_kind}-text",
        "",
        context={"attachments": [_attachment(data, content_type, file_name)]},
    )
    assert any(finding.category == "phone_cn" for finding in result.findings)
    # 未绑定阻断策略的内置检测只告警。
    assert result.action == "audit"


@pytest.mark.parametrize(
    ("data", "content_type", "file_name"),
    [
        (bytes.fromhex("89504e470d0a1a0a") + bytes(40), "image/png", "photo.png"),
        (bytes.fromhex("d0cf11e0a1b11ae1") + bytes(40), "application/msword", "old.doc"),
        (bytes.fromhex("526172211a0700") + bytes(40), "application/vnd.rar", "archive.rar"),
        (bytes.fromhex("377abcaf271c") + bytes(40), "application/x-7z-compressed", "archive.7z"),
        (b"%PDF-1.7" + bytes(40), "application/pdf", "scan.pdf"),
    ],
)
def test_known_unextractable_file_has_explicit_uninspected_audit(
    dlp_engine, data, content_type, file_name
):
    result = dlp_engine.check_input(
        "req-uninspected",
        "",
        context={
            "attachments": [_attachment(data, content_type, file_name)]
        },
    )
    expected = "file_content_parse_failed" if file_name in {"photo.png", "scan.pdf"} else "file_content_uninspected"
    assert any(finding.category == expected for finding in result.findings)


def test_unknown_file_is_blocked_when_policy_blocks():
    # 2.9.22：原“未知类型必拦”改为按 unknown_action；配成禁止时照拦，缺省告警放行。
    findings = inspect_attachments(
        {
            "attachments": [
                _attachment(bytes.fromhex("00010203") + b"not-a-known-format", "application/octet-stream", "unknown.bin")
            ]
        },
        policy={"unknown_action": "block"},
    )
    assert any(
        finding.category == "file_unknown_type" and finding.action == "block"
        for finding in findings
    )


def test_unknown_file_also_records_uninspected_content_boundary(dlp_engine):
    result = dlp_engine.check_input(
        "req-unknown-content",
        "",
        context={
            "attachments": [
                _attachment(bytes([0, 1]) + b"opaque payload", "application/x-customer-binary", "opaque.bin")
            ]
        },
    )
    assert any(
        finding.category == "file_content_uninspected"
        and finding.action == "audit"
        for finding in result.findings
    )


def test_binding_tokens_require_materialized_bytes(dlp_engine):
    data = b"opaque bytes"
    digest = __import__("hashlib").sha256(data).hexdigest()
    byte_context = {
        "tenant_id": "tenant-binding",
        "user_id": "user-binding",
        "provider": "provider-binding",
        "attachments": [_attachment(data, "application/x-customer-binary", "opaque.bin")],
    }
    result = dlp_engine.check_input("req-binding-bytes", "", context=byte_context)
    assert len(result.file_bindings) == 1
    assert result.file_bindings[0].sha256 == digest

    digest_only_context = {
        **byte_context,
        "attachments": [{
            "content_type": "application/x-customer-binary",
            "file_name": "opaque.bin",
            "sha256": digest,
        }],
    }
    digest_only = dlp_engine.check_input("req-binding-digest-only", "", context=digest_only_context)
    assert digest_only.file_bindings == []
