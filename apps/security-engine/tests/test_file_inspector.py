"""P2-2 文件格式管控检视器单元测试（TDD 先行）。

覆盖红线：
- 用魔术字节识别真实类型，绝不信任 content_type / 扩展名
- 伪装可执行、可执行、脚本、未知类型、压缩炸弹按文件策略处置（2.9.22）：
  允许不出命中、告警放行出 alert、禁止出 block；缺省告警放行
- 路径穿越文件名清洗
- 超大文件限制（不做深度解析）
- 证据脱敏红线：只有哈希+元数据，绝不含原始字节
- 无附件早退、坏 base64 优雅跳过、附件数量上限
"""
import base64
import io
import zipfile

import pytest

from app.file_inspector import inspect_attachments
from app import file_inspector


def _att(data: bytes, content_type="application/octet-stream", file_name="f.bin"):
    return {
        "file_name": file_name,
        "content_type": content_type,
        "data_base64": base64.b64encode(data).decode(),
    }


def _ctx(*attachments):
    return {"attachments": list(attachments)}


PNG_MAGIC = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
PE_MAGIC = b"MZ\x90\x00\x03" + b"\x00" * 60          # Windows PE 可执行
ELF_MAGIC = b"\x7fELF\x02\x01\x01" + b"\x00" * 60     # Linux ELF 可执行
PDF_MAGIC = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"0" * 32


def test_no_attachments_returns_empty():
    assert inspect_attachments(None) == []
    assert inspect_attachments({}) == []
    assert inspect_attachments({"attachments": []}) == []
    assert inspect_attachments({"attachments": "not-a-list"}) == []


def test_plain_png_is_allowed_no_finding():
    findings = inspect_attachments(_ctx(_att(PNG_MAGIC, "image/png", "photo.png")))
    assert findings == []


BLOCK_ALL = {
    "executable_action": "block",
    "disguised_executable_action": "block",
    "script_action": "block",
    "unknown_action": "block",
    "zip_bomb_action": "block",
}
SCRIPT_MAGIC = b"#!/bin/sh\nrm -rf /tmp/x\n"
UNKNOWN_BYTES = bytes.fromhex("00010203") + b"opaque-customer-format"


def _zip_bomb() -> bytes:
    # 1MB 全零，压缩后极小 → 压缩比极高，典型压缩炸弹特征
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.bin", b"\x00" * (1024 * 1024))
    return buf.getvalue()


def test_executable_disguised_as_image_is_blocked_when_policy_blocks():
    # 2.9.22：原“伪装可执行必拦”改为按 disguised_executable_action；配成禁止时照拦。
    # 声明 image/png + 扩展名 .png，实际是 PE 可执行 —— 最危险的伪装外发
    findings = inspect_attachments(
        _ctx(_att(PE_MAGIC, "image/png", "cute-cat.png")),
        policy={"disguised_executable_action": "block"},
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "file"
    assert f.action == "block"
    assert f.severity in ("high", "critical")
    assert f.category == "file_disguised_executable"
    assert f.rule_type == "file_fingerprint"
    assert f.rule_id.startswith("file-")
    # 证据脱敏红线：只有哈希+元数据，绝不含原始字节
    assert "sha256:" in f.redacted_evidence
    assert "real=pe" in f.redacted_evidence
    assert "MZ" not in f.redacted_evidence
    assert "\x90" not in f.redacted_evidence
    assert "MZ" not in f.matched_text_preview


def test_real_executable_declared_as_binary_is_blocked_when_policy_blocks():
    # 2.9.22：原“可执行必拦”改为按 executable_action；配成禁止时照拦。
    findings = inspect_attachments(
        _ctx(_att(ELF_MAGIC, "application/octet-stream", "tool.bin")),
        policy={"executable_action": "block"},
    )
    assert len(findings) == 1
    assert findings[0].action == "block"
    assert findings[0].category == "file_executable"
    assert "real=elf" in findings[0].redacted_evidence


# (附件, 类别, 规则编号, 动作字段)：每种文件风险类别三档各验一次。
RISK_CASES = [
    (lambda: _att(PE_MAGIC, "image/png", "cute-cat.png"), "file_disguised_executable", "file-disguised-exec", "disguised_executable_action"),
    (lambda: _att(ELF_MAGIC, "application/octet-stream", "tool.bin"), "file_executable", "file-executable", "executable_action"),
    (lambda: _att(SCRIPT_MAGIC, "application/x-sh", "setup.sh"), "file_script", "file-script", "script_action"),
    (lambda: _att(UNKNOWN_BYTES, "application/octet-stream", "blob.bin"), "file_unknown_type", "file-unknown", "unknown_action"),
    (lambda: _att(_zip_bomb(), "application/zip", "data.zip"), "file_zip_bomb", "file-zip-bomb", "zip_bomb_action"),
]
RISK_IDS = ["disguised", "executable", "script", "unknown", "zip_bomb"]


@pytest.mark.parametrize("make_att,category,rule_id,field", RISK_CASES, ids=RISK_IDS)
def test_file_risk_defaults_to_alert_allow(make_att, category, rule_id, field):
    # 规则包已加载但策略没配这几项（含客户现场那种旧策略 JSON）：一律告警放行，不比 2.9.21 严。
    legacy_site_policy = {
        "allowed_types": ["pdf", "png", "jpeg", "webp", "rar", "7z", "gzip", "bz2", "xz", "archive", "zip"],
        "max_file_mb": 100, "max_zip_ratio": 100, "max_attachments": 10,
    }
    for policy in (file_inspector.normalize_file_policy({}), file_inspector.normalize_file_policy(legacy_site_policy)):
        findings = [f for f in inspect_attachments(_ctx(make_att()), policy=policy) if f.category == category]
        assert len(findings) == 1, (policy, findings)
        assert findings[0].action == "alert"
        assert findings[0].rule_id == rule_id


@pytest.mark.parametrize("make_att,category,rule_id,field", RISK_CASES, ids=RISK_IDS)
def test_file_risk_records_when_rule_pack_missing(make_att, category, rule_id, field):
    # 审查第 5 项：规则包缺失时只记录：留证据，不计安全事件、不告警。
    # 代码质量审查第三轮改动：“缺失”改由加载时打的显式标记判断（占位策略带 rule_pack_loaded=False），
    # 不再从“策略里一项处置都没有”推断，手写的空字典 {} 因此不再算缺失，从本用例去掉。
    for policy in (dict(file_inspector._EMPTY_RUNTIME_POLICY),):
        findings = [f for f in inspect_attachments(_ctx(make_att()), policy=policy) if f.category == category]
        assert len(findings) == 1, (policy, findings)
        finding = findings[0]
        assert finding.action == "allow" and finding.counts_as_security_finding is False
        assert finding.triage.get("disposition") == "observation"
        assert finding.triage.get("disposition_reason") == "rule_pack_missing"
        assert finding.rule_id == rule_id


def test_engine_without_rule_pack_records_file_risk_and_allows(monkeypatch):
    from app import feature_flags as ff
    from app.detectors.engine import SecurityEngine

    monkeypatch.setattr(ff, "_OVERRIDES", {})
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "false")
    previous = file_inspector.snapshot_file_policy()
    file_inspector.replace_file_policy(dict(file_inspector._EMPTY_RUNTIME_POLICY))
    try:
        engine = SecurityEngine()
        result = engine.check_input("no-pack", "附件", _ctx(_att(PE_MAGIC, "image/png", "cat.png")))
    finally:
        file_inspector.replace_file_policy(previous)
    files = [f for f in result.findings if f.type == "file"]
    assert result.action == "allow"
    assert files and files[0].triage.get("disposition_reason") == "rule_pack_missing"


@pytest.mark.parametrize("make_att,category,rule_id,field", RISK_CASES, ids=RISK_IDS)
def test_file_risk_block_when_policy_blocks(make_att, category, rule_id, field):
    findings = [f for f in inspect_attachments(_ctx(make_att()), policy={field: "block"}) if f.category == category]
    assert len(findings) == 1
    assert findings[0].action == "block"
    assert findings[0].rule_id == rule_id


@pytest.mark.parametrize("make_att,category,rule_id,field", RISK_CASES, ids=RISK_IDS)
def test_file_risk_allow_emits_no_finding(make_att, category, rule_id, field):
    findings = inspect_attachments(_ctx(make_att()), policy={field: "allow"})
    assert not any(f.category == category for f in findings)
    assert not any(f.action == "block" for f in findings)


def test_unknown_type_block_survives_confidence_gating(monkeypatch):
    # 未知类型默认 0.4 置信度只留证；管理员显式选“禁止”时不能被门控悄悄压成 audit。
    from app.detectors.engine import SecurityEngine
    monkeypatch.setenv("SECURITY_CONFIDENCE_GATING_ENABLED", "true")
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "false")
    engine = SecurityEngine()
    assert engine.confidence_gating_enabled is True
    blob = _att(UNKNOWN_BYTES, "application/octet-stream", "blob.bin")
    alerted = inspect_attachments(_ctx(blob), policy=file_inspector.normalize_file_policy({}))
    blocked = inspect_attachments(_ctx(blob), policy={"unknown_action": "block"})
    assert engine._determine_action(alerted) == "audit"
    assert engine._determine_action(blocked) == "block"


def test_script_declared_as_image_is_disguised_executable():
    findings = inspect_attachments(_ctx(_att(SCRIPT_MAGIC, "image/png", "logo.png")), policy=BLOCK_ALL)
    assert [f.category for f in findings] == ["file_disguised_executable"]


def test_script_declared_as_source_or_text_is_script_not_disguise():
    for content_type, name in (("text/plain", "run.txt"), ("text/x-python", "tool.py"), ("application/octet-stream", "run")):
        findings = inspect_attachments(_ctx(_att(SCRIPT_MAGIC, content_type, name)), policy=BLOCK_ALL)
        assert [f.category for f in findings] == ["file_script"], (name, findings)


def test_zip_limits_read_from_policy():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(3):  # 3 个条目、3 个嵌套压缩包：恰好不超过环境缺省上限
            zf.writestr(f"inner{i}.zip", b"x" * 1024)
    data = buf.getvalue()
    base = {"zip_bomb_action": "block"}
    assert not any(f.category == "file_zip_bomb" for f in inspect_attachments(_ctx(_att(data, "application/zip", "a.zip")), policy=base))
    for extra, marker in (({"max_zip_entries": 2}, "entries="), ({"max_zip_nested": 2}, "nested=")):
        findings = [f for f in inspect_attachments(_ctx(_att(data, "application/zip", "a.zip")), policy={**base, **extra}) if f.category == "file_zip_bomb"]
        assert len(findings) == 1 and marker in findings[0].redacted_evidence, extra
    big = io.BytesIO()
    with zipfile.ZipFile(big, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", (b"0123456789abcdef" * 4096) * 40)  # 约 2.5MB，压缩比远低于 1000
    findings = [f for f in inspect_attachments(_ctx(_att(big.getvalue(), "application/zip", "big.zip")),
                policy={**base, "max_zip_ratio": 1000, "max_zip_uncompressed_mb": 1}) if f.category == "file_zip_bomb"]
    assert len(findings) == 1 and "uncompressed=" in findings[0].redacted_evidence


def test_normalize_file_policy_validates_new_fields():
    legacy = file_inspector.normalize_file_policy({"allowed_types": ["pdf"], "max_file_mb": 100})
    for field in ("executable_action", "disguised_executable_action", "script_action", "unknown_action",
                  "zip_bomb_action", "unverified_file_reference_action", "file_reference_lookup_failure_action"):
        assert legacy[field] == "alert_allow"
        assert file_inspector.normalize_file_policy({field: "block"})[field] == "block"
        with pytest.raises(ValueError):
            file_inspector.normalize_file_policy({field: "deny"})
        with pytest.raises(ValueError):
            file_inspector.normalize_file_policy({field: True})
    for field in ("max_zip_entries", "max_zip_uncompressed_mb", "max_zip_nested"):
        assert legacy[field] == 0
        assert file_inspector.normalize_file_policy({field: 7})[field] == 7
        with pytest.raises(ValueError):
            file_inspector.normalize_file_policy({field: -1})


def test_type_mismatch_nonexecutable_is_audited_not_blocked():
    # 声明 image/png，实际是 PDF —— 类型不符但非可执行，保守审计不拦截
    findings = inspect_attachments(_ctx(_att(PDF_MAGIC, "image/png", "scan.png")))
    assert len(findings) == 1
    assert findings[0].action == "audit"
    assert findings[0].category == "file_type_mismatch"


def test_zip_bomb_high_ratio_is_blocked_when_policy_blocks():
    # 2.9.22：原“压缩炸弹必拦”改为按 zip_bomb_action；配成禁止时照拦。
    findings = inspect_attachments(
        _ctx(_att(_zip_bomb(), "application/zip", "data.zip")),
        policy={"zip_bomb_action": "block"},
    )
    assert len(findings) == 1
    assert findings[0].action == "block"
    assert findings[0].category == "file_zip_bomb"
    assert "ratio=" in findings[0].redacted_evidence


def test_benign_zip_is_audited():
    # 普通小压缩包：压缩比正常 → 审计而非拦截
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("readme.txt", b"hello world this is a perfectly normal text file")
    findings = inspect_attachments(_ctx(_att(buf.getvalue(), "application/zip", "docs.zip")))
    assert len(findings) == 1
    assert findings[0].action == "audit"
    assert findings[0].category == "file_archive"


def test_path_traversal_filename_is_flagged_and_sanitized():
    findings = inspect_attachments(_ctx(_att(PNG_MAGIC, "image/png", "../../etc/passwd")))
    cats = {f.category for f in findings}
    assert "file_path_traversal" in cats
    pt = next(f for f in findings if f.category == "file_path_traversal")
    assert pt.action in ("alert", "audit", "block")
    # 清洗后的位置/证据不得包含可被当作路径穿越的原始串
    assert ".." not in pt.matched_location
    assert ".." not in pt.redacted_evidence
    assert "/etc/" not in pt.redacted_evidence


def test_oversized_file_is_flagged_and_not_parsed(monkeypatch):
    monkeypatch.setattr(file_inspector, "MAX_FILE_BYTES", 1024)
    big = b"\x00" * 4096
    findings = inspect_attachments(_ctx(_att(big, "application/zip", "big.zip")))
    assert len(findings) == 1
    assert findings[0].category == "file_oversized"
    assert findings[0].action == "audit"


def test_attachment_count_capped(monkeypatch):
    monkeypatch.setattr(file_inspector, "MAX_FILE_ATTACHMENTS", 2)
    atts = [_att(ELF_MAGIC, "application/octet-stream", f"e{i}.bin") for i in range(5)]
    findings = inspect_attachments(_ctx(*atts))
    assert len(findings) == 2


def test_invalid_base64_is_skipped_gracefully():
    ctx = {"attachments": [{"file_name": "x.bin", "content_type": "image/png", "data_base64": "!!!not-base64!!!"}]}
    assert inspect_attachments(ctx) == []


def test_url_only_attachment_without_bytes_is_metadata_only():
    ctx = {
        "attachments": [
            {
                "file_name": "image.png",
                "content_type": "image/png",
                "size": 0,
                "download_url": "https://www.kimi.com/apiv2-files/sign-obj/kimi-fs%2Ffiles%2Fblob%2Fabc?filename=image.png",
            }
        ]
    }
    assert inspect_attachments(ctx) == []


def test_filename_only_metadata_blocks_explicitly_configured_extension():
    ctx = {
        "attachments": [
            {
                "file_name": "report.PDF",
                "content_type": "application/pdf",
                "source": "json_file_metadata",
            }
        ]
    }
    findings = inspect_attachments(ctx, policy={"blocked_types": ["pdf"]})
    blocked = [f for f in findings if f.category == "file_policy_blocked_type"]
    assert len(blocked) == 1
    assert blocked[0].action == "block"
    assert "metadata_only" in blocked[0].redacted_evidence


def test_filename_only_metadata_does_not_block_unconfigured_extension():
    ctx = {
        "attachments": [
            {
                "file_name": "report.pdf",
                "content_type": "application/pdf",
                "source": "json_file_metadata",
            }
        ]
    }
    assert inspect_attachments(ctx, policy={"blocked_types": ["pptx"]}) == []


def test_evidence_never_leaks_raw_secret_like_bytes():
    # 即便文件内容里含疑似密钥串，证据也只应有哈希，绝不回显原文
    payload = PE_MAGIC + b"AKIAIOSFODNN7EXAMPLE_secret_key_material"
    findings = inspect_attachments(_ctx(_att(payload, "image/png", "leak.png")))
    assert len(findings) == 1
    assert "AKIA" not in findings[0].redacted_evidence
    assert "AKIA" not in findings[0].matched_text_preview
    assert "secret_key_material" not in findings[0].redacted_evidence


def test_runtime_file_policy_blocks_configured_safe_type():
    from app.file_inspector import load_file_policy
    try:
        load_file_policy({"blocked_types": ["pdf"]})
        findings = inspect_attachments(_ctx(_att(PDF_MAGIC, "application/pdf", "report.pdf")))
        assert any(f.rule_id == "file-policy-blocked-type:pdf" and f.action == "block" for f in findings)
    finally:
        load_file_policy({})


def test_explicit_policy_snapshot_isolated_from_concurrent_global_policy():
    from app.file_inspector import load_file_policy

    try:
        load_file_policy({"blocked_types": ["pdf"]})
        snapshot = {
            "allowed_types": [],
            "blocked_types": ["png"],
            "review_types": [],
            "max_file_mb": 0,
            "max_zip_ratio": 0,
            "max_attachments": 0,
        }
        pdf_findings = inspect_attachments(
            _ctx(_att(PDF_MAGIC, "application/pdf", "report.pdf")),
            policy=snapshot,
        )
        png_findings = inspect_attachments(
            _ctx(_att(PNG_MAGIC, "image/png", "photo.png")),
            policy=snapshot,
        )
        assert not any(f.category == "file_policy_blocked_type" for f in pdf_findings)
        assert any(f.rule_id == "file-policy-blocked-type:png" for f in png_findings)
    finally:
        load_file_policy({})


def test_runtime_file_policy_enforces_file_size_limit():
    from app.file_inspector import load_file_policy
    try:
        load_file_policy({"max_file_mb": 1})
        payload = b"a" * (2 * 1024 * 1024)
        findings = inspect_attachments(_ctx(_att(payload, "application/pdf", "big.pdf")))
        assert any(f.rule_id == "file-oversized" for f in findings)
    finally:
        load_file_policy({})


def test_runtime_file_policy_blocks_declared_office_type():
    from app.file_inspector import load_file_policy
    docx_like = base64.b64encode(b"PK\x03\x04" + b"0" * 128).decode()
    try:
        load_file_policy({"blocked_types": ["docx"]})
        findings = inspect_attachments({"attachments": [{"file_name": "report.docx", "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "data_base64": docx_like}]})
        assert any(f.rule_id == "file-policy-blocked-type:docx" and f.action == "block" for f in findings)
    finally:
        load_file_policy({})


def test_allowed_declared_text_and_ooxml_types_do_not_fall_through_to_generic_block():
    fixtures = [
        (b"hello", "text/plain", "note.txt", "txt"),
        (b"a,b\n1,2", "text/csv", "data.csv", "csv"),
        (b'{"ok":true}', "application/json", "data.json", "json"),
        (b"PK\x03\x04" + b"0" * 64, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "report.docx", "docx"),
        (b"PK\x03\x04" + b"0" * 64, "application/vnd.openxmlformats-officedocument.presentationml.presentation", "deck.pptx", "pptx"),
        (b"PK\x03\x04" + b"0" * 64, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "book.xlsx", "xlsx"),
    ]
    for payload, content_type, file_name, token in fixtures:
        findings = inspect_attachments(
            _ctx(_att(payload, content_type, file_name)),
            policy={"allowed_types": [token]},
        )
        assert not any(f.action == "block" for f in findings), (token, findings)


def test_executable_policy_token_covers_exe_dll_and_native_binaries():
    fixtures = [
        (PE_MAGIC, "application/octet-stream", "tool.exe"),
        (PE_MAGIC, "application/octet-stream", "library.dll"),
        (ELF_MAGIC, "application/octet-stream", "libagent.so"),
    ]
    for payload, content_type, file_name in fixtures:
        findings = inspect_attachments(
            _ctx(_att(payload, content_type, file_name)),
            policy={"blocked_types": ["executable"]},
        )
        assert any(f.action == "block" for f in findings), (file_name, findings)


# ---- 审查第 1 项：声明为文本、源码的常见类型可被 allowed_types 放开 ----

TEXT_LIKE_FILES = [
    ("a.md", "# 标题\n正文"), ("a.markdown", "# 标题"), ("a.yaml", "key: value\n"), ("a.yml", "key: value\n"),
    ("a.toml", "[a]\nb = 1\n"), ("a.ini", "[a]\nb=1\n"), ("a.xml", "<a/>"), ("a.html", "<p>x</p>"),
    ("a.css", "p { color: red; }"), ("a.log", "2026-11-17 INFO ok"), ("a.sql", "SELECT 1;"),
    ("a.py", "print('hi')\n"), ("a.js", "console.log(1)"), ("a.jsx", "const a = <div/>"),
    ("a.ts", "const a: number = 1"), ("a.tsx", "const a = <div/>"), ("a.go", "package main"),
    ("a.java", "class A {}"), ("a.c", "int main(){}"), ("a.h", "#pragma once"), ("a.cpp", "int main(){}"),
    ("a.cs", "class A {}"), ("a.rb", "puts 1"), ("a.php", "<?php echo 1;"), ("a.rs", "fn main(){}"),
    ("a.kt", "fun main(){}"), ("a.swift", "print(1)"), ("a.scala", "object A"), ("a.vue", "<template/>"),
]


@pytest.mark.parametrize("content_type", ["application/octet-stream", "text/plain"])
def test_allowed_markdown_yaml_python_are_not_unknown(content_type):
    # 复现：allowed_types=["md","yaml","py"]、unknown_action=block 时这三类不能当未知类型拦。
    policy = {"allowed_types": ["md", "yaml", "py"], "unknown_action": "block"}
    for name, text in (("a.md", "# 说明"), ("a.yaml", "key: value\n"), ("a.py", "print('hi')\n")):
        findings = inspect_attachments(_ctx(_att(text.encode(), content_type, name)), policy=policy)
        assert not any(f.category == "file_unknown_type" for f in findings), (name, findings)


@pytest.mark.parametrize("name,text", TEXT_LIKE_FILES, ids=[n for n, _ in TEXT_LIKE_FILES])
def test_allowed_text_and_source_types_are_not_unknown(name, text):
    token = name.rsplit(".", 1)[1]
    policy = {"allowed_types": [token], "unknown_action": "block"}
    findings = inspect_attachments(_ctx(_att(text.encode(), "application/octet-stream", name)), policy=policy)
    assert not any(f.category == "file_unknown_type" for f in findings), (name, findings)
    assert not any(f.action == "block" for f in findings), (name, findings)


def test_text_types_not_in_allowed_list_still_follow_unknown_action():
    findings = inspect_attachments(_ctx(_att(b"# x", "application/octet-stream", "a.md")),
                                   policy={"allowed_types": ["pdf"], "unknown_action": "block"})
    assert any(f.category == "file_unknown_type" and f.action == "block" for f in findings)


def test_shell_script_without_shebang_is_not_declared_text():
    # sh 等脚本不算文本：没有 #! 时仍按未知类型处置，有 #! 时归 file-script。
    policy = {"allowed_types": ["sh", "script"], "unknown_action": "block", "script_action": "block"}
    plain = inspect_attachments(_ctx(_att(b"rm -rf /tmp/x", "application/octet-stream", "a.sh")), policy=policy)
    assert any(f.category == "file_unknown_type" for f in plain)
    shebang = inspect_attachments(_ctx(_att(SCRIPT_MAGIC, "application/octet-stream", "a.sh")), policy=policy)
    assert [f.category for f in shebang] == ["file_script"]


def test_saved_console_default_policy_keeps_executables_on_their_actions():
    # 审查第 2 项（引擎侧）：控制台未保存时显示的默认值原样保存后下发，可执行和脚本仍按
    # executable_action / script_action（缺省告警放行），不会因类型阻断名单被拦。
    saved_default = file_inspector.normalize_file_policy({
        "allowed_types": ["pdf", "png", "jpeg", "webp"], "review_types": ["zip", "gzip", "rar", "7z", "unknown"],
        "max_file_mb": 20, "max_zip_ratio": 100, "max_attachments": 10,
        "executable_action": "alert_allow", "disguised_executable_action": "alert_allow", "script_action": "alert_allow",
        "unknown_action": "alert_allow", "zip_bomb_action": "alert_allow",
    })
    for att in (_att(ELF_MAGIC, "application/octet-stream", "tool.bin"), _att(SCRIPT_MAGIC, "application/x-sh", "a.sh")):
        findings = inspect_attachments(_ctx(att), policy=saved_default)
        assert not any(f.action == "block" for f in findings), findings
        assert any(f.category in {"file_executable", "file_script"} and f.action == "alert" for f in findings)


# ---- 复审补充第 3 项：MIME 与扩展名冲突时不当文本处理 ----

@pytest.mark.parametrize("content_type,name", [
    ("image/png", "a.md"), ("application/pdf", "a.py"), ("application/zip", "a.yaml"),
    ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "a.js"),
])
def test_non_text_mime_with_text_extension_is_not_treated_as_text(content_type, name):
    # 声明的 MIME 是具体的非文本类型、扩展名却是文本类：两者冲突，按未知类型走，不因扩展名放开。
    token = name.rsplit(".", 1)[1]
    policy = {"allowed_types": [token], "unknown_action": "block"}
    findings = inspect_attachments(_ctx(_att(b"plain words", content_type, name)), policy=policy)
    assert any(f.category == "file_unknown_type" and f.action == "block" for f in findings), (content_type, name, findings)


@pytest.mark.parametrize("content_type", ["application/octet-stream", "text/plain", "text/markdown", ""])
def test_generic_or_text_mime_still_uses_text_extension(content_type):
    # 通用二进制（未识别）或本身是文本类的 MIME 不算冲突，扩展名照常参与判断。
    policy = {"allowed_types": ["md"], "unknown_action": "block"}
    findings = inspect_attachments(_ctx(_att(b"# title", content_type, "a.md")), policy=policy)
    assert not any(f.category == "file_unknown_type" for f in findings), (content_type, findings)


# ---- 代码质量审查第三轮第 6 项：声明为文本时先看内容像不像文本 ----

@pytest.mark.parametrize("payload", [
    b"# title\x00\x01\x02binary-tail",                 # 前 8KiB 里有 NUL
    bytes(range(0x80, 0x100)) * 4,                    # 既不是 UTF-8 也不是 GB18030
], ids=["nul", "undecodable"])
def test_declared_text_with_binary_content_is_unknown(payload):
    # 扩展名、MIME 说是 md，内容却是二进制：不能借允许名单放开，按未知类型处置。
    policy = {"allowed_types": ["md"], "unknown_action": "block"}
    findings = inspect_attachments(_ctx(_att(payload, "text/markdown", "a.md")), policy=policy)
    assert any(f.category == "file_unknown_type" and f.action == "block" for f in findings), findings


@pytest.mark.parametrize("payload", [
    "# 标题\n正文".encode("utf-8"),
    "# 标题\n正文".encode("gb18030"),
    ("中" * 4000).encode("utf-8"),                     # 8KiB 截断落在多字节字符中间
], ids=["utf8", "gb18030", "utf8-cut-at-sniff-boundary"])
def test_declared_text_with_text_content_is_allowed(payload):
    policy = {"allowed_types": ["md"], "unknown_action": "block"}
    findings = inspect_attachments(_ctx(_att(payload, "text/markdown", "a.md")), policy=policy)
    assert not any(f.category == "file_unknown_type" for f in findings), findings


# ---- 代码质量审查第三轮：规则包缺失是加载时打的显式标记，不靠字段推断 ----

def test_rule_pack_loaded_marker_is_set_on_load():
    key = file_inspector.RULE_PACK_LOADED_KEY
    assert file_inspector._EMPTY_RUNTIME_POLICY[key] is False
    assert file_inspector.normalize_file_policy({})[key] is True
    assert file_inspector.normalize_file_policy(None)[key] is True


def test_loaded_policy_without_action_fields_is_not_rule_pack_missing():
    # 已加载的策略即使处置字段被裁掉，也按缺省告警放行，不当规则包缺失只记录。
    loaded = file_inspector.normalize_file_policy({})
    for field in file_inspector.FILE_RISK_ACTION_FIELDS:
        loaded.pop(field)
    findings = inspect_attachments(_ctx(_att(PE_MAGIC, "image/png", "cute-cat.png")), policy=loaded)
    assert [f.action for f in findings if f.category == "file_disguised_executable"] == ["alert"], findings


def test_placeholder_policy_is_rule_pack_missing_even_with_action_fields():
    placeholder = dict(file_inspector._EMPTY_RUNTIME_POLICY, disguised_executable_action="block")
    findings = inspect_attachments(_ctx(_att(PE_MAGIC, "image/png", "cute-cat.png")), policy=placeholder)
    finding = next(f for f in findings if f.category == "file_disguised_executable")
    assert finding.action == "allow" and finding.triage.get("disposition_reason") == "rule_pack_missing"


# ---- 复审第四轮：文本核对扫全文 NUL、解码看头尾各 8KiB ----

@pytest.mark.parametrize("tail", [
    b"\x00\x01\x02" * 4096,                     # 后面带 NUL 的二进制
    bytes(range(0x80, 0x100)) * 64,             # 后面不含 NUL、但既不是 UTF-8 也不是 GB18030
], ids=["nul-after-8k", "undecodable-tail"])
def test_text_head_with_binary_tail_renamed_md_is_blocked_as_unknown(tail):
    # 前 8KiB 是文本、后面接二进制，改名 .md：不能借声明文本放开，unknown_action=block 时拦。
    payload = ("# 说明\n" + "正文" * 3000).encode("utf-8") + tail  # 文本约 18KB，二进制在 8KiB 之后
    policy = {"allowed_types": ["md"], "unknown_action": "block"}
    findings = inspect_attachments(_ctx(_att(payload, "text/markdown", "report.md")), policy=policy)
    assert any(f.category == "file_unknown_type" and f.action == "block" for f in findings), findings


@pytest.mark.parametrize("encoding,pad", [("utf-8", ""), ("utf-8", "a"), ("gb18030", ""), ("gb18030", "a")])
def test_long_text_md_is_still_allowed(encoding, pad):
    # 尾部 8KiB 窗口可能从多字节字符中间开始（pad 让对齐错开一个字节），不能因此误判。
    payload = ("# 说明\n" + pad + "正文内容" * 10000).encode(encoding)
    policy = {"allowed_types": ["md"], "unknown_action": "block"}
    findings = inspect_attachments(_ctx(_att(payload, "text/markdown", "report.md")), policy=policy)
    assert not any(f.category == "file_unknown_type" for f in findings), findings


def test_policy_allows_declared_content_requires_data():
    import inspect as _inspect

    param = _inspect.signature(file_inspector._policy_allows_declared_content).parameters["data"]
    assert param.default is _inspect.Parameter.empty


# ---- 合流前次要项：Windows 记事本存的“Unicode”文本（UTF-16 带 BOM）按文本核对 ----

@pytest.mark.parametrize("payload", [
    b"\xff\xfe" + "# 标题\r\n正文内容\r\n".encode("utf-16-le"),                       # 记事本“Unicode”（UTF-16 LE）
    b"\xfe\xff" + ("# 标题\r\n" + "正文内容" * 5000).encode("utf-16-be"),          # UTF-16 BE，超过 8KiB
], ids=["utf16-le-bom", "utf16-be-bom-long"])
def test_utf16_bom_text_is_allowed(payload):
    policy = {"allowed_types": ["txt", "md"], "unknown_action": "block"}
    findings = inspect_attachments(_ctx(_att(payload, "text/plain", "notes.txt")), policy=policy)
    assert not any(f.category == "file_unknown_type" for f in findings), findings


@pytest.mark.parametrize("payload", [
    b"\xff\xfe" + b"\x00\x00" * 64,                         # BOM 后是 NUL 码元
    b"\xff\xfe" + "正文".encode("utf-16-le") + b"\x00",       # 奇数长度，不能完整解码
    b"\xff\xfe" + b"\x00\xd8\x41\x00" * 32,                 # 孤立代理项
], ids=["nul-units", "odd-length", "lone-surrogate"])
def test_utf16_bom_with_binary_is_unknown(payload):
    policy = {"allowed_types": ["txt"], "unknown_action": "block"}
    findings = inspect_attachments(_ctx(_att(payload, "text/plain", "notes.txt")), policy=policy)
    assert any(f.category == "file_unknown_type" and f.action == "block" for f in findings), findings
