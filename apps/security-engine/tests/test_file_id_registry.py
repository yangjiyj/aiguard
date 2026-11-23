"""两阶段 file_id 协议注册表测试（设计 §10）。"""
from __future__ import annotations

import pytest

from app.file_id_registry import FileIDVerdictRegistry


def test_record_allow_then_lookup_allow():
    r = FileIDVerdictRegistry()
    r.record("t1", "user_a", "openai", "file-1", "allow", sha256="sha1", now=1.0)
    status, entry = r.lookup("t1", "user_a", "openai", "file-1", now=1.0)
    assert status == "allow"
    assert entry is not None and entry.sha256 == "sha1"


def test_record_block_then_lookup_block():
    r = FileIDVerdictRegistry()
    r.record("t1", "user_a", "openai", "file-1", "block", now=1.0)
    status, _ = r.lookup("t1", "user_a", "openai", "file-1", now=1.0)
    assert status == "block"


def test_pending_then_lookup_pending():
    r = FileIDVerdictRegistry()
    r.record("t1", "u", "p", "f", "pending", now=1.0)
    status, _ = r.lookup("t1", "u", "p", "f", now=1.0)
    assert status == "pending"


def test_not_found_never_marked_pass():
    r = FileIDVerdictRegistry()
    status, entry = r.lookup("t1", "u", "p", "never-uploaded", now=1.0)
    assert status == "not_found"
    assert entry is None  # 找不到不得标通过


def test_tenant_isolation():
    """同一 file_id 不同 tenant 互不串扰。"""
    r = FileIDVerdictRegistry()
    r.record("t1", "u", "p", "file-x", "allow", now=1.0)
    # tenant_b 查不到 tenant_a 的 file_id
    status, _ = r.lookup("t2", "u", "p", "file-x", now=1.0)
    assert status == "not_found"


def test_subject_isolation():
    """同一 file_id 不同 subject 互不串扰（关联键含 subject）。"""
    r = FileIDVerdictRegistry()
    r.record("t1", "user_a", "p", "file-x", "allow", now=1.0)
    status, _ = r.lookup("t1", "user_b", "p", "file-x", now=1.0)
    assert status == "not_found"


def test_provider_isolation():
    r = FileIDVerdictRegistry()
    r.record("t1", "u", "provider_a", "file-x", "block", now=1.0)
    status, _ = r.lookup("t1", "u", "provider_b", "file-x", now=1.0)
    assert status == "not_found"


def test_ttl_expiry():
    r = FileIDVerdictRegistry(ttl_seconds=10)
    r.record("t1", "u", "p", "f", "allow", now=100.0)
    assert r.lookup("t1", "u", "p", "f", now=109.0)[0] == "allow"
    assert r.lookup("t1", "u", "p", "f", now=120.0)[0] == "not_found"


def test_audit_treated_as_allow():
    """audit verdict 视同放行（留痕但不阻断引用）。"""
    r = FileIDVerdictRegistry()
    r.record("t1", "u", "p", "f", "audit", now=1.0)
    assert r.lookup("t1", "u", "p", "f", now=1.0)[0] == "allow"


def test_quarantine_blocks_reference():
    """quarantine（转审批）引用时拒绝。"""
    r = FileIDVerdictRegistry()
    r.record("t1", "u", "p", "f", "quarantine", now=1.0)
    assert r.lookup("t1", "u", "p", "f", now=1.0)[0] == "block"


def test_blocked_file_no_pass_evidence():
    """被阻断的 file_id，lookup 返回 block —— 调用方据此拒绝，保证阻断文件不到达上游。"""
    r = FileIDVerdictRegistry()
    r.record("t1", "u", "p", "bad", "block", hit_categories=("phone_cn", "id_card_cn"), now=1.0)
    status, entry = r.lookup("t1", "u", "p", "bad", now=1.0)
    assert status == "block"
    assert "phone_cn" in entry.hit_categories


def test_binding_token_is_one_time_and_binds_only_matching_scope():
    r = FileIDVerdictRegistry()
    token = r.issue_binding_token(
        "t1", "u1", "openai", "sha1", "allow", now=1.0
    )
    assert token
    assert r.bind_scanned_file("t2", "u1", "openai", token, "file-x", now=1.0) is False
    assert r.bind_scanned_file("t1", "u1", "openai", token, "file-x", now=1.0) is True
    assert r.lookup("t1", "u1", "openai", "file-x", now=1.0)[0] == "allow"
    assert r.bind_scanned_file("t1", "u1", "openai", token, "file-y", now=1.0) is False


def test_unknown_binding_token_never_creates_file_verdict():
    r = FileIDVerdictRegistry()
    assert r.bind_scanned_file("t1", "u1", "openai", "unknown", "file-x") is False
    assert r.lookup("t1", "u1", "openai", "file-x", now=1.0)[0] == "not_found"
