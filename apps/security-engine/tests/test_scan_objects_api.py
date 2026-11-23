"""scan-objects API + file_id verdict 端到端测试。

用 TestClient 跑真实 FastAPI 路由（含内部 token 中间件、准入、临时区、registry）。
"""
from __future__ import annotations

import os

import pytest

# 每个测试用独立临时区
_TEST_STORE_DIRS: list = []


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path, monkeypatch):
    d = str(tmp_path / "scanstore")
    os.makedirs(d, exist_ok=True)
    monkeypatch.setenv("SECURITY_SCAN_STORE_DIR", d)
    # 重置 scan_service 单例的 store / registry，让新 env 生效
    from app.scan_service import scan_service
    scan_service._store = None
    scan_service.registry.purge()
    _TEST_STORE_DIRS.append(d)
    yield
    scan_service._store = None
    scan_service.registry.purge()


def _client(monkeypatch):
    # 跳过内部 token（测试无 secret）或设 secret
    monkeypatch.delenv("JJD_INTERNAL_API_SECRET", raising=False)
    from starlette.testclient import TestClient
    import app.main as main_module
    return TestClient(main_module.app)


def test_put_object_returns_object_id_and_sha256(tmp_path, monkeypatch):
    c = _client(monkeypatch)
    body = b"hello large file body " * 100
    resp = c.put("/scan-objects/?tenant_id=t1&file_name=a.bin&content_type=text/plain", content=body)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["object_id"]) >= 16
    assert data["size"] == len(body)
    import hashlib
    assert data["sha256"] == hashlib.sha256(body).hexdigest()


def test_put_object_requires_tenant(monkeypatch):
    c = _client(monkeypatch)
    resp = c.put("/scan-objects/", content=b"x")
    assert resp.status_code == 400


def test_put_object_records_fileid_pending(tmp_path, monkeypatch):
    c = _client(monkeypatch)
    resp = c.put(
        "/scan-objects/?tenant_id=t1&subject=u1&provider=openai&file_id=file-xyz",
        content=b"data",
    )
    assert resp.status_code == 200
    # 查 verdict → pending（尚未检测）
    v = c.get("/scan-objects/verdict?tenant_id=t1&subject=u1&provider=openai&file_id=file-xyz")
    assert v.status_code == 200
    assert v.json()["status"] == "pending"


def test_delete_object(tmp_path, monkeypatch):
    c = _client(monkeypatch)
    resp = c.put("/scan-objects/?tenant_id=t1", content=b"data")
    oid = resp.json()["object_id"]
    d = c.delete(f"/scan-objects/{oid}?tenant_id=t1")
    assert d.status_code == 200


def test_verdict_not_found(tmp_path, monkeypatch):
    c = _client(monkeypatch)
    v = c.get("/scan-objects/verdict?tenant_id=t1&file_id=never")
    assert v.json()["status"] == "not_found"


def test_verdict_tenant_isolation(tmp_path, monkeypatch):
    c = _client(monkeypatch)
    c.put("/scan-objects/?tenant_id=t1&subject=u&provider=p&file_id=f", content=b"d")
    v = c.get("/scan-objects/verdict?tenant_id=t2&subject=u&provider=p&file_id=f")
    assert v.json()["status"] == "not_found"


def test_check_input_does_not_bind_client_file_id(tmp_path, monkeypatch):
    """check-input 检测完把 verdict 记入 registry（block 场景）。"""
    monkeypatch.setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
    monkeypatch.setenv("SECURITY_PII_CHECKSUM", "true")
    c = _client(monkeypatch)
    # 上传含手机号的 docx 并关联 file_id
    import base64, io, zipfile
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    doc = f'<?xml version="1.0"?><w:document xmlns:w="{ns}"><w:body><w:p><w:r><w:t>外发手机13812345678</w:t></w:r></w:p></w:body></w:document>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="text/xml"/></Types>')
        z.writestr("word/document.xml", doc)
    data = buf.getvalue()
    # check-input 引用 file_id + data_base64
    payload = {
        "request_id": "r1",
        "content": "",
        "context": {
            "tenant_id": "t1",
            "user_id": "u1",
            "provider": "openai",
            "attachments": [{
                "file_id": "file-block-1",
                "file_name": "secret.docx",
                "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "data_base64": base64.b64encode(data).decode(),
            }],
        },
    }
    # 引擎需要 file_policy.content_dlp_enabled=true。通过临时注入
    from app.scan_service import scan_service
    # 先用 registry 记录 pending（模拟上传）
    scan_service.registry.record("t1", "u1", "openai", "file-block-1", "pending")
    # 直接调 engine（不经 HTTP，因 file_policy 注入更直接）
    import app.detectors.engine as eng_mod
    eng_mod.engine.load_file_policy({"content_dlp_enabled": True})
    result = eng_mod.engine.check_input("r1", "", context=payload["context"])
    # 未绑定阻断策略的内置检测只告警；客户端声明的 file_id 不能被绑定。
    assert result.action == "audit"
    status, entry = scan_service.registry.lookup("t1", "u1", "openai", "file-block-1")
    assert status == "pending"
    assert entry is not None


def test_bind_endpoint_consumes_token_once(tmp_path, monkeypatch):
    c = _client(monkeypatch)
    from app.scan_service import scan_service

    token = scan_service.registry.issue_binding_token(
        "t1", "u1", "openai", "sha1", "allow"
    )
    resp = c.post(
        "/scan-objects/bind",
        json={
            "tenant_id": "t1",
            "subject": "u1",
            "provider": "openai",
            "binding_token": token,
            "file_id": "file-real-upstream",
            "object": "file",
        },
    )
    assert resp.status_code == 200, resp.text
    verdict = c.get(
        "/scan-objects/verdict?tenant_id=t1&subject=u1&provider=openai&file_id=file-real-upstream"
    )
    assert verdict.json()["status"] == "allow"
    replay = c.post(
        "/scan-objects/bind",
        json={
            "tenant_id": "t1",
            "subject": "u1",
            "provider": "openai",
            "binding_token": token,
            "file_id": "file-replay",
            "object": "file",
        },
    )
    assert replay.status_code == 409


def test_bind_endpoint_requires_verified_file_object(tmp_path, monkeypatch):
    c = _client(monkeypatch)
    from app.scan_service import scan_service

    token = scan_service.registry.issue_binding_token(
        "t1", "u1", "openai", "sha1", "allow"
    )
    resp = c.post(
        "/scan-objects/bind",
        json={
            "tenant_id": "t1",
            "subject": "u1",
            "provider": "openai",
            "binding_token": token,
            "file_id": "file-chat-response",
            "object": "chat.completion",
        },
    )
    assert resp.status_code == 400


def test_check_input_returns_one_time_file_binding_tokens(monkeypatch):
    """check-input must return engine-issued tokens to the gateway."""
    from app.api import check_input as check_input_api
    from app.detectors.engine import FileBindingToken, SecurityCheckResult

    monkeypatch.setattr(
        check_input_api.engine,
        "check_input",
        lambda **kwargs: SecurityCheckResult(
            request_id=kwargs["request_id"],
            findings=[],
            action="allow",
            file_bindings=[FileBindingToken(token="one-time", sha256="sha1")],
        ),
    )
    c = _client(monkeypatch)
    resp = c.post(
        "/check-input/",
        json={"request_id": "r-token", "content": "", "context": {}},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["file_bindings"] == [{"token": "one-time", "sha256": "sha1"}]
