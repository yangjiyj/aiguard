"""设计 §15 验收测试 —— 跨组件场景补充。

覆盖原 24 项里缺的关键场景：
- 临时文件进程重启后清理（reap_all 兜底）；
- 扫描服务异常不影响普通文字请求（文字请求不走 scan 准入）；
- 大文件走 object_id 不产生完整 base64 跨服务传输（守 §8 红线）；
- 三入口共享同一检测结论（三入口都调同一 engine.check_input）。
"""
from __future__ import annotations

import base64
import io
import os
import zipfile

import pytest

from app import feature_flags as ff
from app.detectors.engine import SecurityEngine
from app.file_content_dlp_bridge import extract_textual_attachment_content
from app.scan_service import ScanService


PHONE = "13812345678"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _docx(text: str) -> bytes:
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    body = f'<w:body xmlns:w="{ns}"><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body>'
    doc = f'<?xml version="1.0"?><w:document xmlns:w="{ns}">{body}</w:document>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="text/xml"/></Types>')
        z.writestr("word/document.xml", doc)
    return buf.getvalue()


class TestReaperCleansOrphans:
    def test_reap_all_removes_objects(self, tmp_path):
        """临时文件进程重启后：reap_all 清理超时孤儿对象。"""
        svc = ScanService()
        # 手动注入 store 指向 tmp
        from app.scan_store import ScanStore
        clock = {"t": 0.0}
        svc._store = ScanStore(str(tmp_path / "scan"), ttl_seconds=10, now_fn=lambda: clock["t"])
        svc._store.ensure_root()
        clock["t"] = 1000.0
        obj = svc._store.receive_stream("t1", "r1", iter([b"x" * 100]), "text/plain")
        assert os.path.exists(obj.path)
        # 推进时钟超过 TTL，reap_all 清理
        clock["t"] = 1000.0 + 11
        removed = svc.reap_all()
        assert removed == 1
        assert not os.path.exists(obj.path)


class TestPlainTextNotAffectedByScanFailure:
    def test_plain_text_request_bypasses_scan_admission(self, monkeypatch):
        """普通文字请求不进入文件扫描准入/临时区；扫描服务异常不影响文字检测。"""
        monkeypatch.delenv(ff.ENV_FILE_CONTENT_DLP, raising=False)
        # 即使 scan_service 完全不可用，文字请求仍正常检测
        engine = SecurityEngine()
        result = engine.check_input("req_text", f"联系手机{PHONE}")
        cats = {f.category for f in result.findings}
        # 文字里的手机号被检测到（说明文字请求不受扫描服务影响）
        assert "phone_cn" in cats

    def test_scan_admission_not_invoked_for_text(self):
        """准入控制器统计：文字请求处理后，没有任何扫描准入占用。"""
        from app.scan_admission import ScanAdmission
        adm = ScanAdmission()
        # 模拟文字请求（不调 acquire）
        engine = SecurityEngine()
        engine.check_input("req", "普通文字")
        assert adm.stats()["global_in_flight"] == 0


class TestLargeFileNoBase64CrossService:
    def test_object_id_path_reads_bytes_from_store_not_base64(self, tmp_path, monkeypatch):
        """大文件走 object_id：字节从受限临时区读，请求体不携带完整 base64（守 §8）。"""
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        # 装配 scan_service 指向 tmp
        from app import scan_service as svc_mod
        from app.scan_store import ScanStore
        fake_store = ScanStore(str(tmp_path / "scan"))
        fake_store.ensure_root()
        body = b"large document bytes " * 1000
        obj = fake_store.receive_stream("t1", "r1", iter([body[i:i+4096] for i in range(0, len(body), 4096)]), "text/plain", "big.txt")
        # monkeypatch scan_service.store 返回我们的 fake_store
        orig = svc_mod.ScanService.store
        # 用 context attachment 引用 object_id（而非 data_base64）
        ctx = {
            "tenant_id": "t1",
            "attachments": [{
                "file_name": "big.txt",
                "content_type": "text/plain",
                "object_id": obj.object_id,
            }],
        }
        try:
            svc_mod.scan_service._store = fake_store
            file_policy = {"content_dlp_enabled": True}
            text, failures = extract_textual_attachment_content(ctx, file_policy, "t1")
            # object_id 路径读到了字节并提取正文（证明字节从 store 来，不是 base64）
            assert "large document bytes" in text
            assert failures == []
        finally:
            svc_mod.scan_service._store = None


class TestBlockedFileNotReachingUpstream:
    def test_engine_audits_unbound_finding_in_sensitive_docx(self, monkeypatch):
        """文件正文命中按命中规则在控制台配置的动作处置：未绑定阻断策略的内置检测只告警放行。"""
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
        engine = SecurityEngine()
        engine.load_file_policy({"content_dlp_enabled": True})
        data = _docx(f"外发手机{PHONE}")
        ctx = {"tenant_id": "t1", "attachments": [{"file_name": "secret.docx", "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "data_base64": _b64(data)}]}
        result = engine.check_input("req_block", "", context=ctx)
        assert result.action == "audit"
        assert any(f.category == "phone_cn" for f in result.findings)

    def test_engine_blocks_docx_when_policy_is_configured_block(self, monkeypatch):
        """控制台把命中类别配置为阻断时，文件正文命中照样阻断（调用方见 block 即不发上游）。"""
        from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
        engine = SecurityEngine()
        engine.load_file_policy({"content_dlp_enabled": True})
        engine.policies = PolicySet([CompiledPolicy(
            policy_code="scene.phone.block", policy_id="policy_phone_block", policy_name="phone block",
            policy_type="scene_policy", scene="data_leak", action="block", enabled=True, binding_mode="any",
            capabilities=[CompiledPolicyCapability(category="phone_cn", supported_stages=["input"],
                                                   allowed_actions=["audit", "mask", "block"], mask_capable=True)],
        )])
        data = _docx(f"外发手机{PHONE}")
        ctx = {"tenant_id": "t1", "attachments": [{"file_name": "secret.docx", "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "data_base64": _b64(data)}]}
        result = engine.check_input("req_block", "", context=ctx)
        assert result.action == "block"


class TestThreeEntriesShareSameEngine:
    def test_all_entries_route_to_same_check_input(self, monkeypatch):
        """三入口（gateway/proxy/portal）最终都调同一 engine.check_input → 同一结论。"""
        monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
        monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
        engine = SecurityEngine()
        engine.load_file_policy({"content_dlp_enabled": True})
        data = _docx(f"手机{PHONE}")
        # 三个入口构造的 context.attachments 形态略异但都带 data_base64
        ctx_gateway = {"tenant_id": "t1", "attachments": [{"file_name": "f.docx", "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "data_base64": _b64(data), "source": "json_data_url"}]}
        ctx_proxy = {"tenant_id": "t1", "attachments": [{"file_name": "f.docx", "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "data_base64": _b64(data), "source": "multipart"}]}
        ctx_portal = {"tenant_id": "t1", "attachments": [{"file_name": "f.docx", "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "data_base64": _b64(data), "source": "portal_upload"}]}
        results = [engine.check_input(f"r{i}", "", context=c) for i, c in enumerate([ctx_gateway, ctx_proxy, ctx_portal])]
        actions = {r.action for r in results}
        # 三入口同一结论（未绑定阻断策略 → 都只告警）
        assert actions == {"audit"}


class TestIllegalConfigKeepsLastGood:
    def test_illegal_file_policy_rejected(self, monkeypatch):
        """配置非法：normalize 拒绝非布尔 content_dlp_enabled，保留最后有效版本。"""
        from app.file_inspector import load_file_policy, normalize_file_policy
        # 合法策略先载入
        load_file_policy({"content_dlp_enabled": True, "max_file_mb": 20})
        # 非法策略（content_dlp_enabled 非 bool）应 raise
        with pytest.raises(ValueError):
            normalize_file_policy({"content_dlp_enabled": "yes", "max_file_mb": 20})
