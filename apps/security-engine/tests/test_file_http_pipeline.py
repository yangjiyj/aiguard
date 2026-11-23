"""Real file extraction through HTTP routes and bounded ASGI workers."""
import asyncio
import base64
from pathlib import Path
import httpx
import pytest
from fastapi import FastAPI
from app import feature_flags as ff
from app.api import check_input, check_output
from app.detectors.engine import SecurityEngine

FIXTURES = Path(__file__).parent / "fixtures/file_detection"

@pytest.mark.parametrize("stage", ["input", "output"])
@pytest.mark.parametrize("audit", [False, True])
@pytest.mark.parametrize("name", ["chinese-phone.pdf", "chinese-phone.png", "scanned-chinese-phone.pdf"])
def test_enabled_file_dlp_http_pipeline(monkeypatch, stage, audit, name):
    pytest.importorskip("pypdf")
    pytest.importorskip("tesserocr")
    ff.apply_overrides({})
    monkeypatch.setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", str(audit).lower())
    instance = SecurityEngine()
    api = check_input if stage == "input" else check_output
    monkeypatch.setattr(api, "engine", instance)
    app = FastAPI()
    app.include_router(api.router, prefix="/check-" + stage)
    payload = {
        "request_id": "real-file-http",
        "content": "普通业务说明",
        "skip_semantic": True,
        "context": {"attachments": [{
            "file_name": name,
            "content_type": "image/png" if name.endswith("png") else "application/pdf",
            "data_base64": base64.b64encode((FIXTURES / name).read_bytes()).decode(),
        }]},
    }
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            return await client.post("/check-" + stage + "/", json=payload)
    response = asyncio.run(run())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["request_id"] == payload["request_id"]
    assert body["inspection_status"] == "completed"
    # 附件正文的内置检测未绑定阻断策略：两种模式都只告警。
    assert body["action"] == "audit"
    assert any(f["category"] == "phone_cn" and f["content_source"] == "file_attachment" for f in body["raw_findings"])
    assert not any(f["category"].startswith("file_content_") or f["type"] in {"engine_runtime", "semantic_telemetry"} for f in body["raw_findings"])
