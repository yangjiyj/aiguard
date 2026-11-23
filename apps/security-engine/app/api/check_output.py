"""
安全检查输出 API
"""
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict
import time
from app import ocr
from app.bounded_work import BoundedWorkPool, WorkUnavailable, positive_number
from app.file_content_dlp_bridge import file_content_dlp_enabled
from app.detectors.engine import engine, SecurityFinding
from app.detectors.hit_display import WANT_SECRET_TEXT_HEADER, apply_secret_text_policy, want_secret_text
from app.principal_context import PrincipalContext

router = APIRouter()
_OUTPUT_POOL = BoundedWorkPool.from_env("SECURITY_OUTPUT", workers=2, capacity=32)


class CheckOutputRequest(BaseModel):
    request_id: str
    content: str
    content_type: str = "text"
    project_id: Optional[str] = None
    model: Optional[str] = None
    context: Optional[Dict] = None
    # 已知 LLM 协议无法可靠提取最终正文时，只运行确定性数据/内容扫描，
    # 不把原始 JSON/SSE 交给语义攻击裁判。
    skip_semantic: bool = False
    principal: Optional[PrincipalContext] = None


class CheckOutputResponse(BaseModel):
    request_id: str
    findings: List[SecurityFinding]
    action: str
    masked_content: Optional[str] = None
    latency_ms: int
    # P1-A：回带给网关做指纹缓存键 + 上下文重放
    engine_build: str = ""
    rule_pack_version: str = ""
    raw_findings: List[SecurityFinding] = []
    inspection_status: str = "completed"
    semantic_status: str = "not_requested"
    semantic_reason: str = ""
    semantic_config_revision: str = ""


def _run_output_check(request: CheckOutputRequest):
    """
    检查输出内容的安全性
    """
    import time
    start = time.time()

    try:
        content = request.content
        ocr_text = "" if file_content_dlp_enabled() else ocr.extract_ocr_text_from_context(request.context)
        if ocr_text:
            content = ((content or "") + "\n" + ocr_text).strip()

        kwargs = {
            "request_id": request.request_id,
            "content": content,
            "context": request.context,
            "skip_semantic": request.skip_semantic,
        }
        if request.principal is not None:
            kwargs["principal"] = request.principal
        result = engine.check_output(**kwargs)

        latency = int((time.time() - start) * 1000)

        return CheckOutputResponse(
            request_id=result.request_id,
            findings=result.findings,
            action=result.action,
            masked_content=result.masked_content,
            latency_ms=latency,
            engine_build=engine.engine_build,
            rule_pack_version=result.rule_pack_version,
            raw_findings=result.raw_findings,
            semantic_status=result.semantic_status,
            semantic_reason=result.semantic_reason,
            semantic_config_revision=result.semantic_config_revision,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/", response_model=CheckOutputResponse)
async def check_output(
    request: CheckOutputRequest,
    x_jjd_want_secret_text: Optional[str] = Header(None, alias=WANT_SECRET_TEXT_HEADER),
):
    deadline = time.monotonic() + positive_number("SECURITY_OUTPUT_BUDGET_SECONDS", 30.0)
    try:
        result = await _OUTPUT_POOL.run(_run_output_check, request, deadline=deadline)
        return apply_secret_text_policy(result, want_secret_text(x_jjd_want_secret_text))
    except WorkUnavailable as exc:
        reason = "output_" + exc.reason
    except Exception:
        reason = "output_failed"
    raise HTTPException(status_code=503, detail={
        "code": reason, "request_id": request.request_id,
        "inspection_status": "incomplete",
    })
