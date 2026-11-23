"""
安全测试 API
用于规则调优和预览
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from app.detectors.engine import engine, SecurityFinding
from app.detectors.hit_display import apply_secret_text_policy

router = APIRouter()


class SecurityTestRequest(BaseModel):
    text: str
    project_id: Optional[str] = None
    model: Optional[str] = None
    client_type: Optional[str] = None


class SecurityTestResponse(BaseModel):
    findings: List[SecurityFinding]
    action: str
    masked_preview: Optional[str] = None
    latency_ms: int


@router.post("/", response_model=SecurityTestResponse)
async def test_security(request: SecurityTestRequest):
    """
    测试安全规则
    用于控制台预览和规则调优
    """
    import time
    start = time.time()

    try:
        result = engine.check_input(
            request_id="test_request",
            content=request.text,
            context={
                "project_id": request.project_id,
                "model": request.model,
                "client_type": request.client_type
            }
        )

        latency = int((time.time() - start) * 1000)

        # 返回掩码预览
        masked_preview = None
        if result.masked_content:
            masked_preview = result.masked_content[:500] + "..." if len(result.masked_content) > 500 else result.masked_content

        # 控制台预览不需要秘密本体，一律不返回。
        return apply_secret_text_policy(SecurityTestResponse(
            findings=result.findings,
            action=result.action,
            masked_preview=masked_preview,
            latency_ms=latency
        ), False)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# FastAPI endpoint, not a pytest test function.
test_security.__test__ = False
