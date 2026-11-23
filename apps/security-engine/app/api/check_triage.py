"""误报压制 triage API（异步路径调用，observe-only）。"""
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.detectors.engine import engine

router = APIRouter()


class CheckTriageRequest(BaseModel):
    request_id: str
    content: str = ""
    findings: List[Dict[str, Any]] = []
    content_source: str = ""
    stage: str = "input"


class CheckTriageResponse(BaseModel):
    request_id: str
    findings: List[Dict[str, Any]]


@router.post("/", response_model=CheckTriageResponse)
def check_triage(request: CheckTriageRequest):
    """误报压制标注端点（P2-1：普通 def，FastAPI 自动放线程池执行）。

    engine.check_triage 内部是同步阻塞 urllib（Tier-1 打分 + judge_triage，单次最长
    数秒），若声明为 async def 会锁死 uvicorn 单 worker 的事件循环，把 /check-input
    主链一起拖住排队；改普通 def 后判定在线程池跑，事件循环不受影响。

    线程安全依据（已核）：check_triage 路径对 engine 单例只读——
    - 读的配置属性（fp_suppression_enabled/_tier1_low/_judge_*/_tier1_client/
      _triage_total_budget）全部由 reconfigure_semantic 原子引用替换，无锁自洽；
    - Tier1Client.classify / judge_triage 每次调用独立发 urllib 请求，无共享可变状态；
      模块级熔断器计数在 GIL 下竞态最多差一次计数，语义仍 fail-open；
    - findings 为每请求私有对象，triage 就地标注不触碰引擎状态。
    """
    try:
        annotated = engine.check_triage(
            request_id=request.request_id,
            content=request.content,
            findings=request.findings,
            content_source=request.content_source or None,
            stage=request.stage or "input",
        )
        return CheckTriageResponse(request_id=request.request_id, findings=annotated)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
