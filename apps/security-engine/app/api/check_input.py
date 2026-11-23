"""
安全检查输入 API
"""
import asyncio
import logging
import os
import time

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field
from app.principal_context import PrincipalContext
from typing import Any, List, Optional, Dict, Literal
from fastapi.responses import JSONResponse
from app.bounded_work import BoundedWorkPool, WorkUnavailable, positive_number
from app.detection_metrics import COUNTERS
from app import ocr
from app.file_content_dlp_bridge import file_content_dlp_enabled
from app.detectors.hit_display import WANT_SECRET_TEXT_HEADER, apply_secret_text_policy, want_secret_text
from app.detectors.engine import (
    engine,
    FileBindingToken,
    SecurityFinding,
)

router = APIRouter()
logger = logging.getLogger(__name__)

_INPUT_POOL = BoundedWorkPool.from_env("SECURITY_INPUT", workers=2, capacity=32)
_BATCH_ITEM_CONCURRENCY_DEFAULT = 2


def _bounded_header(value: Optional[str]) -> int:
    """Advisory metrics header: never let a caller break or poison /metrics."""
    try:
        return min(10000, max(0, int(str(value).strip())))
    except (TypeError, ValueError, OverflowError):
        return 0


def _batch_item_concurrency():
    """Per-batch in-flight item cap (>=1, <= pool capacity).

    One process shares a single GIL; wall-clock regex budgets burn while threads
    wait for it, so fanning a whole batch into the pool only creates timeouts.
    """
    raw = os.getenv("SECURITY_BATCH_ITEM_CONCURRENCY")
    value = _BATCH_ITEM_CONCURRENCY_DEFAULT
    if raw is not None and raw.strip() != "":
        try:
            parsed = int(raw.strip())
            if parsed < 1:
                raise ValueError(raw)
            value = parsed
        except (TypeError, ValueError):
            logger.warning(
                "invalid SECURITY_BATCH_ITEM_CONCURRENCY=%r, falling back to %d",
                raw, _BATCH_ITEM_CONCURRENCY_DEFAULT)
    return max(1, min(value, _INPUT_POOL.capacity))


def _batch_budget_seconds() -> float:
    """Leave transport headroom under the default 20s gateway client budget."""
    return positive_number("SECURITY_BATCH_BUDGET_SECONDS",
                           min(18.0, positive_number("SECURITY_INPUT_BUDGET_SECONDS", 30.0)))



class CheckInputRequest(BaseModel):
    request_id: str
    content: str
    content_type: str = "text"  # text, json, code
    project_id: Optional[str] = None
    model: Optional[str] = None
    agent_type: Optional[str] = None
    client_type: Optional[str] = None
    context: Optional[Dict] = None
    # 输入侧语义异步旁路门控（默认 False = 现行为，全跑）
    skip_semantic: bool = False
    semantic_only: bool = False
    # 语义专用请求必须声明输入或 Agent 阶段；严格枚举阻止未知阶段绕过门控。
    semantic_stage: Literal["input", "agent"] = "input"
    # P1-A：内容来源（system_prompt|user|assistant_history|tool_result|tool_def，可空=不区分走全量）
    content_source: Optional[str] = None
    # P1-A：scope 例外/裁剪透传
    user_id: Optional[str] = None
    principal: Optional[PrincipalContext] = None


class CheckInputResponse(BaseModel):
    request_id: str
    findings: List[SecurityFinding]
    action: str
    masked_content: Optional[str] = None
    redaction_mapping: dict[str, str] = Field(default_factory=dict)
    latency_ms: int
    # P1-A：回带给网关做指纹缓存键 + 上下文重放
    engine_build: str = ""
    rule_pack_version: str = ""
    semantic_config_revision: str = ""
    semantic_status: str = "not_requested"
    semantic_reason: str = ""
    semantic_trace: Optional[Dict[str, Any]] = None
    raw_findings: List[SecurityFinding] = []
    # The gateway must receive one-time tokens before it can bind an upstream file_id.
    file_bindings: List[FileBindingToken] = []
    inspection_status: Literal["completed", "incomplete"] = "completed"
    inspection_reason: str = ""
    # Explicit, machine-readable degradation evidence. Never a silent skip.
    degradation_reasons: List[str] = Field(default_factory=list)


def _run_check(request: CheckInputRequest) -> CheckInputResponse:
    """同步执行体：单条输入安全检查（供单端点与 batch 线程池共用）。"""
    start = time.time()

    content = request.content
    ocr_text = "" if file_content_dlp_enabled() else ocr.extract_ocr_text_from_context(request.context)
    if ocr_text:
        content = ((content or "") + "\n" + ocr_text).strip()

    ctx = dict(request.context or {})
    # 顶层字段兜底进 context（Go 网关已在 context 放 project_id；user_id/content_source 是 P1-A 新增）
    if request.project_id:
        ctx.setdefault("project_id", request.project_id)
    if request.user_id:
        ctx.setdefault("user_id", request.user_id)
    if request.client_type:
        ctx.setdefault("client_type", request.client_type)

    result = engine.check_input(
        request_id=request.request_id,
        content=content,
        context=ctx,
        skip_semantic=request.skip_semantic,
        semantic_only=request.semantic_only,
        semantic_stage=request.semantic_stage,
        agent_type=request.agent_type,
        content_source=request.content_source,
        principal=request.principal,
    )

    latency = int((time.time() - start) * 1000)

    incomplete_reasons = {
        str(finding.triage.get("review_reason") or "engine_scan_incomplete")
        for finding in result.findings
        if finding.category == "engine_scan_incomplete"
        or (
            finding.triage.get("review_status") == "incomplete"
            and finding.triage.get("review_reason") == "triage_total_budget_exhausted"
            # An advisory shadow review never changes the detection/action.
            # Preserve its incomplete review metadata without discarding an
            # otherwise completed scan. Unknown/required review modes remain
            # conservative; engine_scan_incomplete always remains a failure.
            and finding.triage.get("review_mode") != "shadow"
        )
    }
    # Shared-state degradations that could reduce detection coverage or hide a
    # capacity limit must never be silent. They are promoted into
    # inspection_reason (and semantic_status via the incomplete response path).
    from app.shared_state import drain_reasons
    # Everything that degraded is reported (degradation_reasons, /health), but only
    # a degradation that could not prove an inspection invariant (impact=detection)
    # changes this request's verdict. A capacity degradation -- the breaker or the
    # judge budget fell back to process-local state -- leaves the detection itself
    # complete: the buffer is process-global, so promoting it would turn every
    # unrelated request in the next 30 s into an incomplete one.
    degradation_reasons = drain_reasons()
    verdict_reasons = drain_reasons(impact="detection")
    incomplete_reasons.update(verdict_reasons)
    inspection_reason = ",".join(sorted(incomplete_reasons))
    semantic_status = result.semantic_status
    if verdict_reasons and semantic_status == "completed":
        semantic_status = "incomplete"

    return CheckInputResponse(
        request_id=result.request_id,
        findings=result.findings,
        action=result.action,
        masked_content=result.masked_content,
        redaction_mapping=result.redaction_mapping,
        latency_ms=latency,
        engine_build=engine.engine_build,
        rule_pack_version=result.rule_pack_version,
        semantic_config_revision=result.semantic_config_revision,
        semantic_status=semantic_status,
        semantic_reason=result.semantic_reason,
        semantic_trace=result.semantic_trace,
        raw_findings=result.raw_findings,
        file_bindings=result.file_bindings,
        inspection_status="incomplete" if inspection_reason else "completed",
        inspection_reason=inspection_reason,
        degradation_reasons=degradation_reasons,
    )


def _incomplete(request, reason, started):
    # This is an operational result, never an attack or an inspected allow.
    return CheckInputResponse(
        request_id=request.request_id, findings=[], raw_findings=[], file_bindings=[],
        action="audit", latency_ms=int((time.monotonic() - started) * 1000),
        inspection_status="incomplete", inspection_reason=reason,
        semantic_status="incomplete", semantic_reason=reason,
    )


async def _inspect(request, deadline, prefix):
    started = time.monotonic()
    try:
        return await _INPUT_POOL.run(_run_check, request, deadline=deadline)
    except WorkUnavailable as exc:
        return _incomplete(request, prefix + "_" + exc.reason, started)
    except Exception:
        # Detector exceptions may contain inspected content or internal URLs.
        return _incomplete(request, prefix + "_failed", started)


@router.post("", response_model=CheckInputResponse, include_in_schema=False)
@router.post("/", response_model=CheckInputResponse)
async def check_input(
    request: CheckInputRequest,
    x_jjd_want_secret_text: Optional[str] = Header(None, alias=WANT_SECRET_TEXT_HEADER),
):
    deadline = time.monotonic() + positive_number("SECURITY_INPUT_BUDGET_SECONDS", 30.0)
    result = await _inspect(request, deadline, "input")
    if result.inspection_status != "completed":
        # Existing gateway transport-failure policy (including audit-only) decides
        # how to handle an unavailable inspection; never return HTTP 200 allow.
        raise HTTPException(status_code=503, detail={
            "code": result.inspection_reason, "request_id": request.request_id,
            "inspection_status": "incomplete",
        })
    return apply_secret_text_policy(result, want_secret_text(x_jjd_want_secret_text))


@router.post("/batch", response_model=List[CheckInputResponse])
async def check_input_batch(
    requests: List[CheckInputRequest],
    x_jjd_fp_checks: Optional[str] = Header(None, alias="X-JJD-FP-Checks"),
    x_jjd_fp_hits: Optional[str] = Header(None, alias="X-JJD-FP-Hits"),
    x_jjd_want_secret_text: Optional[str] = Header(None, alias=WANT_SECRET_TEXT_HEADER),
):
    """One shared deadline, one immutable request context and result per item.

    HTTP 207 retains completed items and marks each incomplete item. Consumers
    that only support the legacy complete-batch contract reject non-200 and use
    their configured inspection failure policy. No flattening or hidden retry.
    """
    # The gateway is the only component that knows which message segments
    # were served from the scanfp cache. Record its advisory counts even for
    # an empty batch (all segments reused => zero engine work).
    COUNTERS.record_fingerprint_batch(
        _bounded_header(x_jjd_fp_checks), _bounded_header(x_jjd_fp_hits))
    if not requests:
        return []
    limit = positive_number("SECURITY_BATCH_MAX_ITEMS", 128, integer=True)
    if len(requests) > limit:
        raise HTTPException(status_code=413, detail={"code": "batch_item_limit"})
    deadline = time.monotonic() + _batch_budget_seconds()
    # The pool rejects submissions beyond its capacity. A single accepted batch
    # must not reject its own tail as external overload, so admit at most one
    # pool-capacity wave while every item continues to share the same deadline.
    # The per-batch cap (<= capacity) keeps that invariant and also limits GIL
    # contention inside the single-process engine.
    admission = asyncio.Semaphore(_batch_item_concurrency())

    async def inspect_bounded(request):
        async with admission:
            return await _inspect(request, deadline, "batch")

    results = await asyncio.gather(*[
        inspect_bounded(request) for request in requests
    ])
    want = want_secret_text(x_jjd_want_secret_text)
    results = [apply_secret_text_policy(result, want) for result in results]
    if any(result.inspection_status != "completed" for result in results):
        return JSONResponse(status_code=207, content=[
            result.model_dump(mode="json") for result in results
        ])
    return results
