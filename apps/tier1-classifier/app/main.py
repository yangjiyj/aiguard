"""Tier-1 分类器 sidecar：FastAPI HTTP 服务。

POST /classify {text} → {score: float[0..1], label: str}（B-2 接模型推理）。
鉴权：X-JJDGuard-Internal-Token（与 security-engine 同信任域，逐字节对齐其中间件）。
/health 不鉴权。
"""
import hmac
import logging
import os
import math
import asyncio
import time
from app.bounded_work import BoundedWorkPool, WorkUnavailable, positive_number

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app import classifier
from contextlib import asynccontextmanager

from app.model import load_model_scorer
from app.header_compat import resolve_raw_headers
from app.latency_stats import LatencyStats
from app.request_diagnostics import CallTiming, RequestDiagnostics
from app.bounded_work import check_work_budget

logger = logging.getLogger(__name__)
latency_stats = LatencyStats(capacity=512)
request_diagnostics = RequestDiagnostics()
_INFERENCE_POOL = BoundedWorkPool.from_env("TIER1_INFERENCE", workers=1, capacity=8)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """启动装配：懒加载 Tier-1 模型；失败/缺模型不致命（fail-open，服务照起）。"""
    try:
        scorer = load_model_scorer()
    except Exception:  # noqa: BLE001 加载异常绝不阻断服务启动
        logger.warning("Tier-1 模型装配异常，打分器禁用（fail-open）", exc_info=True)
        scorer = None
    classifier.set_scorer(scorer)
    if scorer is None:
        logger.warning("Tier-1 打分器未就绪：/classify 将返 503，调用方 fail-open")
    else:
        logger.info("Tier-1 打分器就绪")
    yield


app = FastAPI(
    title="Tier-1 Classifier",
    description="Prompt-attack probability classifier (ONNX Runtime)",
    version="1.0.0",
    lifespan=lifespan,
)


class ClassifyRequest(BaseModel):
    text: str = Field(max_length=4096)


@app.middleware("http")
async def require_internal_token(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    # Tier-1 使用独立密钥，不得回退复用网关共享内部密钥。
    secret = os.getenv("JJD_TIER1_INTERNAL_TOKEN", "").strip()
    if not secret:
        return JSONResponse(
            status_code=503,
            content={"error": {"code": "internal_auth_not_configured"}},
        )

    token, conflict = resolve_raw_headers(request.scope["headers"])
    if conflict:
        return JSONResponse(
            status_code=401,
            content={"error": {"code": "internal_token_header_conflict"}},
        )
    if not token or not hmac.compare_digest(token, secret):
        return JSONResponse(
            status_code=401,
            content={"error": "invalid internal token"},
        )
    return await call_next(request)


def _request_budget_seconds(request=None):
    configured = positive_number("TIER1_INFERENCE_TIMEOUT_SECONDS", 1.0)
    if request is None:
        return configured
    values = request.headers.getlist("X-JJDGuard-Inference-Budget-Ms")
    if not values:
        return configured
    if len(values) != 1 or len(values[0]) > 12 or not values[0].isdigit():
        raise ValueError("invalid inference budget")
    milliseconds = int(values[0])
    if milliseconds < 1:
        raise ValueError("invalid inference budget")
    # A caller can shorten, never extend the sidecar's configured cap.
    return min(configured, milliseconds/1000.0)

@app.post("/classify")
async def classify(req: ClassifyRequest, request: Request = None):
    import time
    request_diagnostics.begin()
    try:
        budget = _request_budget_seconds(request)
    except ValueError:
        request_diagnostics.record("invalid_budget")
        return JSONResponse(status_code=422, content={"error":{"code":"invalid_inference_budget"},"coverage_complete":False})
    text = req.text or ""
    if not text.strip():
        request_diagnostics.record("empty")
        return {"score":0.0,"label":"benign","coverage_complete":True}
    scorer = classifier.get_scorer()
    if scorer is None:
        request_diagnostics.record("model_not_loaded")
        return JSONResponse(status_code=503, content={"error":{"code":"model_not_loaded"},"coverage_complete":False})
    timing = CallTiming()
    def run_score():
        check_work_budget()
        timing.start()
        try:
            return scorer.score(text)
        finally:
            timing.finish()
    try:
        score,label = await _INFERENCE_POOL.run(run_score, deadline=time.monotonic()+budget)
        score = float(score)
        if not math.isfinite(score):
            raise ValueError("invalid scorer probability")
    except asyncio.CancelledError:
        request_diagnostics.record("client_cancelled")
        raise
    except WorkUnavailable as exc:
        phase = timing.snapshot()
        reason = exc.reason
        if reason == "timeout" and not phase["inference_started"]:
            reason = "queue_timeout"
        code = "inference_"+reason
        request_diagnostics.record(code)
        return JSONResponse(status_code=503, content={
            "error":{"code":code},"coverage_complete":False,"timing":phase})
    except Exception as exc:
        request_diagnostics.record("scorer_failed")
        logger.warning("Tier-1 scorer failed: %s",type(exc).__name__)
        return JSONResponse(status_code=503,content={"error":{"code":"scorer_failed"},"coverage_complete":False})
    phase = timing.snapshot()
    latency_stats.record(phase["total_ms"])
    request_diagnostics.record()
    score = max(0.0,min(1.0,float(score)))
    return {"score":score,"label":str(label),"coverage_complete":True,"timing":phase}


@app.get("/diagnostics")
async def diagnostics():
    return {"scope":"authenticated_schema_valid_classify_calls",
            "requests":request_diagnostics.snapshot(),"pool":_INFERENCE_POOL.snapshot(),
            "inference_timeout_seconds":positive_number("TIER1_INFERENCE_TIMEOUT_SECONDS",1.0)}

def _capacity_runtime():
    """Concurrency this process really runs with.

    An overlay used to pin 2x16 while engine-resource-autotune.sh assumed 8x256;
    the engine then reported ``within_limit`` and the sidecar answered 503 under
    load. The engine compares these numbers with the autotuned profile
    (``tier1_runtime.capacity_matches_profile``), so they must be the effective
    values, evaluated at request time against the live environment.
    """
    return {
        "inference_workers": _INFERENCE_POOL.workers,
        "inference_capacity": _INFERENCE_POOL.capacity,
        "uvicorn_workers": positive_number("TIER1_WORKERS", 1, integer=True),
    }


@app.get("/health")
async def health_check():
    scorer = classifier.get_scorer()
    reported = scorer.runtime_info() if scorer is not None and hasattr(scorer, "runtime_info") else None
    runtime = dict(reported) if isinstance(reported, dict) else {}
    # Capacity is reported even when the model is missing: a sidecar that cannot
    # score still has to tell the engine how much work it would accept.
    runtime.update(_capacity_runtime())
    pool = _INFERENCE_POOL.snapshot()
    return {
        "status": "healthy",
        "service": "tier1-classifier",
        "model_loaded": scorer is not None,
        "runtime": runtime,
        "pool": {key: pool[key] for key in ("in_flight", "rejected", "expired")},
    }


@app.get("/stats")
async def stats():
    """滚动延迟统计(内部 token 鉴权,由 require_internal_token 中间件覆盖)。

    返回最近窗口的 p50/p95(毫秒)与累计**成功打分**次数,供 control-plane
    智能检测控制台展示延迟。纯读快照,不影响打分热路径。

    字段口径(SFIX-2b):scored_count 只统计成功打分次数(打分器 score() 成功返回),
    不含空/空白输入短路与 503(模型未加载/打分器异常)等未打分请求;classify_count
    为其向后兼容别名,同值同义(非收到的 /classify 请求总数)。
    """
    return latency_stats.snapshot()
