"""
JJDGuard Security Engine
FastAPI 服务，提供 PII 检测、密钥检测、代码/配置识别，并在启动时从
control-plane 拉取租户自定义规则包、运行期热更新。
"""
import asyncio
import hmac
import logging
import os
from contextlib import asynccontextmanager

import anyio
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import (
    apply_context,
    check_input,
    check_output,
    check_triage,
    corpus,
    policy_preview,
    quick_create_preview,
    regex_validation,
    scan_objects,
    test_security,
)
from app.capability_docs import CapabilityDocError, load_capability_docs
from app.detectors.engine import engine
from app.header_compat import resolve_raw_headers
from app.rule_pack_loader import RulePackConfig, RulePackLoader, run_refresh_loop
from app.startup_selfcheck import (assert_deployment_coordination,
                                  assert_runtime_policy_consistency)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """启动装配：从 control-plane 拉取一次规则包并起后台热更新任务。

    - 未配置 CONTROL_PLANE_URL → 加载器禁用，引擎按内置规则运行（向后兼容）。
    - 启动拉取走线程池（refresh_once 是同步阻塞 httpx 调用），避免阻塞启动事件循环；
      单次失败由 refresh_once 内部吞掉，不阻断服务启动。
    - 关闭时取消后台任务并等待其结束，吞掉 CancelledError 实现优雅停机。
    """
    try:
        if not load_capability_docs():
            raise RuntimeError("capability docs directory is empty")
    except Exception:
        # 打包漏文件或写坏文件时让升级的健康检查发现，而不是悄悄退回旧显示。
        logger.error("capability docs load failed", exc_info=True)
        raise
    # Native OCR initializes process signal handlers. Uvicorn runs lifespan on
    # the main thread; lazy initialization in an HTTP worker would fail.
    from app.file_readiness import file_detection_readiness
    readiness = file_detection_readiness()
    if not readiness["ready"]:
        logger.warning("file capabilities unavailable: %s", readiness["missing"])

    try:
        from app import semantic_config_loader
        semantic_config_loader.start()
    except Exception:
        logger.warning("semantic_config_loader 启动失败，语义配置走 env", exc_info=True)

    assert_runtime_policy_consistency(engine)
    try:
        logger.info("deployment coordination: %s", assert_deployment_coordination())
    except Exception:
        # Coordination misconfiguration is a hard startup error; a valkey
        # outage is handled by the audited runtime degradations instead.
        logger.error("deployment coordination selfcheck failed", exc_info=True)
        raise
    config = RulePackConfig.from_env()
    initial_refresh_task = None
    refresh_task = None
    if config.enabled:
        loader = RulePackLoader(config)
        # 首次拉取也必须后台执行。control-plane 的 Compose 启动依赖
        # security-engine healthy；若在 lifespan 里等待 control-plane，会形成启动环。
        initial_refresh_task = asyncio.create_task(
            anyio.to_thread.run_sync(loader.refresh_and_acknowledge, engine)
        )
        refresh_task = asyncio.create_task(run_refresh_loop(loader, engine))
        logger.info(
            "规则包热更新已启用：tenant=%s，每 %ss 刷新一次",
            config.tenant_id,
            config.effective_refresh_seconds,
        )
    else:
        logger.info("未配置 CONTROL_PLANE_URL，规则包加载器禁用，引擎按内置规则运行")

    # 文件内容 DLP 临时区清理：启动时清孤儿 + 定时清 TTL（设计 §6.3）。
    # scan_service.store 在未配置 SECURITY_SCAN_STORE_DIR 时为 None，reap_all 返回 0。
    from app.scan_service import scan_service
    try:
        scan_service.reap_all()
    except Exception:
        logger.warning("scan store startup reap failed", exc_info=True)

    async def _scan_reaper_loop():
        while True:
            try:
                await asyncio.sleep(60)
                await anyio.to_thread.run_sync(scan_service.reap_all)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.warning("scan store periodic reap failed", exc_info=True)

    reaper_task = asyncio.create_task(_scan_reaper_loop())
    try:
        yield
    finally:
        if initial_refresh_task is not None:
            initial_refresh_task.cancel()
            try:
                await initial_refresh_task
            except asyncio.CancelledError:
                pass
        if refresh_task is not None:
            refresh_task.cancel()
            try:
                await refresh_task
            except asyncio.CancelledError:
                pass
        reaper_task.cancel()
        try:
            await reaper_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="JJDGuard Security Engine",
    description="PII/Secret/Code detection and masking service",
    version="1.0.0",
    lifespan=lifespan,
)


def _cors_origins() -> list[str]:
    raw = os.getenv("SECURITY_ENGINE_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
@app.middleware("http")
async def require_internal_token(request: Request, call_next):
    secret = os.getenv("JJD_INTERNAL_API_SECRET", "").strip()
    if not secret or request.url.path == "/health":
        return await call_next(request)

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


app.include_router(check_input.router, prefix="/check-input", tags=["Security"])
app.include_router(check_output.router, prefix="/check-output", tags=["Security"])
app.include_router(check_triage.router, prefix="/check-triage", tags=["Security"])
app.include_router(apply_context.router, prefix="/apply-context", tags=["Security"])
app.include_router(test_security.router, prefix="/test", tags=["Test"])
app.include_router(regex_validation.router, prefix="/admin/v1/internal/regex", tags=["Internal"])
app.include_router(policy_preview.router, prefix="/admin/v1/internal/policies/preview", tags=["Internal"])
app.include_router(quick_create_preview.router, prefix="/admin/v1/internal/policies/quick-create/preview", tags=["Internal"])
app.include_router(scan_objects.router, prefix="/scan-objects", tags=["ScanObjects"])
app.include_router(corpus.router, prefix="/internal/corpus", tags=["Internal"])


@app.get("/health")
async def health_check():
    from app.runtime_profile import runtime_snapshot
    # status/service keep their historical shape; runtime is additive so the
    # console "service health" page can show the effective resource profile,
    # shared-state mode, judge budget and any degradation without a new API.
    return {"status": "healthy", "service": "security-engine",
            "runtime": runtime_snapshot()}


@app.get("/metrics")
async def metrics():
    """Detection cost metrics. JSON shape; console aggregates by node_id."""
    from app.runtime_profile import runtime_snapshot
    return runtime_snapshot()


@app.get("/ready")
def readiness_check():
    from app.file_readiness import file_detection_readiness
    state = file_detection_readiness()
    return JSONResponse(status_code=200 if state["ready"] else 503, content=state)
