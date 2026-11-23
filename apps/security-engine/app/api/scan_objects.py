"""文件扫描对象上传 API（/scan-objects/）。

设计 §4/§8：大文件走 object_id 临时区，不跨服务传完整 base64。
- PUT /scan-objects/：流式上传字节到受限临时区，返回 object_id + sha256 + size；
  经准入控制器（限并发）+ 临时区高水位检查；传入 file_id 只登记不可放行的 pending 占位。
- DELETE /scan-objects/{object_id}：检测完即焚。
- GET /scan-objects/verdict：按 tenant+subject+provider+file_id 查两阶段协议结果。

所有端点受 main.py 的内部 token 中间件保护（与 /check-input/ 同）。
tenant_id/file_id 从查询参数取（事件请求不携带任意路径）。
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.scan_admission import AdmissionError
from app.scan_service import scan_service

router = APIRouter()


def _tenant_required(request: Request) -> str:
    tenant = (request.query_params.get("tenant_id") or "").strip()
    if not tenant:
        raise HTTPException(status_code=400, detail="tenant_id query param is required")
    return tenant


class PutObjectResponse(BaseModel):
    object_id: str
    sha256: str
    size: int
    content_type: str = ""
    file_name: str = ""


@router.put("", response_model=PutObjectResponse)
async def put_object(request: Request):
    """流式接收文件字节到受限临时区。

    查询参数：tenant_id(必填), subject, provider, file_id, file_name, content_type, max_file_mb, request_id。
    返回 object_id（后续 check-input 引用）。准入/高水位/超限 → 503/507/413。
    """
    if not scan_service.has_store():
        raise HTTPException(status_code=503, detail="scan store not configured (SECURITY_SCAN_STORE_DIR)")
    tenant = _tenant_required(request)
    subject = (request.query_params.get("subject") or "").strip()
    provider = (request.query_params.get("provider") or "").strip()
    file_id = (request.query_params.get("file_id") or "").strip()
    file_name = (request.query_params.get("file_name") or "").strip()
    content_type = (request.query_params.get("content_type") or "").strip()
    request_id = (request.query_params.get("request_id") or "").strip()
    max_file_mb = 0
    raw_mb = (request.query_params.get("max_file_mb") or "").strip()
    if raw_mb.isdigit():
        max_file_mb = int(raw_mb)

    # 准入控制：限租户并发/全局容量；普通文字请求不走本端点故不受影响
    try:
        slot = scan_service.admission.acquire(tenant, timeout=0.5)
    except AdmissionError as exc:
        raise HTTPException(status_code=503, detail=f"scan admission denied: {exc}")

    try:
        # 真流式：异步 request.stream() 块经线程安全队列喂给同步 receive_stream（线程池跑，
        # 不在事件循环线程做阻塞磁盘 I/O；不把整个文件缓存进 chunks 列表）。
        import queue as _queue
        from starlette.concurrency import run_in_threadpool

        q: "_queue.Queue[object]" = _queue.Queue(maxsize=32)
        _SENTINEL = object()

        async def _pump():
            try:
                async for chunk in request.stream():
                    await asyncio.to_thread(q.put, chunk)
            finally:
                await asyncio.to_thread(q.put, _SENTINEL)

        def _sync_iter():
            while True:
                item = q.get()
                if item is _SENTINEL:
                    return
                yield item  # type: ignore[misc]

        max_bytes = max_file_mb * 1024 * 1024 if max_file_mb > 0 else None

        pump_task = asyncio.create_task(_pump())
        try:
            obj = await run_in_threadpool(
                scan_service.store.receive_stream,  # type: ignore[union-attr]
                tenant_id=tenant,
                request_id=request_id or f"upload:{file_id or file_name or 'adhoc'}",
                stream=_sync_iter(),
                content_type=content_type,
                file_name=file_name,
                max_file_bytes=max_bytes,
            )
        finally:
            if not pump_task.done():
                pump_task.cancel()
            try:
                await pump_task
            except BaseException:
                pass
    except HTTPException:
        raise
    except Exception as exc:
        msg = str(exc)
        if "high_watermark" in msg:
            raise HTTPException(status_code=507, detail="scan store disk high watermark reached")
        if "exceeds_max_bytes" in msg:
            raise HTTPException(status_code=413, detail="file exceeds max bytes")
        raise HTTPException(status_code=503, detail=f"scan store receive failed: {msg}")
    finally:
        slot.release()

    # 兼容旧客户端的 pending 占位不可放行；可信 verdict 只由 binding token 消费写入。
    if file_id:
        scan_service.registry.record(
            tenant=tenant, subject=subject, provider=provider, file_id=file_id,
            verdict="pending", sha256=obj.sha256,
        )

    return PutObjectResponse(
        object_id=obj.object_id, sha256=obj.sha256, size=obj.size,
        content_type=content_type, file_name=file_name,
    )


@router.delete("/{object_id}")
async def delete_object(object_id: str, request: Request):
    """检测完即焚：从临时区删除对象。"""
    if not scan_service.has_store():
        raise HTTPException(status_code=503, detail="scan store not configured")
    tenant = _tenant_required(request)
    try:
        scan_service.store.consume(object_id, tenant)  # type: ignore[union-attr]
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"object not removable: {exc}")
    return {"deleted": object_id}


class VerdictResponse(BaseModel):
    status: str  # allow | block | pending | not_found
    hit_categories: list = []
    sha256: str = ""


class BindObjectRequest(BaseModel):
    tenant_id: str
    subject: str = ""
    provider: str = ""
    binding_token: str
    file_id: str
    object: str = ""


class BindObjectResponse(BaseModel):
    status: str


@router.get("/verdict", response_model=VerdictResponse)
async def get_verdict(request: Request):
    """两阶段 file_id 协议：查 file_id 的检测结果。

    查询参数：tenant_id(必填), subject, provider, file_id(必填)。
    返回 status：allow(可使用) / block(拒绝) / pending(未完成) / not_found(不得标通过)。
    """
    tenant = _tenant_required(request)
    file_id = (request.query_params.get("file_id") or "").strip()
    if not file_id:
        raise HTTPException(status_code=400, detail="file_id query param is required")
    subject = (request.query_params.get("subject") or "").strip()
    provider = (request.query_params.get("provider") or "").strip()
    status, entry = scan_service.registry.lookup(tenant, subject, provider, file_id)
    return VerdictResponse(
        status=status,
        hit_categories=list(entry.hit_categories) if entry else [],
        sha256=entry.sha256 if entry else "",
    )


@router.post("/bind", response_model=BindObjectResponse)
async def bind_object(request: BindObjectRequest):
    """Consume a scan binding token for a verified upstream object.

    The gateway must validate the upstream response object/file contract before
    calling this internal endpoint. The token is still scope-checked and
    one-time here, so replay and cross-tenant/provider binding fail closed.
    """
    tenant = request.tenant_id.strip()
    if (
        not tenant
        or not request.binding_token.strip()
        or not request.file_id.strip()
        or request.object.strip().lower() != "file"
    ):
        raise HTTPException(
            status_code=400,
            detail="tenant_id, binding_token, file_id and object=file are required",
        )
    bound = scan_service.registry.bind_scanned_file(
        tenant=tenant,
        subject=request.subject.strip(),
        provider=request.provider.strip(),
        token=request.binding_token.strip(),
        file_id=request.file_id.strip(),
    )
    if not bound:
        raise HTTPException(status_code=409, detail="binding token is invalid, expired, or already used")
    return BindObjectResponse(status="bound")
