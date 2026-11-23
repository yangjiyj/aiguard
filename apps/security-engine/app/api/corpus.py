"""训练语料扫描内部接口（规格第 5.3 节）。

- POST /internal/corpus/scan：一批文本只跑敏感数据类检测，返回命中位置和替换后的文本。
- POST /internal/corpus/extract：把 scan-objects 临时区里的 docx/pdf/xlsx 提取成文本，读完即删。

两条接口都受 main.py 的内部令牌中间件保护；未配置内部密钥时直接拒绝。
检测和提取都在独立的 2 线程池里执行，不占用线上检测的线程池。
"""
from __future__ import annotations

import json
import os
import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.bounded_work import BoundedWorkPool, WorkUnavailable, positive_number
from app.corpus_scanner import scan_batch
from app.detectors.engine import engine

router = APIRouter()

CORPUS_POOL = BoundedWorkPool.from_env("SECURITY_CORPUS", workers=2, capacity=4)

MAX_ITEMS = 256
MAX_TEXT_BYTES = 4 * 1024 * 1024
# 请求体上限：文本 4 MB 加 JSON 转义与字段开销的余量；超过直接 413，不整体读入内存。
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_ITEM_ID_CHARS = 128


class CorpusItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(min_length=1, max_length=MAX_ITEM_ID_CHARS)
    text: str


class CorpusScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    items: list[CorpusItem]


class CorpusExtractRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tenant_id: str = Field(min_length=1, max_length=128)
    object_id: str = Field(min_length=1, max_length=128)
    declared_type: Literal["docx", "pdf", "xlsx"]


def _require_internal_secret() -> None:
    if not os.getenv("JJD_INTERNAL_API_SECRET", "").strip():
        raise HTTPException(status_code=503, detail={"code": "internal_auth_unavailable"})


async def _read_body(request: Request, limit: int) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise HTTPException(status_code=413, detail={"code": "request_too_large"})
    return bytes(body)


def _parse(model, body: bytes):
    try:
        return model.model_validate(json.loads(body))
    except (ValidationError, ValueError, UnicodeError, TypeError):
        # 校验错误里会带原文片段，统一换成不含内容的错误码。
        raise HTTPException(status_code=422, detail={"code": "invalid_request"}) from None


def _deadline(name: str, default: float) -> float:
    return time.monotonic() + positive_number(name, default)


@router.post("/scan")
async def scan_corpus(http_request: Request):
    _require_internal_secret()
    request = _parse(CorpusScanRequest, await _read_body(http_request, MAX_BODY_BYTES))
    if len(request.items) > MAX_ITEMS:
        raise HTTPException(status_code=413, detail={"code": "batch_item_limit"})
    try:
        total = sum(len(item.text.encode("utf-8")) for item in request.items)
    except UnicodeError:
        raise HTTPException(status_code=422, detail={"code": "invalid_request"}) from None
    if total > MAX_TEXT_BYTES:
        raise HTTPException(status_code=413, detail={"code": "batch_text_limit"})
    try:
        results, version = await CORPUS_POOL.run(
            scan_batch, request.items, deadline=_deadline("SECURITY_CORPUS_SCAN_BUDGET_SECONDS", 60.0)
        )
    except WorkUnavailable as exc:
        raise HTTPException(status_code=503, detail={"code": "corpus_scan_" + exc.reason}) from None
    except Exception:
        # 检测器异常里可能带被检文本，不外传。
        raise HTTPException(status_code=503, detail={"code": "corpus_scan_failed"}) from None
    return {"items": results, "rule_pack_version": version, "engine_build": engine.engine_build}


def _extract_object(request: CorpusExtractRequest) -> dict:
    from app.file_inspector import _detect_real_type
    from app.file_text_extractor import extract_attachment_text
    from app.scan_service import scan_service
    from app.scan_store import ScanStoreError

    store = scan_service.store
    if store is None:
        raise HTTPException(status_code=503, detail={"code": "scan_store_unavailable"})
    try:
        data = store.read_bytes(request.object_id, request.tenant_id)
    except ScanStoreError:
        raise HTTPException(status_code=404, detail={"code": "object_not_found"}) from None
    try:
        real_type = _detect_real_type(data)
        expected = "pdf" if request.declared_type == "pdf" else "zip"
        if real_type != expected:
            raise HTTPException(status_code=422, detail={"code": "type_mismatch", "real_type": real_type})
        # OOXML 的容器是 ZIP，声明类型只用来选择正文路径（与文件 DLP 的 _effective_extract_type 一致）。
        result = extract_attachment_text(request.declared_type, data)
    finally:
        try:
            store.consume(request.object_id, request.tenant_id)
        except ScanStoreError:
            pass
    if result.error or result.encrypted or result.timeout or (not result.text and not result.complete):
        reason = "encrypted" if result.encrypted else "timeout" if result.timeout else (result.error or "empty")
        raise HTTPException(status_code=422, detail={"code": "extract_failed", "reason": reason})
    return {
        "text": result.text,
        "real_type": real_type,
        "complete": result.complete,
        "truncated": result.truncated,
        "chars": len(result.text),
        "incomplete_reasons": list(result.incomplete_reasons),
    }


@router.post("/extract")
async def extract_corpus_document(http_request: Request):
    _require_internal_secret()
    request = _parse(CorpusExtractRequest, await _read_body(http_request, 4096))
    try:
        return await CORPUS_POOL.run(
            _extract_object, request, deadline=_deadline("SECURITY_CORPUS_EXTRACT_BUDGET_SECONDS", 120.0)
        )
    except HTTPException:
        raise
    except WorkUnavailable as exc:
        raise HTTPException(status_code=503, detail={"code": "corpus_extract_" + exc.reason}) from None
    except Exception:
        raise HTTPException(status_code=503, detail={"code": "corpus_extract_failed"}) from None
