"""Internal read-only preview for a proposed custom matcher."""

import json
import os
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, ValidationError

from app.custom_rules import CompiledRule, CustomRuleSet
from app.detectors.engine import engine

router = APIRouter()


class QuickMatcher(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    type: Literal["keyword", "regex"]
    config: dict


class QuickPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    matcher: QuickMatcher | None = None
    capability_categories: list[Literal["email", "phone_cn", "id_card_cn", "bank_card_cn"]] | None = None
    stage: Literal["input", "output"] = "input"
    samples: list[str]


@router.post("/")
async def preview_quick_matcher(http_request: Request):
    if not os.getenv("JJD_INTERNAL_API_SECRET", "").strip():
        raise HTTPException(status_code=503, detail={"code": "internal_auth_unavailable"})
    body = bytearray()
    async for chunk in http_request.stream():
        body.extend(chunk)
        if len(body) > 8192:
            raise HTTPException(status_code=413, detail={"code": "request_too_large"})
    try:
        request = QuickPreviewRequest.model_validate(json.loads(body))
    except (ValidationError, ValueError, UnicodeError, TypeError):
        raise HTTPException(status_code=422, detail={"code": "invalid_request"}) from None
    try:
        sample_sizes = [len(value.encode("utf-8")) for value in request.samples]
    except UnicodeError:
        raise HTTPException(status_code=422, detail={"code": "invalid_request"}) from None
    if len(sample_sizes) > 12 or any(size > 1024 for size in sample_sizes) or sum(sample_sizes) > 4096:
        raise HTTPException(status_code=422, detail={"code": "samples_too_large"})
    builtins = request.capability_categories
    if (request.matcher is None) == (builtins is None) or (builtins is not None and len(builtins) != 1):
        raise HTTPException(status_code=422, detail={"code": "invalid_matcher"})
    if builtins is not None:
        matches = []
        for index, sample in enumerate(request.samples):
            # This is the exact built-in PII detector called by runtime input/output scans.
            finding = next((item for item in engine._detect_regex_pii(sample)
                            if item.category == builtins[0]), None)
            matches.append(_match_result(index, finding))
        return {"matches": matches}
    if request.matcher.type == "keyword":
        if set(request.matcher.config) != {"keywords"}:
            raise HTTPException(status_code=422, detail={"code": "invalid_matcher"})
        keywords = request.matcher.config["keywords"]
        if not isinstance(keywords, list) or not 1 <= len(keywords) <= 20 or not all(
            isinstance(value, str) for value in keywords
        ):
            raise HTTPException(status_code=422, detail={"code": "invalid_matcher"})
        try:
            keyword_sizes = [len(value.encode("utf-8")) for value in keywords]
        except UnicodeError:
            raise HTTPException(status_code=422, detail={"code": "invalid_matcher"}) from None
        if any(size == 0 or size > 256 for size in keyword_sizes):
            raise HTTPException(status_code=422, detail={"code": "invalid_matcher"})
        config = {"keywords": keywords}
    else:
        if set(request.matcher.config) != {"regex"}:
            raise HTTPException(status_code=422, detail={"code": "invalid_matcher"})
        pattern = request.matcher.config["regex"]
        if not isinstance(pattern, str):
            raise HTTPException(status_code=422, detail={"code": "invalid_matcher"})
        try:
            pattern_size = len(pattern.encode("utf-8"))
        except UnicodeError:
            raise HTTPException(status_code=422, detail={"code": "invalid_matcher"}) from None
        if not 0 < pattern_size <= 1000:
            raise HTTPException(status_code=422, detail={"code": "invalid_matcher"})
        config = {"regex": pattern}
    rule = CompiledRule(
        rule_id="quick_preview", rule_name="quick_preview",
        rule_type=request.matcher.type, category="custom", severity="medium",
        action="audit", **config,
    )
    rules = CustomRuleSet([rule])
    if rules.skipped or len(rules.active_rules) != 1:
        raise HTTPException(status_code=422, detail={"code": "invalid_matcher"})
    matches = []
    for index, sample in enumerate(request.samples):
        findings = rules.match(sample)
        if any(f.type == "engine_runtime" for f in findings):
            raise HTTPException(status_code=503, detail={"code": "preview_incomplete"})
        finding = next((item for item in findings if item.type == "custom"), None)
        matches.append(_match_result(index, finding))
    return {"matches": matches}


def _match_result(index, finding):
    return {
        "sample_index": index,
        "matched": finding is not None,
        "location": finding.matched_location if finding else None,
        "redacted_evidence": "<REDACTED>" if finding else None,
    }
