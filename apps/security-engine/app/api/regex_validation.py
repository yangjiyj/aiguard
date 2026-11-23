import os
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from app.custom_rules import validate_and_compile_regex


router = APIRouter()
MAX_REGEX_VALIDATION_REQUEST_BYTES = 4096


class RegexValidationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    pattern: str


class RegexValidationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    valid: bool
    error_code: Literal["unsafe_regex", "invalid_syntax"] | None


@router.post("/validate", response_model=RegexValidationResponse)
async def validate_regex(
    request: RegexValidationRequest,
) -> RegexValidationResponse:
    # The application-wide middleware validates the token when a secret is
    # configured. This endpoint additionally refuses to operate when the
    # secret is absent, so a deployment mistake cannot expose an internal
    # CPU-consuming validator as an unauthenticated public route.
    if not os.getenv("JJD_INTERNAL_API_SECRET", "").strip():
        raise HTTPException(
            status_code=503,
            detail={"code": "internal_auth_unavailable"},
        )
    if len(request.pattern.encode("utf-8")) > MAX_REGEX_VALIDATION_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"code": "request_too_large"},
        )

    compiled, error_code = validate_and_compile_regex(request.pattern)
    return RegexValidationResponse(
        valid=compiled is not None,
        error_code=error_code,
    )
