"""Read-only effective policy preview over the engine's current rule pack."""

import hashlib
import json
import os
from typing import List, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.detectors.engine import engine
from app.policy_bindings import PolicyPreviewEvaluation
from app.principal_context import PrincipalContext
from app.rule_pack_loader import DEFAULT_TENANT_ID

router = APIRouter()


class PolicyPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tenant_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    )
    stage: Literal["input", "agent", "output"]
    principal: PrincipalContext


class PolicyPreviewItem(PolicyPreviewEvaluation):
    policy_version: str


class PolicyPreviewResponse(BaseModel):
    tenant_id: str
    stage: Literal["input", "agent", "output"]
    rule_pack_version: str
    identity_version: str
    content_evaluated: Literal[False] = False
    policies: List[PolicyPreviewItem]


def _policy_version(policy) -> str:
    canonical = json.dumps(
        policy.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:16]


@router.post("/", response_model=PolicyPreviewResponse)
async def preview_policies(request: PolicyPreviewRequest):
    configured_tenant = (
        os.getenv("SECURITY_TENANT_ID", DEFAULT_TENANT_ID).strip()
        or DEFAULT_TENANT_ID
    )
    if (
        request.tenant_id != configured_tenant
        or request.principal.tenant_id != request.tenant_id
    ):
        raise HTTPException(status_code=403, detail="tenant mismatch")

    _, policies, _, _, _, rule_pack_version = engine.snapshot_rule_pack_state()
    evaluations = policies.preview(request.stage, request.principal)
    versions = {
        policy.policy_id: _policy_version(policy)
        for policy in policies.policies
    }
    return PolicyPreviewResponse(
        tenant_id=request.tenant_id,
        stage=request.stage,
        rule_pack_version=rule_pack_version,
        identity_version=request.principal.identity_version,
        policies=[
            PolicyPreviewItem(
                **evaluation.model_dump(),
                policy_version=versions[evaluation.policy_id],
            )
            for evaluation in evaluations
        ],
    )
