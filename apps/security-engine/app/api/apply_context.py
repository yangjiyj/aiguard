"""安全上下文重放 API（/apply-context/）。

指纹缓存（Plan B）命中且首见有 findings 时，网关拿首见的 raw_findings 调本端点，
对当前请求上下文重放 编码降档 → 内容例外 → 决策（不重跑正则），得到最终 action。
引擎无状态：只消费传入的 raw_findings 与 context。
"""
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.detectors.engine import engine, SecurityFinding
from app.detectors.hit_display import (WANT_SECRET_TEXT_HEADER, apply_secret_text_policy, restore_secret_text,
                                       want_secret_text)
from app.detectors.severity_downgrade import apply_evidence_downgrades
from app.rule_pack_loader import DEFAULT_TENANT_ID
from app.semantic_enforcement import apply_semantic_enforcement
from app.principal_context import PrincipalContext

router = APIRouter()


class ApplyContextFinding(SecurityFinding):
    model_config = ConfigDict(extra="forbid", strict=True)


class ApplyContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tenant_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    )
    raw_findings: List[ApplyContextFinding] = Field(default_factory=list)
    context: Optional[Dict[str, Any]] = None
    principal: Optional[PrincipalContext] = None


class ApplyContextResponse(BaseModel):
    findings: List[SecurityFinding]
    action: str


@router.post("/", response_model=ApplyContextResponse)
async def apply_context(
    request: ApplyContextRequest,
    x_jjd_want_secret_text: Optional[str] = Header(None, alias=WANT_SECRET_TEXT_HEADER),
):
    configured_tenant = (
        os.getenv("SECURITY_TENANT_ID", DEFAULT_TENANT_ID).strip()
        or DEFAULT_TENANT_ID
    )
    if request.tenant_id != configured_tenant:
        # One engine instance owns exactly one tenant's immutable rule-pack
        # snapshot. Replaying another tenant's cached findings against it would
        # silently apply the wrong policies and exceptions, so fail closed
        # before reading any engine state.
        raise HTTPException(status_code=403, detail="tenant mismatch")
    try:
        ctx = request.context or {}
 # 反序列化为 SecurityFinding（保留 /action/severity 等全部字段）
        findings: List[SecurityFinding] = [
            finding.model_copy(deep=True) for finding in request.raw_findings
        ]
        runtime = engine.snapshot_semantic_runtime()
        # Replay runs on the same protocol source markers as a fresh scan. A cached
        # candidate for a source the administrator excluded must not resurface.
        if not engine._inspection_in_scope(runtime, ctx.get("content_source"), ctx):
            return ApplyContextResponse(findings=[], action="allow")
        if any(engine._needs_full_reinspection(runtime, finding) for finding in findings):
            # This endpoint has raw findings but no complete original message.
            # A stale raw candidate must not resurrect a withdrawn finding.
            # Existing gateway consumers retry the full bounded inspection.
            raise HTTPException(status_code=409, detail="contextual_review_requires_full_input")
        findings = engine._filter_invalid_builtin_rule_pii(findings)
        # 重放：场景策略 → 编码降档 → 内容例外 → 决策（不重跑正则）。
        # 顺序必须与直连检测链一致，否则缓存命中会绕过或改写策略语义。
        _, policies, content_exceptions, _, _, _ = engine.snapshot_rule_pack_state()
        findings = policies.apply(findings, stage="input", principal=request.principal)
        findings = engine._apply_coding_traffic_downgrade(
            findings, ctx, ctx.get("agent_type")
        )
        replay_content = str(ctx.get("content") or "")
        if not replay_content:
            replay_content = "\n".join(
                str(finding.raw_evidence or "") for finding in findings if finding.raw_evidence
            )
        findings = engine._apply_signal_disposition(
            findings,
            replay_content,
            ctx.get("content_source"),
            ctx,
            ctx.get("agent_type"),
        )
        findings = content_exceptions.apply(
            findings,
            project_id=ctx.get("project_id"),
            user_id=ctx.get("user_id"),
            principal=request.principal,
            tenant_id=request.tenant_id,
        )
        # 证据降级与直连链同位置（例外之后、语义闸门之前）。字段名标记来自原文判定、随 raw_findings 缓存；
        # AI 复核降级只发生在上面会 409 的命中上（直连按同一条件写 ai_review_downgrade_eligible），
        # 所以重放不需要复核结论。
        findings = apply_evidence_downgrades(findings)
        # 与直连检测同一语义拦截闸门：完成度取原检测写入 raw finding 的 semantic_run_status。
        findings = apply_semantic_enforcement(findings, policies=policies, principal=request.principal,
                                              stage="input", runtime=runtime)
        action = engine._determine_action(findings, runtime, context=ctx, principal=request.principal, policies=policies)
        # 缓存重放没有原文可供脱敏：原样返回 mask，网关与正向代理据此回退全量检测
        # 并由全量检测真正脱敏；绝不把配置为"脱敏"的规则升级为阻断。
        # 重放没有原文：秘密本体从 raw_evidence 和 evidence_context 重新算出（出错内部兜住，不带内容外冒）。
        want = want_secret_text(x_jjd_want_secret_text)
        if want:
            restore_secret_text(findings)
        return apply_secret_text_policy(ApplyContextResponse(findings=findings, action=action), want)
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001 与其它端点一致的错误封装
        raise HTTPException(status_code=500, detail=str(e))
