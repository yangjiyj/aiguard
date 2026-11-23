"""Strict runtime DTO and evaluator for capability-bound policies."""

from __future__ import annotations

from typing import Any, List, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.detectors.severity_downgrade import SEVERITY_INDEX
from app.principal_context import PrincipalContext
from app.semantic_enforcement import (SEMANTIC_CONTEXT_CATEGORY, is_context_judge_verdict,
                                      policy_match_categories)


_SEMANTIC_OBSERVE_ONLY_FINDING_TYPES = frozenset(
    {"semantic_attack", "semantic_telemetry"}
)
_RUNTIME_FAIL_CLOSED_FINDING_TYPES = frozenset(
    {"regex_timeout", "custom_scan_incomplete"}
)
_RUNTIME_AUDIT_ONLY_FINDING_TYPES = frozenset({"engine_runtime"})


def _effective_policy_action(
    finding: Any,
    requested_action: str,
    semantic_action: str = "audit",
    stage: str = "input",
) -> str:
    """Map a policy's configured action onto one finding.

    A semantic judge opinion follows the policy's separate console choice
    ``semantic_action`` (default audit), never the policy action used for
    deterministic findings: shipped policies such as role-play detection carry
    ``action=block`` for keywords, and upgrading must not silently start
    blocking on the probabilistic opinion bound to the same policy. ``block``
    here is only a request; app.semantic_enforcement keeps it solely for a
    completed, high-confidence verdict in protect mode at a stage the console
    enabled (semantic_block_stages, default input only). Output-side semantic
    analysis is never run, so its opinions stay audit.
    """
    if getattr(finding, "type", "") in _RUNTIME_AUDIT_ONLY_FINDING_TYPES:
        return "audit"
    if getattr(finding, "type", "") in _RUNTIME_FAIL_CLOSED_FINDING_TYPES:
        # An incomplete scan is recorded, never enforced (2026-09-23).
        return "audit"
    if getattr(finding, "counts_as_security_finding", True) is False:
        return "allow"
    if getattr(finding, "type", "") == "semantic_attack":
        if stage in {"input", "agent"} and semantic_action == "block":
            return "block"
        return "audit"
    if (
        getattr(finding, "rule_type", "") == "semantic"
        or getattr(finding, "type", "") in _SEMANTIC_OBSERVE_ONLY_FINDING_TYPES
    ):
        return "audit"
    return requested_action


def _policy_categories(finding: Any, policy: Any) -> frozenset:
    """该策略视角下 finding 可命中的能力类别。

    只有启用、且「智能分析命中时」为拦截/仅记录的策略，才把上下文裁判结论（不分攻击类型）
    映射到它绑定的任一语义能力；其余策略（含出厂预置与缺省 audit 的存量策略、停用策略）
    按原类别精确匹配，行为与扩展前逐一相同。
    """
    if policy.enabled and policy.semantic_action in ("block", "observe"):
        return policy_match_categories(finding)
    return frozenset({getattr(finding, "category", "")})


def _finding_matched_capabilities(finding: Any, policy: Any, matched: List[str]) -> List[str]:
    """上下文裁判结论如实记为 prompt_input_semantic_risk，后跟它借以命中的绑定能力。"""
    if not is_context_judge_verdict(finding):
        return list(matched)
    own = _policy_categories(finding, policy)
    return [SEMANTIC_CONTEXT_CATEGORY] + [c for c in matched if c in own and c != SEMANTIC_CONTEXT_CATEGORY]


def _semantic_observe_update(finding: Any, semantic_action: str) -> dict:
    """「仅记录」：保留语义证据，但不计为安全发现、不产生告警。"""
    if (
        semantic_action != "observe"
        or getattr(finding, "type", "") != "semantic_attack"
        or getattr(finding, "counts_as_security_finding", True) is False
    ):
        return {}
    return {
        "counts_as_security_finding": False,
        "action": "allow",
        "triage": {
            **finding.triage,
            "disposition": "observation",
            "disposition_reason": "policy_semantic_observe",
        },
    }


class CompiledPolicyCapability(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    category: str
    supported_stages: List[Literal["input", "agent", "output"]]
    allowed_actions: List[Literal["audit", "mask", "block"]]
    mask_capable: bool

    @field_validator("category")
    @classmethod
    def nonblank_category(cls, value: str) -> str:
        if not value or value != value.strip():
            raise ValueError("policy capability category must be non-blank and trimmed")
        return value

    @model_validator(mode="after")
    def valid_contract(self):
        if not self.supported_stages or len(set(self.supported_stages)) != len(
            self.supported_stages
        ):
            raise ValueError("policy capability stages must be non-empty and unique")
        if not self.allowed_actions or len(set(self.allowed_actions)) != len(
            self.allowed_actions
        ):
            raise ValueError("policy capability actions must be non-empty and unique")
        if self.mask_capable != ("mask" in self.allowed_actions):
            raise ValueError("mask capability contract is inconsistent")
        return self


class SubjectBindingMatchDetail(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    dimension: Literal[
        "tenant_ids",
        "actor_user_ids",
        "key_owner_user_ids",
        "personnel_department_ids",
        "project_ids",
        "application_department_ids",
        "key_ids",
        "protocols",
        "entry_points",
        "model_ids",
    ]
    configured_values: List[str]
    matched: bool
    reason: Literal[
        "matched",
        "principal_missing",
        "actor_not_authenticated",
        "principal_value_missing",
        "no_configured_value_matched",
    ]
    include_children: bool = False


class SubjectBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tenant_ids: List[str] = Field(default_factory=list)
    actor_user_ids: List[str] = Field(default_factory=list)
    key_owner_user_ids: List[str] = Field(default_factory=list)
    personnel_department_ids: List[str] = Field(default_factory=list)
    personnel_department_include_children: bool = False
    project_ids: List[str] = Field(default_factory=list)
    application_department_ids: List[str] = Field(default_factory=list)
    key_ids: List[str] = Field(default_factory=list)
    protocols: List[str] = Field(default_factory=list)
    entry_points: List[str] = Field(default_factory=list)
    model_ids: List[str] = Field(default_factory=list)

    @field_validator(
        "tenant_ids", "actor_user_ids", "key_owner_user_ids",
        "personnel_department_ids", "project_ids", "application_department_ids",
        "key_ids", "protocols", "entry_points", "model_ids",
    )
    @classmethod
    def canonical_values(cls, values: List[str], info) -> List[str]:
        if any(not value or value != value.strip() or len(value) > 256 for value in values):
            raise ValueError(f"{info.field_name} contains an invalid binding")
        if values != sorted(set(values)):
            raise ValueError(f"{info.field_name} must be sorted and unique")
        if info.field_name in {"protocols", "entry_points"} and any(value != value.lower() for value in values):
            raise ValueError(f"{info.field_name} must be lowercase")
        return values

    @model_validator(mode="after")
    def valid_department_expansion(self):
        if self.personnel_department_include_children and not self.personnel_department_ids:
            raise ValueError("department child expansion requires a department binding")
        return self

    def match_details(
        self,
        principal: PrincipalContext | None,
    ) -> List[SubjectBindingMatchDetail]:
        actor_departments = set(
            principal.actor_department_ids if principal is not None else []
        )
        if principal is not None and self.personnel_department_include_children:
            actor_departments.update(principal.actor_department_ancestor_ids)
        values = (
            ("tenant_ids", self.tenant_ids, [principal.tenant_id] if principal else [], False),
            ("actor_user_ids", self.actor_user_ids, [principal.actor_user_id] if principal else [], True),
            ("key_owner_user_ids", self.key_owner_user_ids, [principal.key_owner_user_id] if principal else [], False),
            (
                "personnel_department_ids",
                self.personnel_department_ids,
                sorted(actor_departments) if principal else [],
                True,
            ),
            ("project_ids", self.project_ids, [principal.application_id] if principal else [], False),
            (
                "application_department_ids",
                self.application_department_ids,
                [principal.application_department_id] if principal else [],
                False,
            ),
            ("key_ids", self.key_ids, [principal.key_id] if principal else [], False),
            ("protocols", self.protocols, [principal.protocol] if principal else [], False),
            ("entry_points", self.entry_points, [principal.entry_point] if principal else [], False),
            ("model_ids", self.model_ids, [principal.model_id] if principal else [], False),
        )
        details: List[SubjectBindingMatchDetail] = []
        for dimension, configured, actual, actor_required in values:
            if not configured:
                continue
            actual = [value for value in actual if value]
            if principal is None:
                matched, reason = False, "principal_missing"
            elif actor_required and principal.trust_level != "authenticated":
                matched, reason = False, "actor_not_authenticated"
            elif not actual:
                matched, reason = False, "principal_value_missing"
            elif set(actual).intersection(configured):
                matched, reason = True, "matched"
            else:
                matched, reason = False, "no_configured_value_matched"
            details.append(SubjectBindingMatchDetail(
                dimension=dimension,
                configured_values=list(configured),
                matched=matched,
                reason=reason,
                include_children=(
                    dimension == "personnel_department_ids"
                    and self.personnel_department_include_children
                ),
            ))
        return details

    def matches(self, principal: PrincipalContext | None) -> bool:
        return all(detail.matched for detail in self.match_details(principal))


class RedactionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    replacement: str
    restore_response: bool = False

    @field_validator("replacement")
    @classmethod
    def valid_replacement(cls, value: str) -> str:
        if not value.strip() or len(value) > 128 or any(ch in value for ch in "\r\n\x00") or "<JJD_" in value:
            raise ValueError("redaction replacement is invalid")
        return value


class CompiledPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    authoring_source: Literal["", "agentshield"] = ""
    policy_code: str
    policy_id: str
    policy_name: str
    policy_type: str
    scene: str
    severity: Literal["low", "medium", "high", "critical"] | None = None
    matcher_rule_id: str = ""
    action: Literal["audit", "mask", "block"]
    # 控制台「智能分析命中时」：仅作用于语义裁判 finding；缺省 audit = 升级前行为。
    semantic_action: Literal["audit", "block", "observe"] = "audit"
    enabled: bool
    binding_mode: Literal["any", "all"]
    capabilities: List[CompiledPolicyCapability] = Field(default_factory=list)
    subject_binding: SubjectBinding | None = None
    redaction: RedactionSettings | None = None

    @field_validator(
        "policy_code",
        "policy_id",
        "policy_name",
        "policy_type",
        "scene",
        "matcher_rule_id",
    )
    @classmethod
    def trimmed_identity(cls, value: str, info) -> str:
        if value != value.strip():
            raise ValueError(f"{info.field_name} must be trimmed")
        if info.field_name != "matcher_rule_id" and not value:
            raise ValueError(f"{info.field_name} must be non-blank")
        return value

    @model_validator(mode="after")
    def valid_selector(self):
        if bool(self.matcher_rule_id) == bool(self.capabilities):
            raise ValueError(
                "policy must select exactly one matcher identity or capability set"
            )
        categories = [item.category for item in self.capabilities]
        if len(categories) != len(set(categories)):
            raise ValueError("policy capability categories must be unique")
        for capability in self.capabilities:
            if self.action not in capability.allowed_actions:
                raise ValueError("policy action is unsupported by capability")
            if self.action == "mask" and not capability.mask_capable:
                raise ValueError("policy mask action requires mask-capable detector")
        return self

    def stage_capabilities(
        self,
        stage: Literal["input", "agent", "output"],
    ) -> List[CompiledPolicyCapability]:
        return [
            capability
            for capability in self.capabilities
            if stage in capability.supported_stages
        ]

    def supports_stage(
        self,
        stage: Literal["input", "agent", "output"],
    ) -> bool:
        if self.matcher_rule_id:
            return stage in {"input", "output"}
        stage_capabilities = self.stage_capabilities(stage)
        if self.binding_mode == "all":
            return len(stage_capabilities) == len(self.capabilities)
        return bool(stage_capabilities)


class PolicyPreviewEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    policy_code: str
    policy_id: str
    policy_name: str
    enabled: bool
    matched: bool
    subject_matched: bool
    stage: Literal["input", "agent", "output"]
    stage_supported: bool
    configured_action: Literal["audit", "mask", "block"]
    effective_action: Literal["audit", "mask", "block"] | None
    conditional_action: Literal["audit", "mask", "block"] | None
    requires_finding: bool
    action_basis: Literal[
        "finding_required",
        "policy_disabled",
        "subject_not_matched",
        "stage_not_supported",
    ]
    capability_categories: List[str]
    stage_capability_categories: List[str]
    matcher_rule_id: str
    binding_details: List[SubjectBindingMatchDetail]


class PolicySet:
    """Immutable policy evaluator applied to one request's finding batch."""

    def __init__(self, policies: List[CompiledPolicy]):
        self.policies = tuple(policies)
        codes = [policy.policy_code for policy in policies]
        ids = [policy.policy_id for policy in policies]
        if len(codes) != len(set(codes)) or len(ids) != len(set(ids)):
            raise ValueError("policy identity must be unique")

    def __len__(self) -> int:
        return len(self.policies)

    def preview(
        self,
        stage: Literal["input", "agent", "output"],
        principal: PrincipalContext | None,
    ) -> List[PolicyPreviewEvaluation]:
        if stage not in {"input", "agent", "output"}:
            raise ValueError("policy stage is invalid")
        result: List[PolicyPreviewEvaluation] = []
        for policy in self.policies:
            binding_details = (
                policy.subject_binding.match_details(principal)
                if policy.subject_binding is not None
                else []
            )
            subject_matched = all(item.matched for item in binding_details)
            stage_capabilities = policy.stage_capabilities(stage)
            stage_supported = policy.supports_stage(stage)
            if not policy.enabled:
                action_basis = "policy_disabled"
            elif not subject_matched:
                action_basis = "subject_not_matched"
            elif not stage_supported:
                action_basis = "stage_not_supported"
            else:
                action_basis = "finding_required"
            matched = action_basis == "finding_required"
            result.append(PolicyPreviewEvaluation(
                policy_code=policy.policy_code,
                policy_id=policy.policy_id,
                policy_name=policy.policy_name,
                enabled=policy.enabled,
                matched=matched,
                subject_matched=subject_matched,
                stage=stage,
                stage_supported=stage_supported,
                configured_action=policy.action,
                effective_action=None,
                conditional_action=policy.action if matched else None,
                requires_finding=matched,
                action_basis=action_basis,
                capability_categories=[
                    capability.category for capability in policy.capabilities
                ],
                stage_capability_categories=[
                    capability.category for capability in stage_capabilities
                ],
                matcher_rule_id=policy.matcher_rule_id,
                binding_details=binding_details,
            ))
        return result

    def apply(self, findings: List[Any], stage: str, principal: PrincipalContext | None = None) -> List[Any]:
        if stage not in {"input", "agent", "output"}:
            raise ValueError("policy stage is invalid")
        if not findings or not self.policies:
            return findings

        applicable_policies = tuple(
            policy for policy in self.policies
            if policy.subject_binding is None or policy.subject_binding.matches(principal)
        )
        excluded = tuple(
            policy for policy in self.policies
            if policy.enabled and policy not in applicable_policies
        )
        excluded_rule_ids = {policy.matcher_rule_id for policy in excluded if policy.matcher_rule_id}

        def excluded_by_subject(finding: Any) -> bool:
            return finding.rule_id in excluded_rule_ids or any(
                _policy_categories(finding, policy) & {cap.category for cap in policy.capabilities}
                for policy in excluded
            )

        if not applicable_policies:
            return [
                finding.model_copy(deep=True, update={"action": "audit"})
                if excluded_by_subject(finding)
                else finding
                for finding in findings
            ]
        matched_by_policy: dict[str, List[str]] = {}
        enabled_declarations: List[tuple] = []
        disabled_declarations: List[tuple] = []
        for policy in applicable_policies:
            if policy.matcher_rule_id:
                matched_by_policy[policy.policy_code] = []
                continue
            stage_capabilities = policy.stage_capabilities(stage)
            declared_categories = {item.category for item in stage_capabilities}
            (enabled_declarations if policy.enabled else disabled_declarations).append(
                (policy, declared_categories)
            )
            if policy.binding_mode == "all":
                if len(stage_capabilities) != len(policy.capabilities):
                    continue
                required = [item.category for item in stage_capabilities]
                if not set(required).issubset({
                    category for f in findings if getattr(f, "counts_as_security_finding", True)
                    for category in _policy_categories(f, policy)
                }):
                    continue
                matched_by_policy[policy.policy_code] = required
            else:
                present_categories = {
                    category for f in findings for category in _policy_categories(f, policy)
                }
                matched = [
                    item.category
                    for item in stage_capabilities
                    if item.category in present_categories
                ]
                if matched:
                    matched_by_policy[policy.policy_code] = matched

        result: List[Any] = []
        for finding in findings:
            replacements: List[Any] = []
            matched_configured_policy = False
            for policy in applicable_policies:
                matched_capabilities = matched_by_policy.get(policy.policy_code)
                if policy.matcher_rule_id:
                    applies = finding.rule_id == policy.matcher_rule_id
                    matched_capabilities = []
                else:
                    applies = (
                        matched_capabilities is not None
                        and bool(_policy_categories(finding, policy) & set(matched_capabilities))
                    )
                if not applies:
                    continue
                matched_configured_policy = True
                if not policy.enabled:
                    continue
                source_rule_id = finding.source_rule_id or finding.rule_id
                triage = {**finding.triage}
                if policy.severity:
                    # 告警级别以命中策略为准；检测器原级别只留作排查参考。
                    triage["policy_severity"] = policy.severity
                    triage.setdefault("detector_severity", finding.severity)
                update = {
                    "policy_code": policy.policy_code,
                    "triage": triage,
                    "source_rule_id": source_rule_id,
                    "matched_capabilities": _finding_matched_capabilities(
                        finding, policy, list(matched_capabilities or [])
                    ),
                    "rule_id": policy.policy_id,
                    "rule_name": policy.policy_name,
                    "rule_type": policy.policy_type,
                    "policy_scene": policy.scene,
                    "action": _effective_policy_action(
                        finding, policy.action, policy.semantic_action, stage
                    ),
                }
                if policy.severity:
                    update["severity"] = policy.severity
                    reason = triage.get("severity_downgrade_reason")
                    if reason and SEVERITY_INDEX.get(finding.severity, -1) < SEVERITY_INDEX.get(
                        policy.severity, -1
                    ):
                        # 检测器已主动压低并写明原因的级别，不被策略级别抬回。
                        update["severity"] = finding.severity
                        triage["severity_before_downgrade"] = policy.severity
                    elif reason:
                        # 策略级别不高于检测器级别时没有降级，原因只留作排查参考。
                        triage["detector_downgrade_reason"] = triage.pop("severity_downgrade_reason")
                observe = _semantic_observe_update(finding, policy.semantic_action)
                if observe:
                    observe["triage"] = {
                        **update["triage"],
                        **{k: observe["triage"][k] for k in ("disposition", "disposition_reason")},
                    }
                    update.update(observe)
                replacements.append(finding.model_copy(deep=True, update=update))
            if replacements:
                result.extend(replacements)
            elif excluded_by_subject(finding):
                result.append(finding.model_copy(deep=True, update={"action": "audit"}))
            elif any(_policy_categories(finding, policy) & declared
                     for policy, declared in enabled_declarations):
                # The detector produced evidence for an enabled policy, but an
                # `all` conjunction was not complete. Keep the evidence for
                # audit without letting the detector's raw severity/action
                # bypass the customer's conjunction and enforce early.
                result.append(
                    finding.model_copy(deep=True, update={"action": _effective_policy_action(finding, "audit")})
                )
            elif (
                not matched_configured_policy
                and not any(_policy_categories(finding, policy) & declared
                            for policy, declared in disabled_declarations)
            ):
                result.append(finding)
        return result
