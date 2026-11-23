"""全局观察留痕管全部检测类拦截（2.9.22 D6）：集成凭据的 DLP 强制档也只记录、不拦。"""
import pytest
from app.detectors.engine import SecurityEngine, SecurityFinding
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet, SubjectBinding
from app.principal_context import PrincipalContext


def policy(source="agentshield", key="key1", tenant="tenant_default"):
    p = CompiledPolicy(policy_code="p.dlp", policy_id="policy1", policy_name="防泄漏", policy_type="data_leak", scene="data_leak", action="block", enabled=True, binding_mode="any", capabilities=[CompiledPolicyCapability(category="phone_cn", supported_stages=["input", "output"], allowed_actions=["audit", "block"], mask_capable=False)], subject_binding=SubjectBinding(tenant_ids=[tenant],key_ids=[key]))
    return p.model_copy(update={"authoring_source": source})


def principal(key="key1", tenant="tenant_default"):
    return PrincipalContext(schema_version=1,tenant_id=tenant,key_id=key,identity_source="api_key",trust_level="key_bound")


@pytest.mark.parametrize("source,key,tenant,effective,integration",[
    ("agentshield","key1","tenant_default","block",True),
    ("","key1","tenant_default","block",True),
    ("agentshield","other","tenant_default","block",True),
    ("agentshield","key1","other","block",True),
    ("agentshield","key1","tenant_default","record",True),
    ("agentshield","key1","tenant_default","block",False),
])
@pytest.mark.parametrize("stage",["input","output"])
def test_global_record_mode_records_integration_dlp_matrix(source,key,tenant,effective,integration,stage):
    engine=SecurityEngine();engine.audit_only=True
    engine.load_policies(PolicySet([policy(source)]))
    ctx={"tenant_id":tenant,"key_id":key,"effective_dlp_enforcement":effective,"integration_credential":integration,"integration_dlp_block_key_ids":["key1"]}
    result=getattr(engine,"check_"+stage)("测试请求","手机号 13800138000",context=ctx,principal=principal(key,tenant),skip_semantic=True)
    assert result.action == "audit"
    assert not any(f.triage.get("integration_dlp_block") for f in result.findings)
    assert engine.audit_only is True


@pytest.mark.parametrize("stage",["input","output"])
def test_protect_mode_integration_dlp_policy_still_blocks(stage):
    engine=SecurityEngine();engine.audit_only=False
    engine.load_policies(PolicySet([policy()]))
    ctx={"tenant_id":"tenant_default","key_id":"key1","effective_dlp_enforcement":"block","integration_credential":True,"integration_dlp_block_key_ids":["key1"]}
    result=getattr(engine,"check_"+stage)("测试请求","手机号 13800138000",context=ctx,principal=principal(),skip_semantic=True)
    assert result.action == "block"


def test_missing_principal_and_builtin_findings_remain_audit():
    engine=SecurityEngine();engine.audit_only=True
    engine.load_policies(PolicySet([policy()]))
    ctx={"tenant_id":"tenant_default","key_id":"key1","effective_dlp_enforcement":"block","integration_credential":True,"integration_dlp_block_key_ids":["key1"]}
    assert engine.check_input("测试","手机号 13800138000",context=ctx,skip_semantic=True).action=="audit"
    for kind in ["guard","hard_floor","engine_runtime","regex_timeout","custom_scan_incomplete"]:
        finding=SecurityFinding(type=kind,category="hard_floor",severity="critical",rule_id="floor",action="block",matched_text_preview="")
        assert engine._determine_action([finding])=="audit"
        assert engine._raw_action([finding])=="audit"


def test_agent_identity_observation_does_not_disable_dlp():
    engine=SecurityEngine();engine.audit_only=False
    engine.load_policies(PolicySet([policy()]))
    ctx={"tenant_id":"tenant_default","key_id":"key1","effective_dlp_enforcement":"block","integration_credential":True,"integration_dlp_block_key_ids":["key1"]}
    result=engine.check_input("测试","手机号 13800138000",context=ctx,principal=principal(),skip_semantic=True,agent_type="claude-code")
    assert result.action=="block"


@pytest.mark.parametrize("kind", ["guard", "hard_floor", "engine_runtime", "regex_timeout", "custom_scan_incomplete", "pii"])
def test_trusted_integration_context_cannot_promote_unmanaged_or_mixed_findings(kind):
    engine = SecurityEngine()
    engine.audit_only = True
    policies = PolicySet([policy()])
    ctx = {"tenant_id": "tenant_default", "key_id": "key1", "effective_dlp_enforcement": "block", "integration_credential": True,"integration_dlp_block_key_ids":["key1"]}
    managed = SecurityFinding(type="pii", category="phone_cn", severity="high", rule_id="policy1", policy_code="p.dlp", action="block", matched_text_preview="")
    unmanaged = SecurityFinding(type=kind, category="phone_cn", severity="critical", rule_id="unmanaged", action="block", matched_text_preview="", triage={"integration_dlp_block": True})
    for decide in [engine._determine_action, engine._raw_action]:
        assert decide([managed, unmanaged], context=ctx, principal=principal(), policies=policies) == "audit"
        assert engine.audit_only is True


@pytest.mark.parametrize("effective,want", [("block", "audit"), ("record", "audit")])
def test_cached_context_replay_rechecks_credential_and_current_policy(monkeypatch, effective, want):
    import asyncio
    import importlib
    api = importlib.import_module("app.api.apply_context")
    engine = SecurityEngine()
    engine.audit_only = True
    engine.load_policies(PolicySet([policy()]))
    monkeypatch.setattr(api, "engine", engine)
    monkeypatch.setenv("SECURITY_TENANT_ID", "tenant_default")
    request = api.ApplyContextRequest(tenant_id="tenant_default", principal=principal(), context={"tenant_id":"tenant_default", "key_id":"key1", "effective_dlp_enforcement":effective, "integration_credential":True,"integration_dlp_block_key_ids":["key1"]}, raw_findings=[api.ApplyContextFinding(type="pii", category="phone_cn", rule_id="builtin-phone", severity="high", action="block", matched_text_preview="")])
    assert asyncio.run(api.apply_context(request)).action == want
    engine.load_policies(PolicySet([policy(source="")]))
    assert asyncio.run(api.apply_context(request)).action == "audit"


@pytest.mark.parametrize("verified_keys,want", [([], "audit"), (["key1"], "audit"), (["key1", "key2"], "audit")])
def test_every_bound_key_requires_trusted_block_posture(verified_keys, want):
    engine = SecurityEngine()
    engine.audit_only = True
    bound = policy().model_copy(update={"subject_binding": SubjectBinding(tenant_ids=["tenant_default"], key_ids=["key1", "key2"])})
    policies = PolicySet([bound])
    finding = SecurityFinding(type="pii", category="phone_cn", severity="high", rule_id="policy1", policy_code="p.dlp", action="block", matched_text_preview="")
    ctx = {"tenant_id":"tenant_default", "key_id":"key1", "effective_dlp_enforcement":"block", "integration_credential":True, "integration_dlp_block_key_ids":verified_keys}
    assert engine._determine_action([finding], context=ctx, principal=principal(), policies=policies) == want
