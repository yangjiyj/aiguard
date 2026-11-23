package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const rulePackEngineE2EScript = `
import json
import os

from app.detectors.engine import SecurityEngine
from app.file_inspector import snapshot_file_policy
from app.rule_pack_loader import RulePackConfig, RulePackLoader

config = RulePackConfig(
    base_url=os.environ["RULE_PACK_E2E_URL"],
    token=os.environ["RULE_PACK_E2E_INTERNAL_TOKEN"],
    attestation_token=os.environ["RULE_PACK_E2E_ATTESTATION_TOKEN"],
    tenant_id=os.environ["RULE_PACK_E2E_TENANT"],
    node_id="engine-e2e-node",
    refresh_seconds=60,
)
loader = RulePackLoader(config)
engine = SecurityEngine()

def snapshot():
    return {
        "version": engine.rule_pack_version,
        "active_rule_ids": [
            rule.rule_id for rule, _pattern in engine.custom_rules.active_rules
        ],
        "skipped_rule_ids": [
            rule.rule_id for rule in engine.custom_rules.skipped
        ],
        "exception_ids": [
            exception.exception_id
            for exception in engine.content_exceptions.exceptions
        ],
        "file_policy": snapshot_file_policy(),
        "active_count": loader._actual_active_count,
        "skipped_count": loader._actual_skipped_count,
    }

results = []
states = []
for _ in range(3):
    results.append(loader.refresh_once(engine))
    states.append(snapshot())

print(json.dumps({"results": results, "states": states}, sort_keys=True))
`

func TestRulePackRealPostgresControlPlaneAndSecurityEngineClosedLoop(t *testing.T) {
	f := newSecurityRulesFixture(t)
	resetRulePackPullLedger(t)
	ctx := context.Background()
	for _, stmt := range []string{
		`ALTER TABLE tenants ADD COLUMN name text NOT NULL DEFAULT 'tenant', ADD COLUMN edition text NOT NULL DEFAULT 'enterprise', ADD COLUMN status text NOT NULL DEFAULT 'active', ADD COLUMN industry text NOT NULL DEFAULT 'generic', ADD COLUMN config_json jsonb NOT NULL DEFAULT '{}', ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(), ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now()`,
		`ALTER TABLE rule_sets ADD COLUMN industry text NOT NULL DEFAULT 'generic'`,
		`CREATE TABLE content_audit_exceptions (
			id text PRIMARY KEY, tenant_id text NOT NULL, scope_type text NOT NULL,
			scope_ref text, include_children boolean NOT NULL DEFAULT false, rule_id text, rule_ref text, decision text NOT NULL,
			reason text, expires_at timestamptz, enabled boolean NOT NULL DEFAULT true,
			created_by text, created_at timestamptz NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := f.pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("prepare rule-pack E2E fixture: %v", err)
		}
	}

	if _, err := f.pool.Exec(ctx, `DELETE FROM rules WHERE id=$1`, f.managedA); err != nil {
		t.Fatalf("exclude unrelated managed rule: %v", err)
	}
	const internalToken = "e2e-shared-internal-token"
	const attestationToken = "e2e-tenant-attestation-token"
	const tenantBAttestationToken = "e2e-tenant-b-attestation-token"
	f.deps.TenantRepo = repository.NewTenantRepository(f.pool)
	f.deps.SystemRepo = &contentConfigSystemRepo{}
	f.deps.RulePackAttestationTokens = map[string]string{
		f.tenantA: attestationToken,
		f.tenantB: tenantBAttestationToken,
	}

	var requestCount atomic.Int32
	packHandler := InternalAPIMiddleware(internalToken, f.deps)(GetInternalRulePack(f.deps))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCount.Add(1) == 3 {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, runtimeCompileUnavailableCode, "runtime rule pack is unavailable")
			return
		}
		packHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get test working directory: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "../../../.."))
	commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(commandCtx, "python3", "-c", rulePackEngineE2EScript)
	cmd.Env = append(os.Environ(),
		"PYTHONPATH="+filepath.Join(repoRoot, "apps/security-engine"),
		"RULE_PACK_E2E_URL="+server.URL,
		"RULE_PACK_E2E_INTERNAL_TOKEN="+internalToken,
		"RULE_PACK_E2E_ATTESTATION_TOKEN="+attestationToken,
		"RULE_PACK_E2E_TENANT="+f.tenantA,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("security-engine E2E failed: %v stderr=%s", err, stderr.String())
	}
	if requestCount.Load() != 3 {
		t.Fatalf("request count=%d want=3", requestCount.Load())
	}

	var engineResult struct {
		Results []bool `json:"results"`
		States  []struct {
			Version        string                 `json:"version"`
			ActiveRuleIDs  []string               `json:"active_rule_ids"`
			SkippedRuleIDs []string               `json:"skipped_rule_ids"`
			ExceptionIDs   []string               `json:"exception_ids"`
			FilePolicy     map[string]interface{} `json:"file_policy"`
			ActiveCount    int                    `json:"active_count"`
			SkippedCount   int                    `json:"skipped_count"`
		} `json:"states"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output), &engineResult); err != nil {
		t.Fatalf("decode security-engine result: %v output=%s", err, output)
	}
	if len(engineResult.Results) != 3 || !engineResult.Results[0] || !engineResult.Results[1] || engineResult.Results[2] {
		t.Fatalf("refresh results=%v want [true true false]", engineResult.Results)
	}
	if len(engineResult.States) != 3 {
		t.Fatalf("state snapshots=%d want=3", len(engineResult.States))
	}
	firstStateJSON, _ := json.Marshal(engineResult.States[0])
	secondStateJSON, _ := json.Marshal(engineResult.States[1])
	thirdStateJSON, _ := json.Marshal(engineResult.States[2])
	if !bytes.Equal(firstStateJSON, secondStateJSON) || !bytes.Equal(secondStateJSON, thirdStateJSON) {
		t.Fatalf("second idempotent pull or failed third pull changed last-good: %s / %s / %s", firstStateJSON, secondStateJSON, thirdStateJSON)
	}
	state := engineResult.States[2]
	if state.Version == "" || len(state.ActiveRuleIDs) != 1 || state.ActiveRuleIDs[0] != f.runtimeA || len(state.SkippedRuleIDs) != 0 || state.ActiveCount != 1 || state.SkippedCount != 0 {
		t.Fatalf("unexpected applied engine state: %+v", state)
	}

	pack, err := compileTenantRulePack(ctx, f.deps, f.tenantA)
	if err != nil {
		t.Fatalf("compile authoritative pack after E2E: %v", err)
	}
	nodes := listRulePackPullStatus(f.tenantA, pack.Version, time.Now().UTC())
	if len(nodes) != 1 || nodes[0].NodeID != "engine-e2e-node" || nodes[0].HeldVersion != pack.Version || nodes[0].ServedVersion != pack.Version || nodes[0].ActiveRuntimeCount == nil || *nodes[0].ActiveRuntimeCount != 1 || nodes[0].SkippedRuntimeCount == nil || *nodes[0].SkippedRuntimeCount != 0 || nodes[0].Status != rulePackNodeStatusConverged {
		t.Fatalf("second pull did not produce converged actual-count receipt: %+v", nodes)
	}
	runtimeStatus := ruleRuntimeStatusFromPack(pack, evaluateRulePackConvergence(f.tenantA, pack.Version))
	if !runtimeStatus.RuntimeVerified || runtimeStatus.ActiveRuntimeCount == nil || *runtimeStatus.ActiveRuntimeCount != 1 || runtimeStatus.ActualSkippedCount == nil || *runtimeStatus.ActualSkippedCount != 0 || runtimeStatus.Status != runtimeStatusApplied {
		t.Fatalf("actual runtime status not verified after E2E: %+v", runtimeStatus)
	}

	crossTenantRequest, err := http.NewRequest(http.MethodGet, server.URL+"/admin/v1/internal/rules/pack", nil)
	if err != nil {
		t.Fatalf("create cross-tenant request: %v", err)
	}
	crossTenantRequest.Header.Set(InternalAPISecretHeader, internalToken)
	crossTenantRequest.Header.Set("X-Tenant-ID", f.tenantB)
	crossTenantRequest.Header.Set(rulePackAttestationHeader, tenantBAttestationToken)
	crossTenantRequest.Header.Set(nodeIDHeader, "engine-e2e-node")
	crossTenantResponse, err := server.Client().Do(crossTenantRequest)
	if err != nil {
		t.Fatalf("cross-tenant node request: %v", err)
	}
	defer crossTenantResponse.Body.Close()
	if crossTenantResponse.StatusCode != http.StatusOK {
		t.Fatalf("tenant-namespaced same node status=%d want200", crossTenantResponse.StatusCode)
	}
	if got := listRulePackPullStatus(f.tenantB, "", time.Now().UTC()); len(got) != 1 || got[0].NodeID != "engine-e2e-node" {
		t.Fatalf("tenant-b same node was not isolated in its own ledger: %+v", got)
	}
	if requestCount.Load() != 4 {
		t.Fatalf("request count after cross-tenant check=%d want=4", requestCount.Load())
	}
}

const quickDraftASGIPreviewScript = `
import asyncio
import json
import os
import sys
import httpx
from app.main import app

async def main():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://engine") as client:
        response = await client.post(
            "/admin/v1/internal/policies/quick-create/preview/",
            json=json.load(sys.stdin),
            headers={"X-JJDGuard-Internal-Token": os.environ["QUICK_E2E_INTERNAL_TOKEN"]},
        )
        response.raise_for_status()
        print(json.dumps(response.json()))

asyncio.run(main())
`

type quickDraftASGIPreview struct{ repoRoot string }

func (p quickDraftASGIPreview) PreviewQuickMatcher(ctx context.Context, request quickEngineRequest) (*quickEngineResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "python3", "-c", quickDraftASGIPreviewScript)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(p.repoRoot, "apps/security-engine"), "JJD_INTERNAL_API_SECRET=quick-e2e-secret", "QUICK_E2E_INTERNAL_TOKEN=quick-e2e-secret")
	cmd.Stdin = bytes.NewReader(body)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("quick-create ASGI preview failed: %w", err)
	}
	var response quickEngineResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

const quickDraftASGIRegexValidationScript = `
import asyncio
import json
import os
import sys
import httpx
from app.main import app

async def main():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://engine") as client:
        response = await client.post("/admin/v1/internal/regex/validate",
            json={"pattern": json.load(sys.stdin)},
            headers={"X-JJDGuard-Internal-Token": os.environ["QUICK_E2E_INTERNAL_TOKEN"]})
        response.raise_for_status()
        print(json.dumps(response.json()))

asyncio.run(main())
`

type quickDraftASGIValidator struct{ repoRoot string }

func (v quickDraftASGIValidator) ValidateRegex(ctx context.Context, pattern string) (bool, string, error) {
	body, err := json.Marshal(pattern)
	if err != nil {
		return false, "", err
	}
	process := exec.CommandContext(ctx, "python3", "-c", quickDraftASGIRegexValidationScript)
	process.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(v.repoRoot, "apps/security-engine"), "JJD_INTERNAL_API_SECRET=quick-e2e-secret", "QUICK_E2E_INTERNAL_TOKEN=quick-e2e-secret")
	process.Stdin = bytes.NewReader(body)
	output, err := process.Output()
	if err != nil {
		return false, "", fmt.Errorf("quick-create ASGI regex validation failed: %w", err)
	}
	var result struct {
		Valid     bool    `json:"valid"`
		ErrorCode *string `json:"error_code"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return false, "", err
	}
	if result.ErrorCode != nil {
		return result.Valid, *result.ErrorCode, nil
	}
	return result.Valid, "", nil
}

const quickDraftRuntimeScript = `
import json
import os
from app.detectors.engine import SecurityEngine
from app.rule_pack_loader import RulePackConfig, RulePackLoader

config = RulePackConfig(
    base_url=os.environ["RULE_PACK_E2E_URL"],
    token=os.environ["RULE_PACK_E2E_INTERNAL_TOKEN"],
    attestation_token=os.environ["RULE_PACK_E2E_ATTESTATION_TOKEN"],
    tenant_id=os.environ["RULE_PACK_E2E_TENANT"],
    node_id="quick-draft-e2e-node",
    refresh_seconds=60,
)
engine = SecurityEngine()
loader = RulePackLoader(config)
loaded = loader.refresh_once(engine)
result = engine.check_input("quick-draft-e2e-request", "(HT-2026-000123)")
clean = engine.check_input("quick-draft-e2e-clean", "ordinary unrelated content")
output = engine.check_output("quick-draft-e2e-output", "(HT-2026-000123)")
clean_output = engine.check_output("quick-draft-e2e-clean-output", "ordinary unrelated content")
rule_id = os.environ["QUICK_E2E_RULE_ID"]
hits = [finding for finding in result.findings if finding.rule_id == rule_id]
output_hits = [finding for finding in output.findings if finding.rule_id == rule_id]
print(json.dumps({
    "loaded": loaded,
    "active": rule_id in [rule.rule_id for rule, _ in engine.custom_rules.active_rules],
    "matched": bool(hits),
    "action": result.action,
    "redacted": all("HT-2026-000123" not in finding.redacted_evidence for finding in hits),
    "clean_matched": any(finding.rule_id == rule_id for finding in clean.findings),
    "clean_action": clean.action,
    "output_matched": bool(output_hits),
    "output_action": output.action,
    "output_redacted": bool(output_hits) and all("HT-2026-000123" not in finding.redacted_evidence for finding in output_hits),
    "clean_output_matched": any(finding.rule_id == rule_id for finding in clean_output.findings),
    "clean_output_action": clean_output.action,
}, sort_keys=True))
`

type quickDraftRuntimeState struct {
	Loaded             bool   `json:"loaded"`
	Active             bool   `json:"active"`
	Matched            bool   `json:"matched"`
	Action             string `json:"action"`
	Redacted           bool   `json:"redacted"`
	CleanMatched       bool   `json:"clean_matched"`
	CleanAction        string `json:"clean_action"`
	OutputMatched      bool   `json:"output_matched"`
	OutputAction       string `json:"output_action"`
	OutputRedacted     bool   `json:"output_redacted"`
	CleanOutputMatched bool   `json:"clean_output_matched"`
	CleanOutputAction  string `json:"clean_output_action"`
}

func TestQuickCreateRealPostgresToSecurityEngineRuntime(t *testing.T) {
	f := newSecurityRulesFixture(t)
	resetRulePackPullLedger(t)
	ctx := context.Background()
	for _, stmt := range []string{
		`ALTER TABLE tenants ADD COLUMN name text NOT NULL DEFAULT 'tenant', ADD COLUMN edition text NOT NULL DEFAULT 'enterprise', ADD COLUMN status text NOT NULL DEFAULT 'active', ADD COLUMN industry text NOT NULL DEFAULT 'generic', ADD COLUMN config_json jsonb NOT NULL DEFAULT '{}', ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(), ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now()`,
		`ALTER TABLE rule_sets ADD COLUMN industry text NOT NULL DEFAULT 'generic'`,
		`ALTER TABLE security_capabilities ADD COLUMN name text NOT NULL DEFAULT 'test capability', ADD COLUMN capability_kind text NOT NULL DEFAULT 'static', ADD COLUMN component text NOT NULL DEFAULT 'security-engine'`,
		`CREATE TABLE content_audit_exceptions (
            id text PRIMARY KEY, tenant_id text NOT NULL, scope_type text NOT NULL,
            scope_ref text, include_children boolean NOT NULL DEFAULT false, rule_id text, rule_ref text, decision text NOT NULL,
            reason text, expires_at timestamptz, enabled boolean NOT NULL DEFAULT true,
            created_by text, created_at timestamptz NOT NULL DEFAULT now()
        )`,
	} {
		if _, err := f.pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("prepare quick-create E2E fixture: %v", err)
		}
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM rules WHERE rule_set_id=$1`, f.ruleSetA); err != nil {
		t.Fatalf("isolate tenant runtime rules: %v", err)
	}
	f.deps.TenantRepo = repository.NewTenantRepository(f.pool)
	f.deps.SystemRepo = &contentConfigSystemRepo{}
	const internalToken = "quick-e2e-rule-pack-token"
	const attestationToken = "quick-e2e-attestation-token"
	const tenantBAttestationToken = "quick-e2e-tenant-b-attestation-token"
	f.deps.RulePackAttestationTokens = map[string]string{f.tenantA: attestationToken, f.tenantB: tenantBAttestationToken}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get test working directory: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "../../../.."))
	f.deps.SecurityEngineInternalToken = "quick-e2e-secret"
	quickHandler := &quickCreateHandler{
		policies: newSecurityPoliciesHandler(f.deps, f.deps.RuleRepo, quickDraftASGIValidator{repoRoot: repoRoot}),
		engine:   quickDraftASGIPreview{repoRoot: repoRoot},
	}
	const marker = "HT-2026-000123"
	const body = `{"kind":"number","positive_samples":["HT-2026-000123","HT-2026-000456"]}`
	generatedResponse := httptest.NewRecorder()
	quickHandler.generate(generatedResponse, securityRulesRequest(http.MethodPost, "/admin/v1/security/policies/quick-create/generate", body, f.tenantA))
	if generatedResponse.Code != http.StatusOK {
		t.Fatalf("quick generate status=%d", generatedResponse.Code)
	}
	var generated struct {
		Matcher        *securityPolicyMatcherRequest            `json:"matcher"`
		Segments       []repository.SecurityPolicyNumberSegment `json:"segments"`
		AuthoringProof string                                   `json:"authoring_proof"`
	}
	if err := json.Unmarshal(generatedResponse.Body.Bytes(), &generated); err != nil || generated.Matcher == nil || generated.Matcher.Type != "regex" {
		t.Fatalf("generated matcher invalid: %v", err)
	}
	trialBody, err := json.Marshal(map[string]any{"matcher": generated.Matcher, "samples": []string{"(HT-2026-000789)", "ordinary text", "xHT-2026-000789"}})
	if err != nil {
		t.Fatal(err)
	}
	preview := httptest.NewRecorder()
	quickHandler.execute(preview, securityRulesRequest(http.MethodPost, "/admin/v1/security/policies/quick-create/preview", string(trialBody), f.tenantA))
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"matched":true`) || !strings.Contains(preview.Body.String(), `"matched":false`) {
		t.Fatalf("quick preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	createBody, err := json.Marshal(map[string]any{
		"name": "quick E2E policy", "scene": "data_security", "severity": "medium",
		"action": "block", "enabled": false, "matcher": generated.Matcher, "authoring_proof": generated.AuthoringProof, "authoring": map[string]any{"version": 1, "kind": "number", "matcher_pattern": func() string {
			var config struct {
				Regex string `json:"regex"`
			}
			_ = json.Unmarshal(generated.Matcher.Config, &config)
			return config.Regex
		}(), "segments": generated.Segments},
	})
	if err != nil {
		t.Fatal(err)
	}
	draft := httptest.NewRecorder()
	quickHandler.policies.create(draft, securityRulesRequest(http.MethodPost, "/admin/v1/security/policies", string(createBody), f.tenantA))
	if draft.Code != http.StatusCreated || strings.Contains(draft.Body.String(), marker) {
		t.Fatalf("original policy create status=%d or exposed marker", draft.Code)
	}
	var created struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(draft.Body.Bytes(), &created); err != nil || created.ID == "" || created.Enabled {
		t.Fatalf("original policy create response invalid: %v", err)
	}
	foreignBody := map[string]any{}
	if err := json.Unmarshal(createBody, &foreignBody); err != nil {
		t.Fatal(err)
	}
	foreignBody["name"] = "forged tenant policy"
	foreignJSON, _ := json.Marshal(foreignBody)
	foreignCreate := httptest.NewRecorder()
	quickHandler.policies.create(foreignCreate, securityRulesRequest(http.MethodPost, "/admin/v1/security/policies", string(foreignJSON), f.tenantB))
	if foreignCreate.Code != 422 {
		t.Fatalf("cross-tenant generation proof accepted: %d %s", foreignCreate.Code, foreignCreate.Body.String())
	}
	foreignGenerate := httptest.NewRecorder()
	quickHandler.generate(foreignGenerate, securityRulesRequest(http.MethodPost, "/admin/v1/security/policies/quick-create/generate", `{"kind":"number","policy_id":"`+created.ID+`","segments":[{"kind":"fixed","value":"HT-"},{"kind":"digits","length":4},{"kind":"fixed","value":"-"},{"kind":"digits","length":6}]}`, f.tenantB))
	if foreignGenerate.Code != 422 {
		t.Fatalf("cross-tenant saved edit accepted: %d %s", foreignGenerate.Code, foreignGenerate.Body.String())
	}
	stored, err := f.deps.RuleRepo.GetSecurityPolicy(ctx, f.tenantA, created.ID)
	if err != nil || stored.Enabled || stored.Action != "block" {
		t.Fatalf("draft not persisted disabled with requested action: %v", err)
	}
	if len(stored.Authoring.Segments) != 4 || stored.Authoring.Segments[1].Kind != "fixed" {
		t.Fatalf("saved segments missing on reopen: %+v", stored.Authoring.Segments)
	}
	regenerateBody, err := json.Marshal(map[string]any{
		"kind": "number", "policy_id": created.ID, "segments": []repository.SecurityPolicyNumberSegment{
			stored.Authoring.Segments[0], {Kind: "digits", Length: 4}, stored.Authoring.Segments[2], stored.Authoring.Segments[3],
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	regeneratedResponse := httptest.NewRecorder()
	quickHandler.generate(regeneratedResponse, securityRulesRequest(http.MethodPost, "/admin/v1/security/policies/quick-create/generate", string(regenerateBody), f.tenantA))
	if regeneratedResponse.Code != http.StatusOK {
		t.Fatalf("segments-only regenerate status=%d body=%s", regeneratedResponse.Code, regeneratedResponse.Body.String())
	}
	var regenerated struct {
		Matcher        *securityPolicyMatcherRequest            `json:"matcher"`
		Segments       []repository.SecurityPolicyNumberSegment `json:"segments"`
		AuthoringProof string                                   `json:"authoring_proof"`
	}
	if err := json.Unmarshal(regeneratedResponse.Body.Bytes(), &regenerated); err != nil || regenerated.Matcher == nil || len(regenerated.Segments) != 4 {
		t.Fatalf("segments-only regeneration failed: %v", err)
	}
	editBody, err := json.Marshal(map[string]any{"matcher": regenerated.Matcher, "authoring_proof": regenerated.AuthoringProof, "authoring": map[string]any{"version": 1, "kind": "number", "matcher_pattern": func() string {
		var config struct {
			Regex string `json:"regex"`
		}
		_ = json.Unmarshal(regenerated.Matcher.Config, &config)
		return config.Regex
	}(), "segments": regenerated.Segments}})
	if err != nil {
		t.Fatal(err)
	}
	editResponse := httptest.NewRecorder()
	quickHandler.policies.update(editResponse, withPolicyID(securityRulesRequest(http.MethodPatch, "/admin/v1/security/policies/"+created.ID, string(editBody), f.tenantA), created.ID))
	if editResponse.Code != http.StatusOK {
		t.Fatalf("save segments-only edit status=%d body=%s", editResponse.Code, editResponse.Body.String())
	}
	stored, err = f.deps.RuleRepo.GetSecurityPolicy(ctx, f.tenantA, created.ID)
	if err != nil || len(stored.Authoring.Segments) != 4 || stored.Authoring.Segments[1].Kind != "digits" {
		t.Fatalf("reopened edited segments missing: %v %+v", err, stored)
	}
	if other, err := f.deps.RuleRepo.GetSecurityPolicy(ctx, f.tenantB, created.ID); err != repository.ErrSecurityPolicyNotFound || other != nil {
		t.Fatalf("other tenant can read quick draft: %v", err)
	}
	before, err := compileTenantRulePack(ctx, f.deps, f.tenantA)
	if err != nil {
		t.Fatalf("compile disabled quick draft: %v", err)
	}
	for _, rule := range before.Rules {
		if rule.RuleID == created.ID {
			t.Fatal("disabled quick draft entered active rule pack")
		}
	}

	server := httptest.NewServer(InternalAPIMiddleware(internalToken, f.deps)(GetInternalRulePack(f.deps)))
	t.Cleanup(server.Close)
	checkRuntime := func(tenantID, token string) quickDraftRuntimeState {
		t.Helper()
		commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(commandCtx, "python3", "-c", quickDraftRuntimeScript)
		cmd.Env = append(os.Environ(),
			"PYTHONPATH="+filepath.Join(repoRoot, "apps/security-engine"),
			"RULE_PACK_E2E_URL="+server.URL,
			"RULE_PACK_E2E_INTERNAL_TOKEN="+internalToken,
			"RULE_PACK_E2E_ATTESTATION_TOKEN="+token,
			"RULE_PACK_E2E_TENANT="+tenantID,
			"QUICK_E2E_RULE_ID="+created.ID,
		)
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("run real security-engine against quick draft: %v", err)
		}
		var state quickDraftRuntimeState
		if err := json.Unmarshal(bytes.TrimSpace(output), &state); err != nil {
			t.Fatalf("decode runtime result: %v", err)
		}
		return state
	}
	inactive := checkRuntime(f.tenantA, attestationToken)
	if !inactive.Loaded || inactive.Active || inactive.Matched || inactive.Action == "block" || inactive.OutputMatched || inactive.OutputAction == "block" || inactive.CleanOutputMatched || inactive.CleanOutputAction == "block" {
		t.Fatalf("disabled quick draft affected runtime: %+v", inactive)
	}

	enabled := httptest.NewRecorder()
	request := securityRulesRequest(http.MethodPatch, "/admin/v1/security/policies/"+created.ID, `{"enabled":true}`, f.tenantA)
	quickHandler.policies.update(enabled, withPolicyID(request, created.ID))
	if enabled.Code != http.StatusOK {
		t.Fatalf("enable quick draft status=%d body=%s", enabled.Code, enabled.Body.String())
	}
	stored, err = f.deps.RuleRepo.GetSecurityPolicy(ctx, f.tenantA, created.ID)
	if err != nil || !stored.Enabled {
		t.Fatalf("enabled quick draft not persisted: %v", err)
	}
	active := checkRuntime(f.tenantA, attestationToken)
	if !active.Loaded || !active.Active || !active.Matched || active.Action != "block" || !active.Redacted {
		t.Fatalf("enabled quick draft did not block real input with redacted evidence: %+v", active)
	}
	if active.CleanMatched || active.CleanAction == "block" {
		t.Fatalf("unrelated input was matched or blocked: %+v", active)
	}
	if !active.OutputMatched || active.OutputAction != "block" || !active.OutputRedacted || active.CleanOutputMatched || active.CleanOutputAction == "block" {
		t.Fatalf("enabled quick draft did not block matching output or affected unrelated output: %+v", active)
	}
	foreign := checkRuntime(f.tenantB, tenantBAttestationToken)
	if !foreign.Loaded || foreign.Active || foreign.Matched || foreign.Action == "block" || foreign.CleanMatched || foreign.CleanAction == "block" || foreign.OutputMatched || foreign.OutputAction == "block" || foreign.CleanOutputMatched || foreign.CleanOutputAction == "block" {
		t.Fatalf("tenant B was affected by tenant A quick policy: %+v", foreign)
	}
}
