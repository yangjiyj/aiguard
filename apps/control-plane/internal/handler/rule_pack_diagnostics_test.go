package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	securityrules "github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

type rulePackTenantSourceStub struct {
	tenant *repository.Tenant
	err    error
}

func (s rulePackTenantSourceStub) GetByID(context.Context, string) (*repository.Tenant, error) {
	return s.tenant, s.err
}

type rulePackRuleSourceStub struct {
	rules      []*repository.Rule
	rulesErr   error
	exceptions []*repository.ContentAuditException
	excErr     error
	industry   string
}

type runtimeSystemRepoStub struct {
	contentConfigSystemRepo
	setting *repository.SystemSetting
	getErr  error
}

func (s *runtimeSystemRepoStub) Get(context.Context, string) (*repository.SystemSetting, error) {
	return s.setting, s.getErr
}

func (s *rulePackRuleSourceStub) ListCompilableRulesByTenant(_ context.Context, _ string, industry string) ([]*repository.Rule, error) {
	s.industry = industry
	return s.rules, s.rulesErr
}

func (s *rulePackRuleSourceStub) ListActiveContentAuditExceptionsByTenant(context.Context, string) ([]*repository.ContentAuditException, error) {
	return s.exceptions, s.excErr
}

func runtimeAPIRequest(method, target, tenantID, role string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	user := &repository.User{ID: "user-runtime", TenantID: tenantID, Role: role, Status: "active"}
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
}

func TestGetVersionInfoReportsRuntimeUnavailableHonestly(t *testing.T) {
	req := runtimeAPIRequest(http.MethodGet, "/admin/v1/system/version", "tenant-version-unavailable", "viewer")
	rec := httptest.NewRecorder()

	GetVersionInfo(&Dependencies{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("version compatibility endpoint status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		RuleSetVersion string `json:"ruleset_version"`
		Runtime        struct {
			DesiredVersion     string         `json:"desired_version"`
			CatalogCount       int            `json:"catalog_count"`
			CompiledCount      int            `json:"compiled_count"`
			SkippedCount       int            `json:"skipped_count"`
			Reasons            map[string]int `json:"reasons"`
			RuntimeVerified    bool           `json:"runtime_verified"`
			ActiveRuntimeCount *int           `json:"active_runtime_count"`
			Status             string         `json:"status"`
			LastError          string         `json:"last_error"`
		} `json:"runtime"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode version response: %v body=%s", err, rec.Body.String())
	}
	if body.RuleSetVersion != "" || body.Runtime.DesiredVersion != "" {
		t.Fatalf("unavailable compile must not invent version: %+v", body)
	}
	if body.Runtime.RuntimeVerified || body.Runtime.ActiveRuntimeCount != nil {
		t.Fatalf("no engine receipt must be unverified with null active count: %+v", body.Runtime)
	}
	if body.Runtime.Status != runtimeStatusUnavailable || body.Runtime.LastError != runtimeCompileUnavailableCode {
		t.Fatalf("unavailable runtime status is not explicit/safe: %+v", body.Runtime)
	}
}

func TestSyncRuleSetReturnsStructuredUnavailableWithoutLeakingError(t *testing.T) {
	req := runtimeAPIRequest(http.MethodPost, "/admin/v1/system/ruleset/sync", "tenant-sync-unavailable", "platform_admin")
	rec := httptest.NewRecorder()

	SyncRuleSet(&Dependencies{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("sync compile failure status=%d want503 body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"ruleset_version":""`) || !strings.Contains(body, `"status":"unavailable"`) || !strings.Contains(body, `"last_error":"runtime_compile_unavailable"`) {
		t.Fatalf("sync unavailable contract incomplete: %s", body)
	}
	if strings.Contains(strings.ToLower(body), "database") || strings.Contains(strings.ToLower(body), "nil pointer") {
		t.Fatalf("sync leaked internal failure details: %s", body)
	}
}

func TestRuleRuntimeAdmin503sLogSafeCorrelation(t *testing.T) {
	var logs bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		target  string
	}{
		{name: "pull status", handler: GetRulePackPullStatus(&Dependencies{}), target: "/admin/v1/rules/pull-status"},
		{name: "sync", handler: SyncRuleSet(&Dependencies{}), target: "/admin/v1/system/ruleset/sync"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requestID := "request-" + strings.ReplaceAll(tc.name, " ", "-")
			req := runtimeAPIRequest(http.MethodPost, tc.target, "tenant-safe-log", "platform_admin")
			req.Header.Set("X-Request-ID", requestID)
			rec := httptest.NewRecorder()
			tc.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			for _, want := range []string{requestID, "tenant-safe-log", runtimeCompileUnavailableCode} {
				if !strings.Contains(logs.String(), want) {
					t.Fatalf("safe log missing %q: %s", want, logs.String())
				}
			}
		})
	}
}

func TestInternalRulePackCompileFailureIsSafe503(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/rules/pack", nil)
	req.Header.Set("X-Tenant-ID", "tenant-pack-unavailable")
	req.Header.Set(rulePackAttestationHeader, "tenant-pack-token")
	req.Header.Set(nodeIDHeader, "node-pack-unavailable")
	rec := httptest.NewRecorder()

	GetInternalRulePack(&Dependencies{RulePackAttestationTokens: map[string]string{"tenant-pack-unavailable": "tenant-pack-token"}}).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("internal pack failure status=%d want503 body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), runtimeCompileUnavailableCode) {
		t.Fatalf("internal pack must expose stable safe code: %s", rec.Body.String())
	}
}

func TestCompileTenantRulePackRecordsSafeExceptionDegradationWarning(t *testing.T) {
	source := &rulePackRuleSourceStub{
		rules: []*repository.Rule{{
			ID: "rule-runtime", RuleType: "regex", Name: "runtime", Severity: "high", Action: "block", Enabled: true,
			MatchConfigJSON: []byte(`{"regex":"token"}`),
		}},
		excErr: errors.New("sensitive database connection detail"),
	}
	pack, err := compileTenantRulePackFromSources(
		context.Background(),
		"tenant-degraded",
		rulePackTenantSourceStub{tenant: &repository.Tenant{ID: "tenant-degraded", Industry: "finance"}},
		source,
	)
	if err != nil {
		t.Fatalf("degraded compilation must remain available: %v", err)
	}
	if source.industry != "finance" {
		t.Fatalf("existing tenant industry was not used, got %q", source.industry)
	}
	if !pack.Degraded || !containsRuntimeWarning(pack.Warnings, runtimeWarningExceptionsUnavailable) {
		t.Fatalf("degradation warnings missing: degraded=%v warnings=%v", pack.Degraded, pack.Warnings)
	}
	joined := strings.Join(pack.Warnings, " ")
	if strings.Contains(joined, "database") || strings.Contains(joined, "private") {
		t.Fatalf("warnings leaked backend details: %v", pack.Warnings)
	}
}

func TestCompileTenantRulePackFailsClosedOnExceptionLimit(t *testing.T) {
	source := &rulePackRuleSourceStub{excErr: repository.ErrContentAuditExceptionLimitExceeded}
	_, err := compileTenantRulePackFromSources(
		context.Background(),
		"tenant-exception-limit",
		rulePackTenantSourceStub{tenant: &repository.Tenant{ID: "tenant-exception-limit"}},
		source,
	)
	if !errors.Is(err, repository.ErrContentAuditExceptionLimitExceeded) {
		t.Fatalf("exception overflow error=%v want stable limit error", err)
	}
}

func TestInternalRulePackReturns503WhenActiveExceptionsExceedLimit(t *testing.T) {
	f := newSecurityRulesFixture(t)
	resetRulePackPullLedger(t)
	ctx := context.Background()
	for _, statement := range []string{
		`ALTER TABLE tenants ADD COLUMN name text NOT NULL DEFAULT 'tenant', ADD COLUMN edition text NOT NULL DEFAULT 'enterprise', ADD COLUMN status text NOT NULL DEFAULT 'active', ADD COLUMN industry text NOT NULL DEFAULT 'generic', ADD COLUMN config_json jsonb NOT NULL DEFAULT '{}', ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(), ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now()`,
		`ALTER TABLE rule_sets ADD COLUMN industry text NOT NULL DEFAULT 'generic'`,
		`CREATE TABLE content_audit_exceptions (
			id text PRIMARY KEY, tenant_id text NOT NULL, scope_type text NOT NULL,
			scope_ref text, include_children boolean NOT NULL DEFAULT false, rule_id text, rule_ref text, decision text NOT NULL,
			reason text, expires_at timestamptz, enabled boolean NOT NULL DEFAULT true,
			created_by text, created_at timestamptz NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := f.pool.Exec(ctx, statement); err != nil {
			t.Fatalf("prepare exception overflow fixture: %v", err)
		}
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO content_audit_exceptions
			(id, tenant_id, scope_type, scope_ref, decision, reason, expires_at, enabled, created_by)
		SELECT 'cex_pack_limit_' || value::text, $1, 'tenant', '', 'audit', 'limit probe', NOW() + INTERVAL '1 day', TRUE, 'test'
		FROM generate_series(1, 10001) AS value
	`, f.tenantA); err != nil {
		t.Fatalf("insert exception overflow fixture: %v", err)
	}

	f.deps.TenantRepo = repository.NewTenantRepository(f.pool)
	f.deps.SystemRepo = &contentConfigSystemRepo{}
	f.deps.RulePackAttestationTokens = map[string]string{f.tenantA: "exception-limit-attestation"}
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/rules/pack", nil)
	request.Header.Set("X-Tenant-ID", f.tenantA)
	request.Header.Set(rulePackAttestationHeader, "exception-limit-attestation")
	request.Header.Set(nodeIDHeader, "node-exception-limit")
	recorder := httptest.NewRecorder()

	GetInternalRulePack(f.deps).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("exception overflow status=%d want503 body_bytes=%d", recorder.Code, recorder.Body.Len())
	}
	if !strings.Contains(recorder.Body.String(), runtimeCompileUnavailableCode) {
		t.Fatalf("exception overflow must return stable safe code: %s", recorder.Body.String())
	}
	if nodes := listRulePackPullStatus(f.tenantA, "", time.Now().UTC()); len(nodes) != 0 {
		t.Fatalf("failed overflow pull must not create a convergence receipt: %+v", nodes)
	}
}

func TestCompileTenantRulePackSuccessIsNotDegraded(t *testing.T) {
	source := &rulePackRuleSourceStub{}
	pack, err := compileTenantRulePackFromSources(
		context.Background(),
		"tenant-finance",
		rulePackTenantSourceStub{tenant: &repository.Tenant{ID: "tenant-finance", Industry: "finance"}},
		source,
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if source.industry != "finance" || pack.Degraded || len(pack.Warnings) != 0 {
		t.Fatalf("successful source lookup should be clean: industry=%q degraded=%v warnings=%v", source.industry, pack.Degraded, pack.Warnings)
	}
}

func TestCompileTenantRulePackBlankIndustryUsesGeneric(t *testing.T) {
	source := &rulePackRuleSourceStub{}
	_, err := compileTenantRulePackFromSources(
		context.Background(),
		"tenant-blank-industry",
		rulePackTenantSourceStub{tenant: &repository.Tenant{ID: "tenant-blank-industry", Industry: " \t "}},
		source,
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if source.industry != "generic" {
		t.Fatalf("blank tenant industry=%q want generic", source.industry)
	}
}

func TestCompileTenantRulePackRejectsCandidateOverflow(t *testing.T) {
	candidates := make([]*repository.Rule, maxRulePackCandidates+1)
	for i := range candidates {
		candidates[i] = &repository.Rule{ID: fmt.Sprintf("candidate-%05d", i), RuleType: "keyword", Enabled: true, MatchConfigJSON: []byte(`{"keywords":["x"]}`)}
	}
	source := &rulePackRuleSourceStub{rules: candidates}
	_, err := compileTenantRulePackFromSources(context.Background(), "tenant-overflow", rulePackTenantSourceStub{tenant: &repository.Tenant{ID: "tenant-overflow"}}, source)
	if err == nil || !errors.Is(err, errRulePackCandidateLimitExceeded) {
		t.Fatalf("candidate overflow error=%v want stable limit error", err)
	}
}

func TestCompileTenantRulePackRejectsMissingOrUnknownTenantSource(t *testing.T) {
	for _, tc := range []struct {
		name         string
		tenantSource rulePackTenantSource
	}{
		{name: "missing dependency", tenantSource: nil},
		{name: "tenant not found", tenantSource: rulePackTenantSourceStub{}},
		{name: "tenant query error", tenantSource: rulePackTenantSourceStub{err: errors.New("database unavailable")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &rulePackRuleSourceStub{}
			if _, err := compileTenantRulePackFromSources(context.Background(), "tenant-missing-source", tc.tenantSource, source); err == nil {
				t.Fatal("tenant uncertainty must return unavailable so engine keeps last-good")
			}
		})
	}
}

func TestApplyRulePackFilePolicyFailsClosedOnUnavailableOrInvalidPolicy(t *testing.T) {
	ctx := context.Background()
	base := securityrules.Compile("tenant-policy", nil, nil)
	for _, tc := range []struct {
		name string
		repo SystemRepo
	}{
		{name: "missing dependency", repo: nil},
		{name: "read failure", repo: &runtimeSystemRepoStub{getErr: errors.New("private database detail")}},
		{name: "invalid json", repo: &runtimeSystemRepoStub{setting: &repository.SystemSetting{Key: "content_file_policy_json", Value: `{`}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pack := base
			if err := applyRulePackFilePolicy(ctx, tc.repo, "tenant-policy", &pack); err == nil {
				t.Fatal("policy uncertainty must fail closed so engine keeps last-good pack")
			}
		})
	}

	pack := base
	if err := applyRulePackFilePolicy(ctx, &runtimeSystemRepoStub{}, "tenant-policy", &pack); err != nil || pack.FilePolicy != nil {
		t.Fatalf("missing/empty setting means intentionally unconfigured: policy=%+v err=%v", pack.FilePolicy, err)
	}
	pack = base
	valid := `{"allowed_types":["pdf"],"max_file_mb":10}`
	if err := applyRulePackFilePolicy(ctx, &runtimeSystemRepoStub{setting: &repository.SystemSetting{Key: contentFilePolicySettingKeyForTenant("tenant-policy"), Value: valid}}, "tenant-policy", &pack); err != nil || pack.FilePolicy == nil || pack.FilePolicy.MaxFileMB != 10 {
		t.Fatalf("valid file policy not applied: policy=%+v err=%v", pack.FilePolicy, err)
	}
}

func TestRuntimeStatusNeedsFreshHeldVersionBeforeVerification(t *testing.T) {
	resetRulePackPullLedger(t)
	tenantID := "tenant-runtime-proof"
	pack := &securityrules.RulePack{
		TenantID: tenantID,
		Version:  "desired-version",
		Rules:    make([]securityrules.CompiledRule, 5),
		Diagnostics: securityrules.RuleDiagnostics{
			CatalogCount: 260, CompiledCount: 5, SkippedCount: 255,
			SkipReasons: map[string]int{"no_supported_matcher": 255},
		},
	}

	withoutReceipt := ruleRuntimeStatusFromPack(pack, evaluateRulePackConvergence(tenantID, pack.Version))
	if withoutReceipt.RuntimeVerified || withoutReceipt.ActiveRuntimeCount != nil || withoutReceipt.Status != runtimeStatusPending {
		t.Fatalf("desired state without node receipt must remain unverified: %+v", withoutReceipt)
	}
	if withoutReceipt.CatalogCount != 260 || withoutReceipt.CompiledCount != 5 || withoutReceipt.SkippedCount != 255 || withoutReceipt.Reasons["no_supported_matcher"] != 255 {
		t.Fatalf("runtime diagnostics drifted: %+v", withoutReceipt)
	}

	now := rulePackStatusNow()
	active, skipped := 5, 0
	policyCount := len(pack.Policies)
	recordRulePackPullWithPolicyTelemetry("node-proof", tenantID, pack.Version, pack.Version, &active, &skipped, &policyCount, 0, now)
	verified := ruleRuntimeStatusFromPack(pack, evaluateRulePackConvergence(tenantID, pack.Version))
	if !verified.RuntimeVerified || verified.ActiveRuntimeCount == nil || *verified.ActiveRuntimeCount != 5 || verified.Status != runtimeStatusApplied {
		t.Fatalf("fresh held-version receipt must verify active runtime count: %+v", verified)
	}
}

func TestRuntimeStatusRequiresActualCountsAndReportsDegradedExecution(t *testing.T) {
	resetRulePackPullLedger(t)
	tenantID := "tenant-runtime-counts"
	pack := &securityrules.RulePack{
		TenantID:    tenantID,
		Version:     "desired",
		Rules:       make([]securityrules.CompiledRule, 2),
		Diagnostics: securityrules.RuleDiagnostics{CatalogCount: 2, CompiledCount: 2},
	}
	now := rulePackStatusNow()

	recordRulePackPull("node-count", tenantID, pack.Version, pack.Version, now)
	missing := ruleRuntimeStatusFromPack(pack, evaluateRulePackConvergence(tenantID, pack.Version))
	if missing.RuntimeVerified || missing.ActiveRuntimeCount != nil || missing.Status != runtimeStatusCountUnavailable {
		t.Fatalf("missing engine counts must not verify runtime: %+v", missing)
	}

	active, skipped := 1, 1
	policyCount := len(pack.Policies)
	recordRulePackPullWithPolicyTelemetry("node-count", tenantID, pack.Version, pack.Version, &active, &skipped, &policyCount, 0, now)
	degraded := ruleRuntimeStatusFromPack(pack, evaluateRulePackConvergence(tenantID, pack.Version))
	if !degraded.RuntimeVerified || degraded.ActiveRuntimeCount == nil || *degraded.ActiveRuntimeCount != 1 || degraded.Status != runtimeStatusAppliedDegraded || !containsRuntimeWarning(degraded.Warnings, runtimeWarningActiveCountBelowCompiled) {
		t.Fatalf("actual engine skip must be verified but explicitly degraded: %+v", degraded)
	}
}

func TestRuntimeStatusRejectsInconsistentCountsAndIgnoresStaleNodeInFreshDenominator(t *testing.T) {
	resetRulePackPullLedger(t)
	tenantID := "tenant-runtime-consistency"
	pack := &securityrules.RulePack{
		TenantID:    tenantID,
		Version:     "desired",
		Rules:       make([]securityrules.CompiledRule, 2),
		Diagnostics: securityrules.RuleDiagnostics{CatalogCount: 2, CompiledCount: 2},
	}
	now := rulePackStatusNow()
	active2, skipped0 := 2, 0
	active1, skipped1 := 1, 1
	policyCount := len(pack.Policies)
	recordRulePackPullWithPolicyTelemetry("node-a", tenantID, pack.Version, pack.Version, &active2, &skipped0, &policyCount, 0, now)
	recordRulePackPullWithPolicyTelemetry("node-b", tenantID, pack.Version, pack.Version, &active1, &skipped1, &policyCount, 0, now)
	inconsistent := ruleRuntimeStatusFromPack(pack, evaluateRulePackConvergence(tenantID, pack.Version))
	if inconsistent.RuntimeVerified || inconsistent.ActiveRuntimeCount != nil || inconsistent.Status != runtimeStatusCountInconsistent {
		t.Fatalf("fresh nodes with different actual counts must not verify: %+v", inconsistent)
	}

	resetRulePackPullLedger(t)
	recordRulePackPullWithPolicyTelemetry("node-fresh", tenantID, pack.Version, pack.Version, &active2, &skipped0, &policyCount, 0, now)
	recordRulePackPullWithPolicyTelemetry("node-stale", tenantID, pack.Version, pack.Version, &active1, &skipped1, &policyCount, 0, now.Add(-rulePackFreshnessWindow-time.Second))
	withStale := ruleRuntimeStatusFromPack(pack, evaluateRulePackConvergence(tenantID, pack.Version))
	if !withStale.RuntimeVerified || withStale.ActiveRuntimeCount == nil || *withStale.ActiveRuntimeCount != 2 || withStale.Status != runtimeStatusAppliedWithStaleNodes || !containsRuntimeWarning(withStale.Warnings, runtimeWarningStaleNodes) {
		t.Fatalf("stale node must be warned but excluded from fresh proof denominator: %+v", withStale)
	}
}

func TestRuntimeStatusFreshLaggingNodeBlocksVerification(t *testing.T) {
	resetRulePackPullLedger(t)
	tenantID := "tenant-runtime-partial"
	pack := &securityrules.RulePack{TenantID: tenantID, Version: "desired", Diagnostics: securityrules.RuleDiagnostics{CatalogCount: 2, CompiledCount: 2}}
	now := rulePackStatusNow()
	active, skipped := 2, 0
	recordRulePackPullWithCounts("node-applied", tenantID, pack.Version, pack.Version, &active, &skipped, now)
	recordRulePackPullWithCounts("node-lagging", tenantID, "old", pack.Version, &active, &skipped, now)
	partial := ruleRuntimeStatusFromPack(pack, evaluateRulePackConvergence(tenantID, pack.Version))
	if partial.RuntimeVerified || partial.ActiveRuntimeCount != nil || partial.Status != runtimeStatusPartiallyApplied || partial.FreshCount != 2 || partial.FreshConvergedCount != 1 {
		t.Fatalf("fresh lagging node must block verification: %+v", partial)
	}
}

func TestRuntimeStatusLoadedDegradedPackNeverClaimsPlainApplied(t *testing.T) {
	resetRulePackPullLedger(t)
	tenantID := "tenant-pack-degraded"
	pack := &securityrules.RulePack{
		TenantID: tenantID, Version: "desired", Degraded: true,
		Warnings:    []string{runtimeWarningExceptionsUnavailable},
		Rules:       make([]securityrules.CompiledRule, 1),
		Diagnostics: securityrules.RuleDiagnostics{CatalogCount: 1, CompiledCount: 1},
	}
	active, skipped := 1, 0
	policyCount := len(pack.Policies)
	recordRulePackPullWithPolicyTelemetry("node-degraded", tenantID, pack.Version, pack.Version, &active, &skipped, &policyCount, 0, rulePackStatusNow())
	status := ruleRuntimeStatusFromPack(pack, evaluateRulePackConvergence(tenantID, pack.Version))
	if !status.RuntimeVerified || status.Status != runtimeStatusAppliedDegraded || !status.Degraded || status.LastError != runtimeCompileDegradedCode || !containsRuntimeWarning(status.Warnings, runtimeWarningPackDegraded) {
		t.Fatalf("loaded degraded pack claimed healthy applied state: %+v", status)
	}
}

func TestRulePackJSONCarriesDiagnosticsAndDegradation(t *testing.T) {
	pack := securityrules.Compile("tenant-json", []*repository.Rule{{
		ID: "catalog", RuleType: "prompt_injection", Name: "catalog", Action: "audit", Enabled: true, MatchConfigJSON: []byte(`{}`),
	}}, nil)
	pack.Degraded = true
	pack.Warnings = []string{runtimeWarningExceptionsUnavailable}
	blob, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("marshal pack: %v", err)
	}
	text := string(blob)
	for _, want := range []string{`"diagnostics"`, `"catalog_count":1`, `"compiled_count":0`, `"skipped_count":1`, `"no_supported_matcher":1`, `"degraded":true`, runtimeWarningExceptionsUnavailable} {
		if !strings.Contains(text, want) {
			t.Fatalf("pack JSON missing %q: %s", want, text)
		}
	}
}

func TestVersionAndSyncExposeStructuredRuntimeWithRealPostgres(t *testing.T) {
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
			t.Fatalf("prepare runtime diagnostics fixture: %v", err)
		}
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM rules WHERE id=$1`, f.managedA); err != nil {
		t.Fatalf("exclude unrelated managed rule: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE rules SET enabled=false WHERE id=$1`, f.fakeDomainA); err != nil {
		t.Fatalf("disable candidate for diagnostics: %v", err)
	}
	f.deps.TenantRepo = repository.NewTenantRepository(f.pool)
	systemRepo := &contentConfigSystemRepo{}
	f.deps.SystemRepo = systemRepo
	f.deps.RulePackAttestationTokens = map[string]string{f.tenantA: "runtime-pg-attestation"}

	versionReq := runtimeAPIRequest(http.MethodGet, "/admin/v1/system/version", f.tenantA, "viewer")
	versionRec := httptest.NewRecorder()
	GetVersionInfo(f.deps).ServeHTTP(versionRec, versionReq)
	if versionRec.Code != http.StatusOK {
		t.Fatalf("version status=%d body=%s", versionRec.Code, versionRec.Body.String())
	}
	var versionBody struct {
		RuleSetVersion string            `json:"ruleset_version"`
		Runtime        ruleRuntimeStatus `json:"runtime"`
	}
	if err := json.Unmarshal(versionRec.Body.Bytes(), &versionBody); err != nil {
		t.Fatalf("decode version runtime: %v body=%s", err, versionRec.Body.String())
	}
	if versionBody.RuleSetVersion == "" || versionBody.Runtime.DesiredVersion != versionBody.RuleSetVersion {
		t.Fatalf("desired and legacy versions diverged: %+v", versionBody)
	}
	if versionBody.Runtime.CatalogCount != 3 || versionBody.Runtime.CompiledCount != 1 || versionBody.Runtime.SkippedCount != 2 {
		t.Fatalf("unexpected real diagnostics: %+v", versionBody.Runtime)
	}
	if versionBody.Runtime.Reasons["disabled"] != 1 || versionBody.Runtime.Reasons["management_only"] != 1 {
		t.Fatalf("disabled and management-only candidates must reach compiler diagnostics: %+v", versionBody.Runtime.Reasons)
	}
	if versionBody.Runtime.RuntimeVerified || versionBody.Runtime.ActiveRuntimeCount != nil || versionBody.Runtime.Status != runtimeStatusPending {
		t.Fatalf("no receipt must remain unverified: %+v", versionBody.Runtime)
	}

	pullReq := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/rules/pack", nil)
	pullReq.Header.Set("X-Tenant-ID", f.tenantA)
	pullReq.Header.Set(nodeIDHeader, "node-runtime-pg")
	pullReq.Header.Set(rulePackVersionHeader, versionBody.RuleSetVersion)
	pullReq.Header.Set(rulePackActiveCountHeader, "1")
	pullReq.Header.Set(rulePackSkippedCountHeader, "0")
	pullReq.Header.Set(rulePackPolicyCountHeader, fmt.Sprintf("%d", versionBody.Runtime.CompiledPolicyCount))
	pullReq.Header.Set(rulePackRefreshSecondsHeader, "60")
	pullReq.Header.Set(rulePackAttestationHeader, "runtime-pg-attestation")
	pullRec := httptest.NewRecorder()
	GetInternalRulePack(f.deps).ServeHTTP(pullRec, pullReq)
	if pullRec.Code != http.StatusOK || !strings.Contains(pullRec.Body.String(), `"diagnostics"`) {
		t.Fatalf("internal pack telemetry handshake status=%d body=%s", pullRec.Code, pullRec.Body.String())
	}
	statusReq := newRulePackAdminRequest(http.MethodGet, "/admin/v1/rules/pull-status", f.tenantA)
	statusRec := httptest.NewRecorder()
	GetRulePackPullStatus(f.deps).ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK || !strings.Contains(statusRec.Body.String(), `"status":"converged"`) || !strings.Contains(statusRec.Body.String(), `"active_runtime_count":1`) {
		t.Fatalf("pull-status did not classify against authoritative telemetry: status=%d body=%s", statusRec.Code, statusRec.Body.String())
	}
	syncReq := runtimeAPIRequest(http.MethodPost, "/admin/v1/system/ruleset/sync", f.tenantA, "platform_admin")
	syncRec := httptest.NewRecorder()
	SyncRuleSet(f.deps).ServeHTTP(syncRec, syncReq)
	if syncRec.Code != http.StatusOK {
		t.Fatalf("sync status=%d body=%s", syncRec.Code, syncRec.Body.String())
	}
	var syncBody struct {
		RuleSetVersion string            `json:"ruleset_version"`
		Runtime        ruleRuntimeStatus `json:"runtime"`
	}
	if err := json.Unmarshal(syncRec.Body.Bytes(), &syncBody); err != nil {
		t.Fatalf("decode sync runtime: %v body=%s", err, syncRec.Body.String())
	}
	if syncBody.RuleSetVersion != versionBody.RuleSetVersion || !syncBody.Runtime.RuntimeVerified || syncBody.Runtime.ActiveRuntimeCount == nil || *syncBody.Runtime.ActiveRuntimeCount != 1 || syncBody.Runtime.Status != runtimeStatusApplied {
		t.Fatalf("fresh held receipt did not verify runtime: %+v", syncBody)
	}

	systemRepo.settings = map[string]string{contentFilePolicySettingKeyForTenant(f.tenantA): `{`}
	badPolicyReq := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/rules/pack", nil)
	badPolicyReq.Header.Set("X-Tenant-ID", f.tenantA)
	badPolicyReq.Header.Set(rulePackAttestationHeader, "runtime-pg-attestation")
	badPolicyReq.Header.Set(nodeIDHeader, "node-runtime-pg-bad-policy")
	badPolicyRec := httptest.NewRecorder()
	GetInternalRulePack(f.deps).ServeHTTP(badPolicyRec, badPolicyReq)
	if badPolicyRec.Code != http.StatusServiceUnavailable || !strings.Contains(badPolicyRec.Body.String(), runtimeCompileUnavailableCode) || strings.Contains(strings.ToLower(badPolicyRec.Body.String()), "json") {
		t.Fatalf("invalid file policy must keep last-good via safe 503: status=%d body=%s", badPolicyRec.Code, badPolicyRec.Body.String())
	}
}

func containsRuntimeWarning(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
