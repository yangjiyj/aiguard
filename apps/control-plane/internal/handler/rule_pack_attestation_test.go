package handler

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func attestedInternalPackRequest(tenantID, token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/rules/pack", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set(nodeIDHeader, "attestation-test-node")
	if token != "" {
		req.Header.Set(rulePackAttestationHeader, token)
	}
	return req
}

func TestInternalRulePackRequiresBoundedNodeAndRealHeldVersion(t *testing.T) {
	deps := &Dependencies{RulePackAttestationTokens: map[string]string{"tenant-a": "secret"}}
	for _, tc := range []struct {
		name     string
		nodeID   string
		held     string
		wantCode string
	}{
		{name: "missing node", nodeID: "", wantCode: invalidRulePackNodeCode},
		{name: "invalid version", nodeID: "node-a", held: "version-old", wantCode: invalidRulePackVersionCode},
		{name: "oversized version", nodeID: "node-a", held: strings.Repeat("a", 64<<10), wantCode: invalidRulePackVersionCode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetRulePackPullLedger(t)
			req := attestedInternalPackRequest("tenant-a", "secret")
			req.Header.Set(nodeIDHeader, tc.nodeID)
			req.Header.Set(rulePackVersionHeader, tc.held)
			rec := httptest.NewRecorder()
			GetInternalRulePack(deps).ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.wantCode) {
				t.Fatalf("status=%d code=%q body=%s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if nodes := listRulePackPullStatus("tenant-a", "", time.Now().UTC()); len(nodes) != 0 {
				t.Fatalf("invalid request polluted ledger: %+v", nodes)
			}
		})
	}
}

func TestInternalRulePackRequiresTenantScopedAttestationBeforeCompile(t *testing.T) {
	tokens := map[string]string{"tenant-a": "attest-a-secret", "tenant-b": "attest-b-secret"}
	deps := &Dependencies{RulePackAttestationTokens: tokens}

	for _, tc := range []struct {
		name       string
		tenantID   string
		token      string
		wantStatus int
		wantCode   string
	}{
		{name: "missing map entry", tenantID: "tenant-c", token: "anything", wantStatus: http.StatusServiceUnavailable, wantCode: rulePackAttestationUnavailableCode},
		{name: "old shared secret only", tenantID: "tenant-a", token: "", wantStatus: http.StatusUnauthorized, wantCode: rulePackAttestationInvalidCode},
		{name: "wrong tenant token", tenantID: "tenant-b", token: tokens["tenant-a"], wantStatus: http.StatusUnauthorized, wantCode: rulePackAttestationInvalidCode},
		{name: "wrong token", tenantID: "tenant-a", token: "wrong", wantStatus: http.StatusUnauthorized, wantCode: rulePackAttestationInvalidCode},
		{name: "correct token reaches compiler", tenantID: "tenant-a", token: tokens["tenant-a"], wantStatus: http.StatusServiceUnavailable, wantCode: runtimeCompileUnavailableCode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			GetInternalRulePack(deps).ServeHTTP(rec, attestedInternalPackRequest(tc.tenantID, tc.token))
			if rec.Code != tc.wantStatus || !strings.Contains(rec.Body.String(), tc.wantCode) {
				t.Fatalf("status=%d want=%d code=%q body=%s", rec.Code, tc.wantStatus, tc.wantCode, rec.Body.String())
			}
			for _, secret := range tokens {
				if strings.Contains(rec.Body.String(), secret) {
					t.Fatalf("response leaked attestation token: %s", rec.Body.String())
				}
			}
		})
	}
}

func TestInternalRulePackRejectsInvalidTenantContextBeforeAttestation(t *testing.T) {
	deps := &Dependencies{RulePackAttestationTokens: map[string]string{"tenant-a": "secret"}}
	for _, tenantID := range []string{"../tenant-a", "tenant a", strings.Repeat("x", maxRulePackTenantIDLength+1)} {
		rec := httptest.NewRecorder()
		GetInternalRulePack(deps).ServeHTTP(rec, attestedInternalPackRequest(tenantID, "secret"))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), invalidRulePackTenantCode) {
			t.Fatalf("invalid tenant %q status=%d body=%s", tenantID, rec.Code, rec.Body.String())
		}
	}
}

func TestInternalRulePackRejectsOverlongNodeIDBeforeCompile(t *testing.T) {
	deps := &Dependencies{RulePackAttestationTokens: map[string]string{"tenant-a": "secret"}}
	req := attestedInternalPackRequest("tenant-a", "secret")
	req.Header.Set(nodeIDHeader, strings.Repeat("n", rulePackNodeIDMaxLength+1))
	rec := httptest.NewRecorder()

	GetInternalRulePack(deps).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), invalidRulePackNodeCode) {
		t.Fatalf("overlong node status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestInternalRulePackSafe503LogCarriesRequestTenantAndCodeWithoutToken(t *testing.T) {
	const token = "attestation-secret-must-not-leak"
	deps := &Dependencies{RulePackAttestationTokens: map[string]string{"tenant-a": token}}
	req := attestedInternalPackRequest("tenant-a", token)
	req.Header.Set("X-Request-ID", "request-safe-log")
	rec := httptest.NewRecorder()

	var logs bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})

	GetInternalRulePack(deps).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	got := logs.String()
	for _, want := range []string{"request-safe-log", "tenant-a", runtimeCompileUnavailableCode} {
		if !strings.Contains(got, want) {
			t.Fatalf("safe log missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, token) {
		t.Fatalf("safe log leaked token: %s", got)
	}
}

func TestRuntimeStatusDeclaresTenantTokenAttestationMode(t *testing.T) {
	status := unavailableRuleRuntimeStatus()
	if status.AttestationMode != rulePackAttestationModeTenantToken {
		t.Fatalf("attestation_mode=%q want=%q", status.AttestationMode, rulePackAttestationModeTenantToken)
	}
}
