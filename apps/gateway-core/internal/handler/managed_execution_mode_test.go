package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func managedGatewayPayload(t *testing.T, auditOnly bool, marker any) map[string]any {
	t.Helper()
	payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, auditOnly, false)
	payload["security_execution_mode_managed"] = marker
	if _, ok := marker.(bool); ok {
		revision, err := semanticGatewayConfigRevision(payload, gatewaySemanticTestKey)
		if err != nil {
			t.Fatal(err)
		}
		payload["revision"] = revision
	}
	return payload
}

// 未设部署锁时，签名的 managed 快照双向生效；部署锁（env=true）见
// TestGatewayDeploymentAuditOnlyIsHardCeilingOverManagedProtect。
func TestManagedExecutionModeAppliesBidirectionallyWithoutDeploymentLock(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	var payload atomic.Value
	var reportSnapshot atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == semanticGatewayConfigPath {
			_ = json.NewEncoder(w).Encode(payload.Load().(map[string]any))
			return
		}
		var reported map[string]any
		_ = json.NewDecoder(r.Body).Decode(&reported)
		reportSnapshot.Store(reported)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	for _, auditOnly := range []bool{false, true, false} {
		next := managedGatewayPayload(t, auditOnly, true)
		payload.Store(next)
		config, err := client.refreshSemanticRuntimeConfig(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !config.SecurityExecutionModeManaged || config.SecurityAuditOnly != auditOnly ||
			client.SecurityAuditOnly(context.Background(), true) != auditOnly {
			t.Fatalf("managed auditOnly=%v not applied: %+v", auditOnly, config)
		}
		reported := reportSnapshot.Load().(map[string]any)
		if config.Revision != next["revision"] || reported["applied_revision"] != next["revision"] {
			t.Fatalf("managed revision changed or was not reported: config=%+v report=%v", config, reported)
		}
	}
}

func TestManagedExecutionModeRejectsUntrustedMarkerAndKeepsLastGood(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	for _, tc := range []struct {
		name     string
		marker   any
		tampered bool
	}{
		{"string", "true", false}, {"number", 1, false}, {"null", nil, false},
		{"object", map[string]any{}, false}, {"tampered", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			valid := managedGatewayPayload(t, false, true)
			bad := managedGatewayPayload(t, false, tc.marker)
			if tc.tampered {
				bad = signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
				bad["security_execution_mode_managed"] = true
			}
			var payload atomic.Value
			payload.Store(valid)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == semanticGatewayConfigPath {
					_ = json.NewEncoder(w).Encode(payload.Load().(map[string]any))
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
			if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err != nil {
				t.Fatal(err)
			}
			payload.Store(bad)
			if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err == nil {
				t.Fatal("invalid or unsigned marker was accepted")
			}
			held, _ := client.runtimeCache.getSemanticConfig()
			if held.Revision != valid["revision"] || !held.SecurityExecutionModeManaged ||
				client.SecurityAuditOnly(context.Background(), true) {
				t.Fatalf("failed refresh lost last-good managed protect: %+v", held)
			}
			fresh := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
			if _, err := fresh.refreshSemanticRuntimeConfig(context.Background()); err == nil {
				t.Fatal("fresh invalid marker accepted")
			}
			if !fresh.SecurityAuditOnly(context.Background(), false) {
				t.Fatal("invalid marker bypassed startup audit ceiling")
			}
		})
	}
}

func TestManagedExecutionModeAbsentOrFalsePreservesLegacyCeiling(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	for _, present := range []bool{false, true} {
		payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
		if present {
			payload = managedGatewayPayload(t, false, false)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(payload)
		}))
		client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
		config, err := client.fetchSemanticRuntimeConfig(context.Background())
		server.Close()
		if err != nil {
			t.Fatal(err)
		}
		if config.SecurityExecutionModeManaged || !config.SecurityAuditOnly {
			t.Fatalf("legacy ceiling changed: %+v", config)
		}
	}
}
