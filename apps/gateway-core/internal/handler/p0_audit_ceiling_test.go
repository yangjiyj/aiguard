package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 2.9.22（设计 D7）：部署变量 SECURITY_AUDIT_ONLY=true 只在没有显式执行模式时作初值；
// 控制台显式选了防护阻断（签名 managed protect）就按防护执行。原断言“部署锁压过 managed protect”
// （P0 2026-09-27）随用户 11-17 决定改写。
func TestGatewayDeploymentAuditOnlyIsOnlyInitialValue(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	for _, tc := range []struct {
		name       string
		managed    bool
		wantRecord bool
	}{
		{"managed-protect-wins", true, false},
		{"unmanaged-uses-deployment-initial-value", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := managedGatewayPayload(t, false, tc.managed)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == semanticGatewayConfigPath {
					_ = json.NewEncoder(w).Encode(payload)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
			config, err := client.refreshSemanticRuntimeConfig(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if config.SecurityAuditOnly != tc.wantRecord || client.SecurityAuditOnly(context.Background(), !tc.wantRecord) != tc.wantRecord {
				t.Fatalf("record=%v want %v: %+v", config.SecurityAuditOnly, tc.wantRecord, config)
			}
		})
	}
}

// 客户部署（未设部署锁）：控制台 protect 仍生效。
func TestGatewayManagedProtectAppliesWithoutDeploymentLock(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	payload := managedGatewayPayload(t, false, true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == semanticGatewayConfigPath {
			_ = json.NewEncoder(w).Encode(payload)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.SecurityAuditOnly(context.Background(), true) {
		t.Fatal("managed protect must apply when deployment is not locked")
	}
}
