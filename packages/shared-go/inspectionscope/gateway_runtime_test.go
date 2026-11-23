package inspectionscope

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

const runtimeTestKey = "inspection-runtime-test-key"

func signedRuntimeFixture() map[string]any {
	config := map[string]any{"semantic_enabled": true, "semantic_input_enabled": true, "semantic_agent_enabled": true, "security_audit_only": true, "file_content_dlp_enabled": false,
		"inspect_user_input": true, "inspect_model_output": true, "inspect_builtin_context": false, "inspect_history": false, "inspect_tool_results": true}
	signRuntimeFixture(config)
	return config
}
func signRuntimeFixture(config map[string]any) {
	var keys []string
	for key := range config {
		if key != "revision" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&canonical, "%d:%s=", len(key), key)
		if config[key] == true {
			canonical.WriteString("b:1;")
		} else {
			canonical.WriteString("b:0;")
		}
	}
	mac := hmac.New(sha256.New, []byte(runtimeTestKey))
	mac.Write([]byte("jjdguard:semantic-config:gateway-core\n" + canonical.String()))
	config["revision"] = hex.EncodeToString(mac.Sum(nil)[:16])
}

func TestProxyRuntimeReportsActualIdentityAndFailedLastGood(t *testing.T) {
	config := signedRuntimeFixture()
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); json.NewEncoder(w).Encode(config) }))
	defer server.Close()
	now := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	reader := NewGatewayReader(server.URL, "test-internal-token", runtimeTestKey)
	reader.now = func() time.Time { return now }
	if got := reader.RuntimeStatus(); got.ConfigLoaded || got.Fresh || got.Status == "applied" {
		t.Fatalf("unloaded appeared applied: %+v", got)
	}
	if err := reader.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	good := reader.RuntimeStatus()
	if good.Component != "proxy-server" || good.ConfigComponent != "gateway-core" || good.Status != "applied" || !good.Fresh || good.AppliedRevision != config["revision"] {
		t.Fatalf("wrong successful status: %+v", good)
	}
	status = 503
	now = now.Add(30 * time.Second)
	if err := reader.Refresh(context.Background()); err == nil {
		t.Fatal("failed fetch accepted")
	}
	failed := reader.RuntimeStatus()
	if failed.Status != "degraded" || failed.Fresh || !failed.ConfigLoaded || failed.HeldRevision != good.AppliedRevision || failed.ErrorCode != "control_plane_unavailable" || failed.LastSuccessAt != good.LastSuccessAt {
		t.Fatalf("last-good failure hidden: %+v", failed)
	}
	status = 200
	config["inspect_history"] = true
	signRuntimeFixture(config)
	if err := reader.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := reader.RuntimeStatus(); got.Status != "applied" || got.ErrorCode != "" || got.AppliedRevision == good.AppliedRevision {
		t.Fatalf("recovery failed: %+v", got)
	}
	now = now.Add(121 * time.Second)
	if got := reader.RuntimeStatus(); got.Fresh || got.Status != "degraded" || got.ErrorCode != "config_stale" {
		t.Fatalf("expired success stayed green: %+v", got)
	}
}

func TestProxyRuntimeMissingKeyAndRejectedSignatureAreVisible(t *testing.T) {
	reader := NewGatewayReader("http://127.0.0.1:1", "internal-secret", "")
	if err := reader.Refresh(context.Background()); err == nil {
		t.Fatal("missing key accepted")
	}
	if got := reader.RuntimeStatus(); got.ErrorCode != "attestation_key_missing" || got.ConfigLoaded {
		t.Fatalf("missing key hidden: %+v", got)
	}
	config := signedRuntimeFixture()
	config["inspect_history"] = true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(config) }))
	defer server.Close()
	reader = NewGatewayReader(server.URL, "internal-secret", runtimeTestKey)
	if err := reader.Refresh(context.Background()); err == nil {
		t.Fatal("unsigned change accepted")
	}
	if got := reader.RuntimeStatus(); got.ErrorCode != "config_attestation_invalid" || got.ConfigLoaded {
		t.Fatalf("signature failure hidden: %+v", got)
	}
	encoded, _ := json.Marshal(reader.RuntimeStatus())
	if strings.Contains(string(encoded), runtimeTestKey) || strings.Contains(string(encoded), "internal-secret") {
		t.Fatal("runtime status leaked authentication")
	}
}

func TestProxyRuntimeLegacyProjectionCannotClaimManagedScope(t *testing.T) {
	config := signedRuntimeFixture()
	for _, key := range []string{"inspect_user_input", "inspect_model_output", "inspect_builtin_context", "inspect_history", "inspect_tool_results"} {
		delete(config, key)
	}
	signRuntimeFixture(config)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(config) }))
	defer server.Close()
	reader := NewGatewayReader(server.URL, "internal-token", runtimeTestKey)
	if err := reader.Refresh(context.Background()); err == nil {
		t.Fatal("legacy default-only projection claimed managed scope")
	}
	if got := reader.RuntimeStatus(); got.ConfigLoaded || got.ErrorCode != "inspection_scope_unmanaged" {
		t.Fatalf("legacy scope status=%+v", got)
	}
}
