package handler

import (
	"bytes"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const gatewaySemanticRevision = "0123456789abcdef0123456789abcdef"
const gatewaySemanticTestKey = "semantic-gateway-test-key-32-bytes"
const gatewaySemanticInternalTestSecret = "semantic-internal-api-test-secret-32"

func signedGatewaySemanticPayload(key string, enabled, input, agent, auditOnly, fileDLP bool) map[string]any {
	payload := map[string]any{
		"semantic_enabled": enabled, "semantic_input_enabled": input,
		"semantic_agent_enabled": agent, "security_audit_only": auditOnly,
		"file_content_dlp_enabled": fileDLP,
	}
	keys := make([]string, 0, len(payload))
	for name := range payload {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	var canonical bytes.Buffer
	for _, name := range keys {
		_, _ = fmt.Fprintf(&canonical, "%d:%s=", len([]byte(name)), name)
		value := payload[name].(bool)
		if value {
			canonical.WriteString("b:1;")
		} else {
			canonical.WriteString("b:0;")
		}
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte("jjdguard:semantic-config:" + semanticGatewayComponent + "\n"))
	_, _ = mac.Write(canonical.Bytes())
	payload["revision"] = hex.EncodeToString(mac.Sum(nil)[:16])
	return payload
}

func TestGatewaySemanticConfigUsesSafeProjectionAndAtomicallyAppliesAuditOnly(t *testing.T) {
	var reports int32
	expectedRevision := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, false, true, false, false)["revision"].(string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case semanticGatewayConfigPath:
			if r.Header.Get("X-JJDGuard-Internal-Token") != gatewaySemanticInternalTestSecret {
				t.Errorf("missing internal token")
			}
			_ = json.NewEncoder(w).Encode(signedGatewaySemanticPayload(gatewaySemanticTestKey, true, false, true, false, false))
		case semanticGatewayReportPath:
			atomic.AddInt32(&reports, 1)
			if r.Header.Get("X-Rule-Pack-Attestation") != "" {
				t.Errorf("gateway sent engine attestation")
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["component"] != semanticGatewayComponent || body["applied_revision"] != expectedRevision || body["error_code"] != nil {
				t.Errorf("unexpected applied report: %#v", body)
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	client.runtimeCache.setSecurityAuditOnly(true)
	config, err := client.refreshSemanticRuntimeConfig(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !config.Enabled || config.InputEnabled || !config.AgentEnabled || config.SecurityAuditOnly {
		t.Fatalf("unexpected config: %+v", config)
	}
	if got := client.SecurityAuditOnly(context.Background(), true); got {
		t.Fatal("audit_only was not atomically applied")
	}
	if atomic.LoadInt32(&reports) != 1 {
		t.Fatalf("reports=%d want=1", reports)
	}
}

func TestGatewaySemanticConfigRejectsUnknownSecretBearingFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == semanticGatewayConfigPath {
			payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, true, false)
			payload["judge_api_key"] = "must-never-reach-gateway"
			_ = json.NewEncoder(w).Encode(payload)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	if _, err := client.fetchSemanticRuntimeConfig(context.Background()); err == nil {
		t.Fatal("gateway must reject engine-only fields")
	}
}

func TestGatewaySemanticConfigRejectsTamperedBodyAndPreservesLastGood(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case semanticGatewayConfigPath:
			payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
			payload["semantic_agent_enabled"] = false
			_ = json.NewEncoder(w).Encode(payload)
		case semanticGatewayReportPath:
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision: gatewaySemanticRevision, Enabled: true, InputEnabled: false,
		AgentEnabled: true, SecurityAuditOnly: true,
	})

	if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err == nil {
		t.Fatal("body changed without a matching revision must be rejected")
	}
	got, ok := client.runtimeCache.getSemanticConfig()
	if !ok || got.Revision != gatewaySemanticRevision || !got.AgentEnabled || got.InputEnabled || !got.SecurityAuditOnly {
		t.Fatalf("tampered refresh changed last-good: %+v ok=%v", got, ok)
	}
}

func TestGatewaySemanticConfigMissingDedicatedAttestationKeyFailsClosed(t *testing.T) {
	t.Setenv("JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == semanticGatewayConfigPath {
			_ = json.NewEncoder(w).Encode(signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, true, false))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, gatewaySemanticTestKey)
	if _, err := client.fetchSemanticRuntimeConfig(context.Background()); err == nil {
		t.Fatal("shared internal API secret must not be reused as the semantic attestation key")
	}
}

func TestGatewaySemanticHotPathNeverSynchronouslyFetches(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, "secret")
	if !client.SemanticAgentEnabled(context.Background(), true) {
		t.Fatal("cold cache must use caller fallback")
	}
	if client.SemanticInputEnabled(context.Background(), false) {
		t.Fatal("cold cache must use caller fallback")
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("business hot path performed %d synchronous calls", got)
	}
}

func TestGatewaySemanticRefreshFailurePreservesLastGoodAndReportsDegraded(t *testing.T) {
	reported := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case semanticGatewayConfigPath:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case semanticGatewayReportPath:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			reported <- body
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, "secret")
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision: gatewaySemanticRevision, Enabled: true, InputEnabled: true,
		AgentEnabled: false, SecurityAuditOnly: false,
	})
	if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err == nil {
		t.Fatal("refresh should fail")
	}
	if !client.SemanticInputEnabled(context.Background(), false) || client.SemanticAgentEnabled(context.Background(), true) {
		t.Fatal("failed refresh did not preserve last-good")
	}
	if client.SecurityAuditOnly(context.Background(), true) {
		t.Fatal("failed refresh changed audit_only")
	}
	select {
	case body := <-reported:
		if body["component"] != semanticGatewayComponent || body["held_revision"] != gatewaySemanticRevision ||
			body["applied_revision"] != gatewaySemanticRevision || body["error_code"] != "config_fetch_failed" {
			t.Fatalf("unexpected degraded report: %#v", body)
		}
	case <-time.After(time.Second):
		t.Fatal("missing degraded report")
	}
}

func TestGatewaySemanticRefreshIsSingleflight(t *testing.T) {
	var fetches int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case semanticGatewayConfigPath:
			atomic.AddInt32(&fetches, 1)
			<-release
			_ = json.NewEncoder(w).Encode(signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, true, false))
		case semanticGatewayReportPath:
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	const callers = 12
	var wg sync.WaitGroup
	wg.Add(callers)
	start := make(chan struct{})
	for index := 0; index < callers; index++ {
		go func() {
			defer wg.Done()
			<-start
			if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err != nil {
				t.Errorf("refresh: %v", err)
			}
		}()
	}
	close(start)
	deadline := time.Now().Add(time.Second)
	for atomic.LoadInt32(&fetches) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("fetches=%d want=1", got)
	}
}

func TestGatewaySemanticLastGoodDoesNotExpireBetweenRefreshes(t *testing.T) {
	cache := &runtimeSettingsCache{ttl: time.Nanosecond}
	cache.setSemanticConfig(semanticRuntimeConfig{
		Revision: gatewaySemanticRevision, Enabled: true, InputEnabled: true,
		AgentEnabled: true, SecurityAuditOnly: false,
	})
	time.Sleep(time.Millisecond)
	if _, ok := cache.getSemanticConfig(); !ok {
		t.Fatal("semantic last-good expired")
	}
	if value, ok := cache.getSecurityAuditOnly(); !ok || value {
		t.Fatalf("audit_only last-good expired or changed: value=%v ok=%v", value, ok)
	}
}

func TestNormalizeSemanticRefreshIntervalStaysBelowReportTTL(t *testing.T) {
	if got := normalizeSemanticRefreshInterval(10 * time.Minute); got >= semanticGatewayReportTTL {
		t.Fatalf("interval=%s must stay below TTL=%s", got, semanticGatewayReportTTL)
	}
	if got := normalizeSemanticRefreshInterval(time.Second); got < 5*time.Second {
		t.Fatalf("interval=%s below minimum", got)
	}
}

func TestGatewayDegradedReportDoesNotLeakRawError(t *testing.T) {
	payload := semanticRuntimeReportPayload(semanticRuntimeConfig{Revision: gatewaySemanticRevision}, "config_fetch_failed")
	raw, _ := json.Marshal(payload)
	if strings.Contains(string(raw), "http") || strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "last_error") {
		t.Fatalf("structured report contains raw error material: %s", raw)
	}
}

func TestGatewaySemanticConfigRevisionUsesNodeEffectiveAuditMode(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false))
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	config, err := client.fetchSemanticRuntimeConfig(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	wantRevision := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, true, false)["revision"].(string)
	if !config.SecurityAuditOnly || config.Revision != wantRevision {
		t.Fatalf("node effective config/revision mismatch: got=%+v want_revision=%s", config, wantRevision)
	}
}
