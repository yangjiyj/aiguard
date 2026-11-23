package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpconfirmation"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

var mcpExecutionScopeTestSecret = strings.Repeat("mcp-execution-scope-", 3)

func encryptedMCPExecutionRecord(t *testing.T, scopeSecret string, replay mcpconfirmation.ReplayContext) *mcpConfirmationExecutionRecord {
	t.Helper()
	plaintext, err := json.Marshal(replay)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, _, err := secrets.EncryptProviderSecret(string(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(plaintext)
	scopeKey, _ := mcpconfirmation.ScopeKey(scopeSecret, replay)
	requestHash, _ := mcpconfirmation.CanonicalRequestHash(replay)
	principalHash, _ := mcpconfirmation.PrincipalFingerprint(scopeSecret, replay)
	return &mcpConfirmationExecutionRecord{
		ConfirmationID: "agcf-e2e", InvocationID: "mcpinv-e2e", TenantID: replay.TenantID, ConfirmationState: "approved",
		ToolCallID: replay.ToolCallID, ExecutionStatus: "executing", AttemptID: "attempt-e2e",
		ReplayCiphertext: ciphertext, ReplayContextHash: hex.EncodeToString(digest[:]),
		ScopeKey: scopeKey, CanonicalRequestHash: requestHash, PrincipalHash: principalHash,
		ToolID: replay.ToolID, SupplyChainRevision: replay.SupplyChainRevision,
		ApprovedSchemaHash: replay.ApprovedSchemaHash, ServerRouteHash: replay.ServerRouteHash,
	}
}

func assertMCPRequestAuditScope(t *testing.T, db *fakeMCPAuditDB, want string) {
	t.Helper()
	requestWrites := 0
	for index, query := range db.tx.execedSQL {
		if !strings.Contains(query, "INSERT INTO request_logs") {
			continue
		}
		requestWrites++
		if len(db.tx.execedArgs[index]) < 25 || db.tx.execedArgs[index][24] != want {
			t.Fatalf("MCP request audit scope args=%#v, want $25=%q", db.tx.execedArgs[index], want)
		}
	}
	if requestWrites == 0 {
		t.Fatal("expected at least one MCP request audit write")
	}
}

func TestApprovedMCPConfirmationRechecksConfirmAndExecutesRealUpstreamOnce(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-execute-e2e-key")
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		if r.Header.Get("Authorization") != "Bearer upstream-secret" {
			t.Errorf("upstream auth=%q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"sensitive-confirmation-result"}]}}`))
	}))
	defer upstream.Close()

	var auditPayload map[string]any
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/mcp/effective-policy":
			_, _ = w.Write([]byte(`{"matched":true,"policy_id":"policy-confirm","tool_id":"tool-write","mode":"strict","action":"confirm","supply_chain_status":"approved","supply_chain_revision":"revision-a","server_admission_status":"approved","tool_admission_status":"approved","route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_schema_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))
		case "/admin/v1/internal/agentguard/effective-policy":
			_, _ = w.Write([]byte(`{"data":{"id":"destructive-confirm","mode":"strict","default_action":"audit","confirm_channel_enabled":true,"destructive":{"mode":"strict","action":"confirm","scope_type":"tenant"}}}`))
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			if err := json.NewDecoder(r.Body).Decode(&auditPayload); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"tool-log-e2e"}`))
		default:
			t.Errorf("unexpected control-plane path=%s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer controlPlane.Close()

	authCiphertext, _, err := secrets.EncryptProviderSecret("upstream-secret")
	if err != nil {
		t.Fatal(err)
	}
	client := NewToolRiskClient(controlPlane.URL, "internal-secret")
	setToolGuardTestPosture(t, client, false, false)
	proxy := NewMCPProxyHandler(nil, client, false, "customer")
	auditDB := newFakeAuditDB()
	proxy.auditRecorder = &mcpProxyAuditRecorder{db: auditDB}
	client.SetMCPConfirmationScopeSecret(mcpExecutionScopeTestSecret)
	proxy.serverCache.set("tenant-a\x1fserver-a", &mcpServerRoute{
		ID: "server-a", TenantID: "tenant-a", Name: "demo", ServerURL: upstream.URL,
		Status: "active", Transport: "streamable_http", AuthCiphertext: authCiphertext,
		ProtocolVersion: mcpProtocolVersionLatest, AllowPrivateEgress: true, RouteHash: strings.Repeat("a", 64),
	})
	proxy.targetClientResolver = func(_ context.Context, rawURL string, _ bool, _ *http.Client) (*http.Client, *url.URL, error) {
		parsed, parseErr := url.Parse(rawURL)
		return upstream.Client(), parsed, parseErr
	}

	requestBody := json.RawMessage(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"write","arguments":{"path":"/tmp/safe"}}}`)
	record := encryptedMCPExecutionRecord(t, mcpExecutionScopeTestSecret, mcpconfirmation.ReplayContext{
		Version: mcpconfirmation.ReplayContextVersion, TenantID: "tenant-a",
		ProjectID: "project-a", UserID: "user-a", ClientID: "key-a", KeyPrefix: "sk-a",
		EnvironmentScope: "home",
		AgentType:        "claude-code", AgentSessionID: "agent-session-a", TraceID: "trace-a", OperationID: "op-original",
		ServerID: "server-a", ToolName: "write", ToolCallID: "number:9",
		ProtocolVersion: mcpProtocolVersionLatest, ToolID: "tool-write",
		SupplyChainRevision: "revision-a", ApprovedSchemaHash: strings.Repeat("b", 64),
		ServerRouteHash: strings.Repeat("a", 64), RequestBody: requestBody,
	})
	completion := proxy.executeApprovedMCPConfirmation(context.Background(), record)
	if completion.Status != "executed" || completion.ErrorCode != "" || completion.Summary["result_observed"] != true || upstreamHits.Load() != 1 {
		t.Fatalf("completion=%+v hits=%d", completion, upstreamHits.Load())
	}
	summaryJSON, err := json.Marshal(completion.Summary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(summaryJSON), "sensitive-confirmation-result") || completion.Summary["result_excerpt"] == nil ||
		completion.ResultHash == "" || completion.ResultPlaintextBytes == 0 || completion.ResultCiphertext == "" {
		t.Fatalf("ordinary confirmation lost compatible excerpt or encrypted metadata: completion=%+v", completion)
	}
	if auditPayload["event_kind"] != "execution_forwarded" || auditPayload["execution_observed"] != true ||
		auditPayload["result_observed"] != true || auditPayload["mcp_server_id"] != "server-a" ||
		auditPayload["operation_id"] != "op-original" || auditPayload["trace_id"] != "trace-a" {
		t.Fatalf("audit=%v", auditPayload)
	}
	if params, _ := json.Marshal(auditPayload["parameters"]); strings.Contains(string(params), "upstream-secret") {
		t.Fatalf("audit leaked upstream credential: %s", params)
	}
	assertMCPRequestAuditScope(t, auditDB, "customer")
}

func TestApprovedMCPConfirmationDestructiveMCPConfirmExecutesOnce(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-destructive-confirm-execute-key")
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"destructive-confirm-result"}]}}`))
	}))
	defer upstream.Close()

	var auditPayload map[string]any
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/mcp/effective-policy":
			_, _ = w.Write([]byte(`{"matched":true,"policy_id":"policy-confirm","tool_id":"tool-danger","mode":"strict","action":"confirm","supply_chain_status":"approved","supply_chain_revision":"revision-a","server_admission_status":"approved","tool_admission_status":"approved","route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_schema_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))
		case "/admin/v1/internal/agentguard/effective-policy":
			_, _ = w.Write([]byte(`{"data":{"id":"destructive-confirm","mode":"strict","default_action":"audit","confirm_channel_enabled":true,"config_source":"application_policy","protocol":"mcp","discardable_paths":[],"notify_channel_ids":[],"destructive":{"mode":"strict","action":"confirm","scope_type":"application","scope_ref":"project-a","protocol":"mcp"}}}`))
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			if err := json.NewDecoder(r.Body).Decode(&auditPayload); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"tool-log-destructive-confirm"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer controlPlane.Close()

	toolRiskClient := NewToolRiskClient(controlPlane.URL, "internal")
	setToolGuardTestPosture(t, toolRiskClient, false, false)
	toolRiskClient.SetMCPConfirmationScopeSecret(mcpExecutionScopeTestSecret)
	proxy := NewMCPProxyHandler(nil, toolRiskClient, false)
	proxy.serverCache.set("tenant-a\x1fserver-a", &mcpServerRoute{
		ID: "server-a", TenantID: "tenant-a", Name: "demo", ServerURL: upstream.URL,
		Status: "active", Transport: "streamable_http", ProtocolVersion: mcpProtocolVersionLatest,
		AllowPrivateEgress: true, RouteHash: strings.Repeat("a", 64),
	})
	proxy.targetClientResolver = func(_ context.Context, rawURL string, _ bool, _ *http.Client) (*http.Client, *url.URL, error) {
		parsed, parseErr := url.Parse(rawURL)
		return upstream.Client(), parsed, parseErr
	}

	body := json.RawMessage(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"dangerous_exec","arguments":{"cmd":"rm -rf /srv/data/live-proof"}}}`)
	record := encryptedMCPExecutionRecord(t, mcpExecutionScopeTestSecret, mcpconfirmation.ReplayContext{
		Version: mcpconfirmation.ReplayContextVersion, TenantID: "tenant-a",
		ProjectID: "project-a", OperationID: "op-destructive-confirm", TraceID: "trace-destructive-confirm",
		ServerID: "server-a", ToolName: "dangerous_exec", ToolCallID: "number:9",
		ProtocolVersion: mcpProtocolVersionLatest, ToolID: "tool-danger",
		SupplyChainRevision: "revision-a", ApprovedSchemaHash: strings.Repeat("b", 64),
		ServerRouteHash: strings.Repeat("a", 64), RequestBody: body,
	})
	completion := proxy.executeApprovedMCPConfirmation(context.Background(), record)
	if completion.Status != "executed" || completion.ErrorCode != "" || completion.Summary["result_observed"] != true || upstreamHits.Load() != 1 {
		t.Fatalf("completion=%+v hits=%d", completion, upstreamHits.Load())
	}
	if auditPayload["event_kind"] != "execution_forwarded" || auditPayload["execution_observed"] != true || auditPayload["result_observed"] != true || auditPayload["effective_reason"] != "human_confirmation_approved_once" {
		t.Fatalf("audit=%v", auditPayload)
	}
	if auditPayload["risk_subcategory"] != "filesystem_delete" || auditPayload["operation_id"] != "op-destructive-confirm" || auditPayload["trace_id"] != "trace-destructive-confirm" {
		t.Fatalf("destructive audit facts lost: %v", auditPayload)
	}
}

func TestApprovedMCPConfirmationCurrentBlockAndDangerousCommandCannotBeOverridden(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-execute-block-key")
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	for _, test := range []struct {
		name           string
		policyResponse string
		arguments      string
		wantError      string
	}{
		{name: "current block policy", policyResponse: `{"matched":true,"policy_id":"current","tool_id":"tool-write","mode":"strict","action":"block","supply_chain_status":"approved","supply_chain_revision":"revision-a","server_admission_status":"approved","tool_admission_status":"approved","route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_schema_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`, arguments: `{"path":"/tmp/safe"}`, wantError: "current_policy_blocked"},
		{name: "dangerous command", policyResponse: `{"matched":true,"policy_id":"current","tool_id":"tool-write","mode":"strict","action":"confirm","supply_chain_status":"approved","supply_chain_revision":"revision-a","server_admission_status":"approved","tool_admission_status":"approved","route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_schema_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`, arguments: `{"command":"rm -rf /"}`, wantError: "current_policy_blocked"},
		{name: "supply chain floor", policyResponse: `{"matched":true,"policy_id":"floor","tool_id":"tool-write","mode":"strict","action":"block","supply_chain_status":"quarantined","supply_chain_reasons":["route_binding_changed"],"supply_chain_revision":"revision-a","structural_block":true,"server_admission_status":"approved","tool_admission_status":"approved","route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_schema_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`, arguments: `{"path":"/tmp/safe"}`, wantError: "approval_context_drift"},
		{name: "policy runtime unavailable", arguments: `{"path":"/tmp/safe"}`, wantError: "policy_runtime_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var upstreamHits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":9,"result":{}}`))
			}))
			defer upstream.Close()
			var auditPayload map[string]any
			controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/admin/v1/internal/mcp/effective-policy" {
					if test.policyResponse == "" {
						http.Error(w, "runtime unavailable", http.StatusServiceUnavailable)
						return
					}
					_, _ = w.Write([]byte(test.policyResponse))
					return
				}
				if r.URL.Path == "/admin/v1/internal/agentguard/effective-policy" {
					// 2.9.22：路由变化与重放时环境变化默认告警放行；“supply chain floor”用例要验证的是
					// 配成阻断时照拦，所以把 mcp.drift、mcp.replay_changed 配成阻断（对另两个用例无影响）。
					_, _ = w.Write([]byte(`{"data":{"id":"destructive-confirm","mode":"strict","default_action":"audit","confirm_channel_enabled":true,"destructive":{"mode":"strict","action":"confirm","scope_type":"tenant"},"protections":{"mcp.drift":{"action":"block"},"mcp.replay_changed":{"action":"block"}}}}`))
					return
				}
				if r.URL.Path == "/admin/v1/internal/tools/logs" {
					if err := json.NewDecoder(r.Body).Decode(&auditPayload); err != nil {
						t.Error(err)
					}
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"id":"tool-log-block"}`))
					return
				}
				http.NotFound(w, r)
			}))
			defer controlPlane.Close()
			toolRiskClient := NewToolRiskClient(controlPlane.URL, "internal")
			toolRiskClient.SetMCPConfirmationScopeSecret(mcpExecutionScopeTestSecret)
			toolRiskClient.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
				Revision: strings.Repeat("0", 32), SecurityAuditOnly: false, SecurityExecutionModeManaged: true,
			})
			proxy := NewMCPProxyHandler(nil, toolRiskClient, false, "customer")
			auditDB := newFakeAuditDB()
			proxy.auditRecorder = &mcpProxyAuditRecorder{db: auditDB}
			proxy.serverCache.set("tenant-a\x1fserver-a", &mcpServerRoute{
				ID: "server-a", TenantID: "tenant-a", Name: "demo", ServerURL: upstream.URL,
				Status: "active", Transport: "streamable_http", ProtocolVersion: mcpProtocolVersionLatest, RouteHash: strings.Repeat("a", 64),
			})
			proxy.targetClientResolver = func(_ context.Context, rawURL string, _ bool, _ *http.Client) (*http.Client, *url.URL, error) {
				parsed, parseErr := url.Parse(rawURL)
				return upstream.Client(), parsed, parseErr
			}
			body := json.RawMessage(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"write","arguments":` + test.arguments + `}}`)
			record := encryptedMCPExecutionRecord(t, mcpExecutionScopeTestSecret, mcpconfirmation.ReplayContext{
				Version: mcpconfirmation.ReplayContextVersion, TenantID: "tenant-a",
				EnvironmentScope: "home",
				OperationID:      "op-original-block", TraceID: "trace-original-block",
				ServerID: "server-a", ToolName: "write", ToolCallID: "number:9",
				ProtocolVersion: mcpProtocolVersionLatest, ToolID: "tool-write",
				SupplyChainRevision: "revision-a", ApprovedSchemaHash: strings.Repeat("b", 64),
				ServerRouteHash: strings.Repeat("a", 64), RequestBody: body,
			})
			completion := proxy.executeApprovedMCPConfirmation(context.Background(), record)
			if completion.Status != "failed" || completion.ErrorCode != test.wantError || completion.EvidenceStatus != "complete" || completion.ToolLogID == "" || upstreamHits.Load() != 0 {
				t.Fatalf("completion=%+v hits=%d", completion, upstreamHits.Load())
			}
			if auditPayload["operation_id"] != "op-original-block" || auditPayload["trace_id"] != "trace-original-block" || auditPayload["operation_id"] == auditPayload["trace_id"] {
				t.Fatalf("audit correlation lost: %v", auditPayload)
			}
			if len(auditDB.tx.execedSQL) != 2 ||
				!strings.Contains(auditDB.tx.execedSQL[1], "INSERT INTO security_events") {
				t.Fatalf("hard block did not persist request+security evidence: %#v", auditDB.tx.execedSQL)
			}
			assertMCPRequestAuditScope(t, auditDB, "customer")
		})
	}
}
func TestApprovedMCPConfirmationAuditFailurePreservesExecutionTruth(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-audit-gate-key")
	for _, test := range []struct {
		name             string
		failAuditCall    int32
		wantStatus       string
		wantError        string
		wantAuditError   string
		wantUpstreamHits int32
	}{
		{name: "preflight evidence failure prevents forwarding", failAuditCall: 1, wantStatus: "failed", wantError: "preflight_audit_failed", wantAuditError: "preflight_audit_failed", wantUpstreamHits: 0},
		{name: "terminal evidence failure keeps executed truth", failAuditCall: 2, wantStatus: "executed", wantAuditError: "terminal_audit_failed", wantUpstreamHits: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var upstreamHits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":9,"result":{"ok":true}}`))
			}))
			defer upstream.Close()

			var auditCalls atomic.Int32
			controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/admin/v1/internal/mcp/effective-policy":
					_, _ = w.Write([]byte(`{"matched":true,"policy_id":"policy-confirm","tool_id":"tool-write","mode":"strict","action":"confirm","supply_chain_status":"approved","supply_chain_revision":"revision-a","server_admission_status":"approved","tool_admission_status":"approved","route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_schema_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))
				case "/admin/v1/internal/tools/logs":
					call := auditCalls.Add(1)
					if call == test.failAuditCall {
						http.Error(w, "injected audit failure", http.StatusServiceUnavailable)
						return
					}
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"id":"tool-log-ok"}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer controlPlane.Close()

			toolRiskClient := NewToolRiskClient(controlPlane.URL, "internal")
			toolRiskClient.SetMCPConfirmationScopeSecret(mcpExecutionScopeTestSecret)
			proxy := NewMCPProxyHandler(nil, toolRiskClient, false)
			proxy.serverCache.set("tenant-a\x1fserver-a", &mcpServerRoute{
				ID: "server-a", TenantID: "tenant-a", Name: "demo", ServerURL: upstream.URL,
				Status: "active", Transport: "streamable_http", ProtocolVersion: mcpProtocolVersionLatest,
				AllowPrivateEgress: true, RouteHash: strings.Repeat("a", 64),
			})
			proxy.targetClientResolver = func(_ context.Context, rawURL string, _ bool, _ *http.Client) (*http.Client, *url.URL, error) {
				parsed, parseErr := url.Parse(rawURL)
				return upstream.Client(), parsed, parseErr
			}
			body := json.RawMessage(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"write","arguments":{"path":"/tmp/safe"}}}`)
			record := encryptedMCPExecutionRecord(t, mcpExecutionScopeTestSecret, mcpconfirmation.ReplayContext{
				Version: mcpconfirmation.ReplayContextVersion, TenantID: "tenant-a",
				ServerID: "server-a", ToolName: "write", ToolCallID: "number:9",
				ProtocolVersion: mcpProtocolVersionLatest, ToolID: "tool-write",
				SupplyChainRevision: "revision-a", ApprovedSchemaHash: strings.Repeat("b", 64),
				ServerRouteHash: strings.Repeat("a", 64), RequestBody: body,
			})
			completion := proxy.executeApprovedMCPConfirmation(context.Background(), record)
			if completion.Status != test.wantStatus || completion.ErrorCode != test.wantError ||
				completion.EvidenceStatus != "failed" || completion.AuditErrorCode != test.wantAuditError ||
				upstreamHits.Load() != test.wantUpstreamHits {
				t.Fatalf("completion=%+v hits=%d audit_calls=%d", completion, upstreamHits.Load(), auditCalls.Load())
			}
			if test.wantStatus == "executed" && completion.ResultCiphertext == "" {
				t.Fatal("executed result must remain retrievable even when terminal evidence write fails")
			}
		})
	}
}
