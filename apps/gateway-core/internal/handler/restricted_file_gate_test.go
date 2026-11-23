package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// restrictedFileControlPlane 起假控制面：effective-policy 返回带受限文件模式的策略。
// patterns 为空串时不带受限文件字段（功能关闭）。
func restrictedFileControlPlane(t *testing.T, auditOnly bool, action, patternsJSON string, toolLog *atomic.Int32, modes ...string) *httptest.Server {
	t.Helper()
	mode := "audit"
	if len(modes) > 0 {
		mode = modes[0]
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			restricted := ""
			if patternsJSON != "" {
				restricted = fmt.Sprintf(`,"restricted_file_patterns":%s,"restricted_file_action":%q`, patternsJSON, action)
			}
			_, _ = fmt.Fprintf(w, `{"data":{"id":"policy-rf","name":"restricted","policy_version":"v1","mode":%q,"default_action":"allow","fail_policy":"fail_closed","confirm_channel_enabled":true,"rules":[],"exceptions":[]%s}}`, mode, restricted)
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			if toolLog != nil {
				toolLog.Add(1)
			}
			w.WriteHeader(http.StatusCreated)
		case "/admin/v1/internal/agentguard/confirmations":
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected control-plane path: %s", r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
}

func newRestrictedFileToolRiskClient(t *testing.T, auditOnly bool, action, patternsJSON string, toolLog *atomic.Int32, modes ...string) *ToolRiskClient {
	t.Helper()
	cp := restrictedFileControlPlane(t, auditOnly, action, patternsJSON, toolLog, modes...)
	t.Cleanup(cp.Close)
	client := NewToolRiskClient(cp.URL, "internal-secret")
	setToolGuardTestPosture(t, client, auditOnly, false)
	return client
}

func codexExecResponsesUpstream(cmd string) []byte {
	js := fmt.Sprintf(`const r = await tools.exec_command({cmd:%q,workdir:"/w"})`, cmd)
	return []byte(fmt.Sprintf(`{"id":"resp_rf","object":"response","status":"completed","model":"gpt-5.6","output":[{"id":"cti_rf","type":"custom_tool_call","call_id":"c1","name":"exec","input":%q}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`, js))
}

// §3.4 原生 Responses 非流式：防护模式下 Codex exec 读 pdf → 403 + 事件 + evidence 脱敏；
// 审计模式（最高优先级）只记录放行，见 TestNativeResponsesCodexExecRestrictedFileAuditModeRecords。
func TestNativeResponsesCodexExecRestrictedFileBlocked(t *testing.T) {
	for _, auditOnly := range []bool{false} {
		t.Run(fmt.Sprintf("global_audit=%v", auditOnly), func(t *testing.T) {
			var toolLog atomic.Int32
			client := newRestrictedFileToolRiskClient(t, auditOnly, "block", `["*.pdf","*.docx"]`, &toolLog)
			w, audit := runRestrictedNativeResponse(t, client, auditOnly, codexExecResponsesUpstream("pdftotext 合同.pdf -"))
			if w.Code != http.StatusForbidden {
				t.Fatalf("not blocked: %d %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "exec_command") || strings.Contains(w.Body.String(), "pdftotext") {
				t.Fatalf("raw JS leaked: %s", w.Body.String())
			}
			assertRestrictedEvent(t, audit)
			if toolLog.Load() == 0 {
				t.Fatal("missing tool audit log")
			}
		})
	}
}

// 审计模式最高优先级：受限文件配置 block 也只记录，响应原样放行，不写阻断事件。
func TestNativeResponsesCodexExecRestrictedFileAuditModeRecords(t *testing.T) {
	client := newRestrictedFileToolRiskClient(t, true, "block", `["*.pdf","*.docx"]`, nil)
	w, audit := runRestrictedNativeResponse(t, client, true, codexExecResponsesUpstream("pdftotext 合同.pdf -"))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "msg_jjdguard_safety") {
		t.Fatalf("audit mode must forward the call: %d %s", w.Code, w.Body.String())
	}
	for _, ev := range audit.SecurityEventWrites {
		if strings.HasSuffix(ev.ActionTaken, "_blocked") {
			t.Fatalf("audit mode must not write block events: %+v", ev)
		}
	}
}

func runRestrictedNativeResponse(t *testing.T, client *ToolRiskClient, auditOnly bool, upstream []byte) (*httptest.ResponseRecorder, *MockAuditWriter) {
	t.Helper()
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{ID: "m", ProviderID: "p", ModelName: "gpt-5.6-sol", UpstreamModelID: "gpt-5.6", ProviderType: "openai", ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true}}
	audit := &MockAuditWriter{}
	h := NewResponsesHandler(&config.Config{SecurityAuditOnly: auditOnly}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallResponse: upstream}}, client, nil)
	w := httptest.NewRecorder()
	req := nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect"}`))
	req.Header.Set("User-Agent", "codex_exec/0.149.1 (Ubuntu 26.4.0; x86_64) unknown (codex_exec; 0.149.1)")
	h.Handler().ServeHTTP(w, req)
	return w, audit
}

func assertRestrictedEvent(t *testing.T, audit *MockAuditWriter) {
	t.Helper()
	found := false
	for _, ev := range audit.SecurityEventWrites {
		if ev.ActionTaken == "security_blocked" && strings.Contains(ev.Summary, "restricted file pattern") {
			found = true
		}
		encoded := fmt.Sprintf("%+v", ev)
		if strings.Contains(encoded, "destructive_parse_rejected_fail_safe") || strings.Contains(encoded, "command_parse_incomplete") {
			t.Errorf("incorrect fallback event: %s", encoded)
		}
	}
	if !found {
		t.Fatalf("missing security_blocked restricted file pattern event: %+v", audit.SecurityEventWrites)
	}
}

// No-policy control uses the exact same JavaScript envelope under both tenant modes.
func TestNativeResponsesCodexExecNoPolicyPassthrough(t *testing.T) {
	for _, mode := range []string{"audit", "strict"} {
		t.Run(mode, func(t *testing.T) {
			client := newRestrictedFileToolRiskClient(t, false, "block", "", nil, mode)
			upstream := codexExecResponsesUpstream("pwd")
			w, audit := runRestrictedNativeResponse(t, client, false, upstream)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "custom_tool_call") {
				t.Fatalf("not passed: %d %s", w.Code, w.Body.String())
			}
			var want, got map[string]any
			if err := json.Unmarshal(upstream, &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			wantItem := want["output"].([]any)[0].(map[string]any)
			gotItem := got["output"].([]any)[0].(map[string]any)
			if gotItem["input"] != wantItem["input"] || gotItem["type"] != "custom_tool_call" {
				t.Fatalf("protocol changed: %+v", gotItem)
			}
			for _, ev := range audit.SecurityEventWrites {
				if strings.HasSuffix(ev.ActionTaken, "_blocked") {
					t.Fatalf("unexpected block: %+v", ev)
				}
			}
		})
	}
}

// §3.4 老形态 function_call exec_command + shell argv。
func TestChatCompletionsLegacyRestrictedFileBlocked(t *testing.T) {
	cases := []struct{ name, toolName, args string }{
		{"exec_command cmd", "exec_command", `{"cmd":"cat a.docx"}`},
		{"shell argv", "shell", `{"command":["bash","-lc","pdftotext a.pdf -"]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var toolLog atomic.Int32
			client := newRestrictedFileToolRiskClient(t, false, "block", `["*.pdf","*.docx"]`, &toolLog)
			h := &ChatCompletionsHandler{
				cfg:            &config.Config{SecurityAuditOnly: false},
				securityClient: &MockSecurityChecker{},
				auditWriter:    &MockAuditWriter{},
				toolRiskClient: client,
			}
			envelope := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", UserID: "u"}
			call := ToolCall{ID: "c1", Type: "function", Function: ToolCallFunc{Name: c.toolName, Arguments: c.args}}
			resp := destructiveChatResponse(t, "", call)
			audit := &AuditResult{}
			_, err := h.applyAgentGuardToolDecisionResult(context.Background(), envelope, call, nil, audit, 0)
			_ = resp
			if err == nil {
				t.Fatalf("expected block error, got nil (audit=%+v)", audit)
			}
			if audit.OutputAction != "block" {
				t.Fatalf("audit action=%q, want block", audit.OutputAction)
			}
		})
	}
}

// 四象限：{审计,非审计}×{block,record}。执行模式以控制台为准：审计模式最高优先级，
// 审计+block 也只记；防护模式下 block 才拦。
func TestRestrictedFileAuditModeQuadrants(t *testing.T) {
	quadrants := []struct {
		name      string
		auditOnly bool
		action    string
		wantBlock bool
	}{
		{"非审计+block → 拦", false, "block", true},
		{"非审计+record → 放行", false, "record", false},
		{"审计+block → 放行（审计模式最高优先级）", true, "block", false},
		{"审计+record → 放行（只记）", true, "record", false},
	}
	for _, q := range quadrants {
		t.Run(q.name, func(t *testing.T) {
			client := newRestrictedFileToolRiskClient(t, q.auditOnly, q.action, `["*.pdf"]`, nil)
			h := &ChatCompletionsHandler{
				cfg:            &config.Config{SecurityAuditOnly: q.auditOnly},
				securityClient: &MockSecurityChecker{},
				auditWriter:    &MockAuditWriter{},
				toolRiskClient: client,
			}
			envelope := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", UserID: "u"}
			call := ToolCall{ID: "c1", Type: "function", Function: ToolCallFunc{Name: "exec", Arguments: `{"input":"const r = await tools.exec_command({cmd:\"pdftotext a.pdf -\"})"}`}}
			audit := &AuditResult{}
			_, err := h.applyAgentGuardToolDecisionResult(context.Background(), envelope, call, nil, audit, 0)
			if q.wantBlock {
				if err == nil || audit.OutputAction != "block" {
					t.Fatalf("want block, got err=%v action=%q", err, audit.OutputAction)
				}
			} else {
				if err != nil || audit.OutputAction == "block" {
					t.Fatalf("want allow, got err=%v action=%q", err, audit.OutputAction)
				}
			}
		})
	}
}

// §3.4 Claude Code 形态：Messages 路径 Read file_path 命中 → 拦。
func TestClaudeCodeReadRestrictedFileBlocked(t *testing.T) {
	var toolLog atomic.Int32
	client := newRestrictedFileToolRiskClient(t, false, "block", `["*.pdf"]`, &toolLog)
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{SecurityAuditOnly: false},
		securityClient: &MockSecurityChecker{},
		auditWriter:    &MockAuditWriter{},
		toolRiskClient: client,
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", UserID: "u", AgentType: "claude-code"}
	call := ToolCall{ID: "c1", Type: "function", Function: ToolCallFunc{Name: "Read", Arguments: `{"file_path":"/home/u/合同.pdf"}`}}
	audit := &AuditResult{}
	_, err := h.applyAgentGuardToolDecisionResult(context.Background(), envelope, call, nil, audit, 0)
	if err == nil || audit.OutputAction != "block" {
		t.Fatalf("Claude Code Read pdf should block, err=%v action=%q", err, audit.OutputAction)
	}
}

func TestStrictTenantCodexJSExecDestructiveStillBlocked(t *testing.T) {
	client := newRestrictedFileToolRiskClient(t, false, "block", "", nil, "strict")
	w, audit := runRestrictedNativeResponse(t, client, false, codexExecResponsesUpstream("rm -rf /tmp/jjdguard-victim"))
	if !strings.Contains(w.Body.String(), "msg_jjdguard_safety") && w.Code != 403 {
		t.Fatalf("destructive call allowed: %s", w.Body.String())
	}
	joined := fmt.Sprintf("%+v", audit.SecurityEventWrites)
	// action_taken 修复后真实处置动作为 block（事件类型 tool_attempt_blocked 由 finding 承载）。
	if !strings.Contains(joined, "ActionTaken:block") || strings.Contains(joined, "command_parse_incomplete") || strings.Contains(joined, "destructive_parse_rejected_fail_safe") {
		t.Fatalf("wrong destructive evidence: %s", joined)
	}
	h := &ChatCompletionsHandler{cfg: &config.Config{}, securityClient: &MockSecurityChecker{}, auditWriter: &MockAuditWriter{}, toolRiskClient: client}
	call := ToolCall{ID: "c1", OutputItemID: "cti_rf", Type: "function", Function: ToolCallFunc{Name: "exec", Arguments: `{"input":"const r = await tools.exec_command({cmd:\"rm -rf /tmp/jjdguard-victim\"})"}`}}
	decision, _, err := h.analyzeAgentGuardToolCall(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", UserID: "u", AgentType: "openai-codex"}, call, nil)
	if err != nil || decision.RiskCategory != agentguard.DestructiveRiskCategory || decision.RiskSubcategory != "filesystem_delete" || decision.EffectiveDecision != agentguard.DecisionBlock || decision.Reason == "command_parse_incomplete" {
		t.Fatalf("real command must drive destructive decision: %+v err=%v", decision, err)
	}

}

func TestRestrictedFileShapeMatrix(t *testing.T) {
	function := func(name, args string) []byte {
		item := map[string]any{"id": "fc_rf", "type": "function_call", "call_id": "c1", "name": name, "arguments": args}
		b, err := json.Marshal(map[string]any{"id": "resp_rf", "object": "response", "status": "completed", "model": "gpt-5.6", "output": []any{item}, "usage": map[string]int{"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	shapes := []struct {
		name     string
		response []byte
		pdf      bool
	}{
		{"JS_pdf", codexExecResponsesUpstream("pdftotext 合同.pdf -"), true},
		{"function_cmd", function("exec_command", `{"cmd":"pdftotext 合同.pdf -"}`), true},
		{"shell_array", function("shell", `{"command":["bash","-lc","pdftotext a.pdf -"]}`), true},
		{"Read", function("Read", `{"file_path":"/home/u/合同.pdf"}`), true},
		{"JS_pwd", codexExecResponsesUpstream("pwd"), false},
	}
	for _, mode := range []string{"audit", "strict"} {
		for _, global := range []bool{false, true} {
			for _, policy := range []bool{false, true} {
				for _, shape := range shapes {
					t.Run(fmt.Sprintf("%s/global=%v/policy=%v/%s", mode, global, policy, shape.name), func(t *testing.T) {
						patterns := ""
						if policy {
							patterns = `["*.pdf"]`
						}
						client := newRestrictedFileToolRiskClient(t, global, "block", patterns, nil, mode)
						w, audit := runRestrictedNativeResponse(t, client, global, shape.response)
						blocked := w.Code == 403 || strings.Contains(w.Body.String(), "msg_jjdguard_safety")
						// 审计模式（global）最高优先级：受限文件配置 block 也只记录。
						restrictedBlock := policy && shape.pdf && !global
						// The built-in command allowlist is code, not console configuration:
						// an unlisted command (pdftotext) is recorded as "would confirm" and
						// never interrupts the call. Only the configured restricted-file
						// pattern may block here.
						want := restrictedBlock
						t.Logf("mode=%s global_audit=%v policy=%v shape=%s status=%d blocked=%v", mode, global, policy, shape.name, w.Code, blocked)
						if blocked != want || (!blocked && w.Code != 200) {
							t.Fatalf("want blocked=%v body=%s events=%+v", want, w.Body.String(), audit.SecurityEventWrites)
						}
						if restrictedBlock {
							assertRestrictedEvent(t, audit)
						} else {
							for _, ev := range audit.SecurityEventWrites {
								if strings.HasSuffix(ev.ActionTaken, "_blocked") {
									t.Fatalf("false block event: %+v", ev)
								}
							}
						}
					})
				}
			}
		}
	}
}

func TestRestrictedFileRecordAndAlertAllowEvents(t *testing.T) {
	for _, action := range []string{"record", "alert_allow"} {
		t.Run(action, func(t *testing.T) {
			var logs atomic.Int32
			client := newRestrictedFileToolRiskClient(t, true, action, `["*.pdf"]`, &logs, "audit")
			w, audit := runRestrictedNativeResponse(t, client, true, codexExecResponsesUpstream("pdftotext a.pdf -"))
			if w.Code != 200 || !strings.Contains(w.Body.String(), "custom_tool_call") || logs.Load() == 0 {
				t.Fatal("must pass through and log tool")
			}
			count := 0
			for _, ev := range audit.SecurityEventWrites {
				if ev.ActionTaken == "security_audit" && strings.Contains(ev.Summary, "restricted file pattern") {
					count++
				}
			}
			want := 0
			if action == "alert_allow" {
				want = 1
			}
			if count != want {
				t.Fatalf("events=%d want=%d: %+v", count, want, audit.SecurityEventWrites)
			}
		})
	}
}
