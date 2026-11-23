package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	securityclient "github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
	"github.com/yangjiyj/aiguard/packages/shared-go/filereference"
)

type staticFileReferencePolicy filereference.Policy

func (p staticFileReferencePolicy) Policy(context.Context, string) filereference.Policy {
	return filereference.Policy(p)
}

type fileIDVerdictProbe struct {
	verdictCalls      int
	checkInputCalls   int
	applyContextCalls int
	// exceptionRule 非空时，/apply-context/ 给该 rule_id 的命中标上例外（模拟引擎内容例外）。
	exceptionRule string
	// applyFindings 是最近一次 /apply-context/ 收到的命中数；applyDelay 模拟引擎慢。
	applyFindings int
	applyDelay    time.Duration
	// checkInputBody 非空时作为 /check-input/ 的响应。
	checkInputBody string
}

func newFileIDVerdictChecker(t *testing.T, status string) (*RealSecurityChecker, *fileIDVerdictProbe) {
	t.Helper()
	probe := &fileIDVerdictProbe{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/scan-objects/verdict":
			probe.verdictCalls++
			if got := r.URL.Query().Get("tenant_id"); got != "tenant-a" {
				t.Errorf("tenant_id=%q", got)
			}
			if got := r.URL.Query().Get("subject"); got != "user-a" {
				t.Errorf("subject=%q", got)
			}
			if got := r.URL.Query().Get("provider"); got != "openai" {
				t.Errorf("provider=%q", got)
			}
			if got := r.URL.Query().Get("file_id"); got != "file-blocked" {
				t.Errorf("file_id=%q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			if status == "lookup_error" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
		case "/check-input/":
			probe.checkInputCalls++
			w.Header().Set("Content-Type", "application/json")
			if probe.checkInputBody != "" {
				_, _ = w.Write([]byte(probe.checkInputBody))
				return
			}
			_, _ = w.Write([]byte(`{"action":"allow","findings":[]}`))
		case "/check-output/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"action":"allow","findings":[]}`))
		case "/apply-context/":
			// 复审追加：未经扫描的文件引用命中送引擎过内容例外；这里原样回显，按 exceptionRule 标例外。
			probe.applyContextCalls++
			var req struct {
				RawFindings []map[string]any `json:"raw_findings"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			probe.applyFindings = len(req.RawFindings)
			if probe.applyDelay > 0 {
				time.Sleep(probe.applyDelay)
			}
			for _, finding := range req.RawFindings {
				if probe.exceptionRule != "" && finding["rule_id"] == probe.exceptionRule {
					finding["exception_id"] = "exc-file-ref"
					finding["action"] = "audit"
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"action": "audit", "findings": req.RawFindings})
		default:
			t.Errorf("unexpected security path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return &RealSecurityChecker{client: securityclient.NewClient(server.URL)}, probe
}

func fileIDProtocolRequest(path string, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", "session-a"))
}

func newFileIDChatHandler(caller *MockProviderCaller, checker SecurityChecker, audit *MockAuditWriter, cfg *config.Config) *ChatCompletionsHandler {
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-file-chat", ModelName: "file-chat", ProviderID: "provider-file", ProviderType: "openai",
		ProviderBaseURL: "https://upstream.example/v1", Status: "active",
	}}
	return NewChatCompletionsHandler(cfg, resolver, &MockRateLimitChecker{}, checker, audit, &MockProviderAdapterFactory{MockProviderCaller: caller}, nil, nil)
}

func newFileIDMessagesHandler(caller *MockProviderCaller, checker SecurityChecker, audit *MockAuditWriter, cfg *config.Config) *MessagesHandler {
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-file-messages", ModelName: "file-messages", ProviderID: "provider-file", ProviderType: "openai",
		ProviderBaseURL: "https://upstream.example/v1", Status: "active",
	}}
	return NewMessagesHandler(cfg, resolver, &MockRateLimitChecker{}, checker, audit, &MockProviderAdapterFactory{MockProviderCaller: caller}, nil, nil)
}

func newFileIDResponsesHandler(caller *MockProviderCaller, checker SecurityChecker, audit *MockAuditWriter, cfg *config.Config) *ResponsesHandler {
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-file-responses", ModelName: "file-responses", ProviderID: "provider-file", ProviderType: "openai",
		ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true,
	}}
	return NewResponsesHandler(cfg, resolver, &MockRateLimitChecker{}, checker, audit, &MockProviderAdapterFactory{MockProviderCaller: caller}, nil, nil)
}

func fileIDChatCaller() *MockProviderCaller {
	return &MockProviderCaller{CallResponse: []byte(`{"id":"chat-file","object":"chat.completion","model":"file-chat","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`)}
}

func fileIDMessagesCaller() *MockProviderCaller {
	return &MockProviderCaller{CallResponse: []byte(`{"id":"msg-file","type":"message","role":"assistant","model":"file-messages","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)}
}

func fileIDResponsesCaller() *MockProviderCaller {
	return &MockProviderCaller{CallResponse: []byte(`{"id":"resp-file","object":"response","status":"completed","model":"file-responses","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)}
}

func hasSecurityEvent(audit *MockAuditWriter, action string) bool {
	for _, event := range audit.SecurityEventWrites {
		if event.ActionTaken == action {
			return true
		}
	}
	return false
}

func TestFileIDVerdictStopsAllGatewayProtocols(t *testing.T) {
	type protocolCase struct {
		name  string
		body  []byte
		serve func(*RealSecurityChecker, *MockProviderCaller, *MockAuditWriter) *httptest.ResponseRecorder
	}
	cases := []protocolCase{
		{
			name: "chat_completions",
			body: []byte(`{"model":"file-chat","messages":[{"role":"user","content":[{"type":"input_file","file_id":"file-blocked","filename":"report.pdf"}]}]}`),
			serve: func(checker *RealSecurityChecker, caller *MockProviderCaller, audit *MockAuditWriter) *httptest.ResponseRecorder {
				h := newFileIDChatHandler(caller, checker, audit, &config.Config{})
				w := httptest.NewRecorder()
				h.Handler().ServeHTTP(w, fileIDProtocolRequest("/v1/chat/completions", []byte(`{"model":"file-chat","messages":[{"role":"user","content":[{"type":"input_file","file_id":"file-blocked","filename":"report.pdf"}]}]}`)))
				return w
			},
		},
		{
			name: "messages",
			body: []byte(`{"model":"file-messages","max_tokens":8,"messages":[{"role":"user","content":[{"type":"input_file","file_id":"file-blocked","filename":"report.pdf"}]}]}`),
			serve: func(checker *RealSecurityChecker, caller *MockProviderCaller, audit *MockAuditWriter) *httptest.ResponseRecorder {
				h := newFileIDMessagesHandler(caller, checker, audit, &config.Config{})
				w := httptest.NewRecorder()
				h.Handler().ServeHTTP(w, fileIDProtocolRequest("/v1/messages", []byte(`{"model":"file-messages","max_tokens":8,"messages":[{"role":"user","content":[{"type":"input_file","file_id":"file-blocked","filename":"report.pdf"}]}]}`)))
				return w
			},
		},
		{
			name: "responses",
			body: []byte(`{"model":"file-responses","input":[{"role":"user","content":[{"type":"input_file","file_id":"file-blocked","filename":"report.pdf"}]}]}`),
			serve: func(checker *RealSecurityChecker, caller *MockProviderCaller, audit *MockAuditWriter) *httptest.ResponseRecorder {
				h := newFileIDResponsesHandler(caller, checker, audit, &config.Config{})
				w := httptest.NewRecorder()
				h.Handler().ServeHTTP(w, fileIDProtocolRequest("/v1/responses", []byte(`{"model":"file-responses","input":[{"role":"user","content":[{"type":"input_file","file_id":"file-blocked","filename":"report.pdf"}]}]}`)))
				return w
			},
		},
	}

	// 2.9.22（任务 4.2）：not_found（未经扫描）原先写死阻断，改为按 unverified_file_reference_action，
	// 配成禁止时照拦；检测结论为 block 时不看处置照拦。
	for _, verdictStatus := range []string{"block", "not_found", "pending", "lookup_error"} {
		for _, tc := range cases {
			t.Run(verdictStatus+"/"+tc.name, func(t *testing.T) {
				checker, probe := newFileIDVerdictChecker(t, verdictStatus)
				if verdictStatus != "block" {
					checker.SetFileReferencePolicyReader(staticFileReferencePolicy{Unverified: filereference.Block, LookupFailure: filereference.Block})
				}
				audit := &MockAuditWriter{}
				var caller *MockProviderCaller
				switch tc.name {
				case "chat_completions":
					caller = fileIDChatCaller()
				case "messages":
					caller = fileIDMessagesCaller()
				default:
					caller = fileIDResponsesCaller()
				}

				response := tc.serve(checker, caller, audit)
				if response.Code < http.StatusBadRequest {
					t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
				}
				if len(caller.CallCalls) != 0 {
					t.Fatalf("blocked file_id reached upstream %d time(s)", len(caller.CallCalls))
				}
				if probe.verdictCalls != 1 {
					t.Fatalf("verdict calls=%d want 1", probe.verdictCalls)
				}
				if probe.checkInputCalls != 0 {
					t.Fatalf("blocked reference must not require a fresh input scan, got %d", probe.checkInputCalls)
				}
			})
		}
	}
}

func TestFileIDVerdictAuditOnlyForwardsAllGatewayProtocols(t *testing.T) {
	type protocolCase struct {
		name  string
		serve func(*RealSecurityChecker, *MockProviderCaller, *MockAuditWriter) *httptest.ResponseRecorder
	}
	cases := []protocolCase{
		{
			name: "chat_completions",
			serve: func(checker *RealSecurityChecker, caller *MockProviderCaller, audit *MockAuditWriter) *httptest.ResponseRecorder {
				h := newFileIDChatHandler(caller, checker, audit, &config.Config{SecurityAuditOnly: true})
				w := httptest.NewRecorder()
				h.Handler().ServeHTTP(w, fileIDProtocolRequest("/v1/chat/completions", []byte(`{"model":"file-chat","messages":[{"role":"user","content":[{"type":"input_file","file_id":"file-blocked","filename":"report.pdf"}]}]}`)))
				return w
			},
		},
		{
			name: "messages",
			serve: func(checker *RealSecurityChecker, caller *MockProviderCaller, audit *MockAuditWriter) *httptest.ResponseRecorder {
				h := newFileIDMessagesHandler(caller, checker, audit, &config.Config{SecurityAuditOnly: true})
				w := httptest.NewRecorder()
				h.Handler().ServeHTTP(w, fileIDProtocolRequest("/v1/messages", []byte(`{"model":"file-messages","max_tokens":8,"messages":[{"role":"user","content":[{"type":"input_file","file_id":"file-blocked","filename":"report.pdf"}]}]}`)))
				return w
			},
		},
		{
			name: "responses",
			serve: func(checker *RealSecurityChecker, caller *MockProviderCaller, audit *MockAuditWriter) *httptest.ResponseRecorder {
				h := newFileIDResponsesHandler(caller, checker, audit, &config.Config{SecurityAuditOnly: true})
				w := httptest.NewRecorder()
				h.Handler().ServeHTTP(w, fileIDProtocolRequest("/v1/responses", []byte(`{"model":"file-responses","input":[{"role":"user","content":[{"type":"input_file","file_id":"file-blocked","filename":"report.pdf"}]}]}`)))
				return w
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checker, probe := newFileIDVerdictChecker(t, "block")
			audit := &MockAuditWriter{}
			var caller *MockProviderCaller
			switch tc.name {
			case "chat_completions":
				caller = fileIDChatCaller()
			case "messages":
				caller = fileIDMessagesCaller()
			default:
				caller = fileIDResponsesCaller()
			}

			response := tc.serve(checker, caller, audit)
			if response.Code < http.StatusOK || response.Code >= http.StatusMultipleChoices {
				t.Fatalf("audit-only status=%d body=%s", response.Code, response.Body.String())
			}
			if len(caller.CallCalls) != 1 {
				t.Fatalf("audit-only file_id upstream calls=%d want 1", len(caller.CallCalls))
			}
			if probe.verdictCalls != 1 {
				t.Fatalf("verdict calls=%d want 1", probe.verdictCalls)
			}
			if !hasSecurityEvent(audit, "security_audit_only") {
				t.Fatalf("audit-only file_id verdict was not retained: %+v", audit.SecurityEventWrites)
			}
		})
	}
}

func TestRealSecurityCheckerPreservesFileIDWithBytesAndRegistryContext(t *testing.T) {
	checkInputCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/scan-objects/verdict":
			t.Fatal("new file bytes must be scanned and registered before any verdict lookup")
		case "/check-input/":
			checkInputCalls++
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode check-input: %v", err)
			}
			contextValue, _ := payload["context"].(map[string]interface{})
			if got := contextValue["provider"]; got != "openai" {
				t.Errorf("provider=%#v", got)
			}
			if got := contextValue["user_id"]; got != "user-a" {
				t.Errorf("user_id=%#v", got)
			}
			attachments, _ := contextValue["attachments"].([]interface{})
			if len(attachments) != 1 {
				t.Errorf("attachments=%#v", contextValue["attachments"])
			}
			if len(attachments) == 1 {
				attachment, _ := attachments[0].(map[string]interface{})
				if got := attachment["reference_id"]; got != "file-new" {
					t.Errorf("reference_id=%#v", got)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"action":"allow","findings":[]}`))
		default:
			t.Fatalf("unexpected security path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	h := &ChatCompletionsHandler{
		securityClient: &RealSecurityChecker{client: securityclient.NewClient(server.URL)},
		auditWriter:    &MockAuditWriter{},
	}
	req := &ChatCompletionRequest{Model: "file-chat", Messages: []Message{{
		Role:    "user",
		Content: json.RawMessage(`[{"type":"input_file","file_id":"file-new","filename":"report.pdf","file_data":{"base64":"JVBERi0xLjQ=","mime_type":"application/pdf"}}]`),
	}}}
	_, err := h.applyInputSecurity(context.Background(), &modelrouter.RequestEnvelope{
		RequestID: "req-file-bytes", TenantID: "tenant-a", ProjectID: "project-a", UserID: "user-a", Provider: "openai", Model: "file-chat",
	}, req)
	if err != nil {
		t.Fatalf("input security: %v", err)
	}
	if checkInputCalls != 1 {
		t.Fatalf("check-input calls=%d want 1", checkInputCalls)
	}
}

func TestFileIDVerdictFindingCarriesZeroIndexes(t *testing.T) {
	checker, _ := newFileIDVerdictChecker(t, "block")
	ctx := withAttachments(context.Background(), []map[string]interface{}{{
		"file_id":   "file-blocked",
		"file_name": "report.pdf",
	}})
	envelope := &modelrouter.RequestEnvelope{
		TenantID: "tenant-a",
		UserID:   "user-a",
		Provider: "openai",
	}

	outcome, err := checker.CheckInputDetailed(ctx, envelope, "", 0, "user", "user")
	if err != nil {
		t.Fatalf("check input detailed: %v", err)
	}
	if len(outcome.Findings) != 1 {
		t.Fatalf("findings=%+v", outcome.Findings)
	}
	finding := outcome.Findings[0]
	if finding.MessageIndex == nil || *finding.MessageIndex != 0 ||
		finding.AttachmentIndex == nil || *finding.AttachmentIndex != 0 ||
		finding.MessageRole != "user" {
		t.Fatalf("file-id finding indexes=%+v", finding)
	}
}

// 缺省（告警放行）：未经扫描、检测未完成、查询失败的引用照常转发，另记告警命中，并照常做输入检测。
func TestFileIDReferenceDefaultAlertsAndForwards(t *testing.T) {
	for _, status := range []string{"not_found", "pending", "lookup_error"} {
		t.Run(status, func(t *testing.T) {
			checker, probe := newFileIDVerdictChecker(t, status)
			caller := fileIDChatCaller()
			audit := &MockAuditWriter{}
			h := newFileIDChatHandler(caller, checker, audit, &config.Config{})
			w := httptest.NewRecorder()
			h.Handler().ServeHTTP(w, fileIDProtocolRequest("/v1/chat/completions", []byte(`{"model":"file-chat","messages":[{"role":"user","content":[{"type":"input_file","file_id":"file-blocked","filename":"report.pdf"}]}]}`)))
			if w.Code != http.StatusOK || len(caller.CallCalls) != 1 {
				t.Fatalf("缺省应转发：status=%d calls=%d body=%s", w.Code, len(caller.CallCalls), w.Body.String())
			}
			if probe.verdictCalls != 1 || probe.checkInputCalls != 1 {
				t.Fatalf("verdict=%d checkInput=%d", probe.verdictCalls, probe.checkInputCalls)
			}
		})
	}
}

func TestFileIDReferenceOutcomeFindings(t *testing.T) {
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", Provider: "openai"}
	ctx := withAttachments(context.Background(), []map[string]interface{}{{"file_id": "file-blocked", "file_name": "report.pdf"}})
	for _, tc := range []struct {
		status, action, ruleID, reason string
		policy                         filereference.Policy
	}{
		{"not_found", "audit", "file-id-unverified", "引用的文件没有安全检测记录", filereference.DefaultPolicy()},
		{"pending", "audit", "file-id-unverified", "引用的文件安全检测尚未完成", filereference.DefaultPolicy()},
		{"lookup_error", "audit", "file-id-lookup-failed", "引用文件的安全检测结果查询失败", filereference.DefaultPolicy()},
		{"not_found", "block", "file-id-unverified", "引用的文件没有安全检测记录", filereference.Policy{Unverified: filereference.Block, LookupFailure: filereference.AlertAllow}},
		{"lookup_error", "block", "file-id-lookup-failed", "引用文件的安全检测结果查询失败", filereference.Policy{Unverified: filereference.AlertAllow, LookupFailure: filereference.Block}},
		{"block", "block", "file-id-verdict-block", "引用的文件已被安全检测判定为阻断", filereference.Policy{Unverified: filereference.Allow, LookupFailure: filereference.Allow}},
		{"not_found", "allow", "", "", filereference.Policy{Unverified: filereference.Allow, LookupFailure: filereference.Allow}},
	} {
		t.Run(tc.status+"/"+tc.action, func(t *testing.T) {
			checker, _ := newFileIDVerdictChecker(t, tc.status)
			checker.SetFileReferencePolicyReader(staticFileReferencePolicy(tc.policy))
			outcome, err := checker.CheckInputDetailed(ctx, envelope, "", 0, "user", "user")
			if err != nil {
				t.Fatalf("文件引用处置不应再变成检测失败：%v", err)
			}
			if outcome.Action != tc.action {
				t.Fatalf("action=%s want %s findings=%+v", outcome.Action, tc.action, outcome.Findings)
			}
			if tc.ruleID == "" {
				if len(outcome.Findings) != 0 {
					t.Fatalf("允许时不出命中：%+v", outcome.Findings)
				}
				return
			}
			var hit *SecurityFinding
			for i := range outcome.Findings {
				if outcome.Findings[i].RuleID == tc.ruleID {
					hit = &outcome.Findings[i]
				}
			}
			if hit == nil || hit.EvidenceReason != tc.reason {
				t.Fatalf("命中应写明原因 %q：%+v", tc.reason, outcome.Findings)
			}
			wantAction := "alert"
			if tc.action == "block" {
				wantAction = "block"
			}
			if hit.Action != wantAction {
				t.Fatalf("finding action=%s want %s", hit.Action, wantAction)
			}
		})
	}
}

// 复审追加：unverified_file_reference_action=block 时，未经扫描的文件引用命中先过内容例外
// （rule_ref=file-id-unverified）：命中例外不拦不告警、只记录；没有例外照拦。查询失败不过例外。
func TestFileIDReferenceUnverifiedBlockHonoursContentException(t *testing.T) {
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", ProjectID: "project-a", Provider: "openai"}
	ctx := withAttachments(context.Background(), []map[string]interface{}{{"file_id": "file-blocked", "file_name": "report.pdf"}})
	blockAll := staticFileReferencePolicy(filereference.Policy{Unverified: filereference.Block, LookupFailure: filereference.Block})

	checker, probe := newFileIDVerdictChecker(t, "not_found")
	probe.exceptionRule = "file-id-unverified"
	checker.SetFileReferencePolicyReader(blockAll)
	outcome, err := checker.CheckInputDetailed(ctx, envelope, "", 0, "user", "user")
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Action == "block" || probe.checkInputCalls != 1 || probe.applyContextCalls != 1 {
		t.Fatalf("命中例外应放行并照常做输入检测：action=%s checkInput=%d apply=%d", outcome.Action, probe.checkInputCalls, probe.applyContextCalls)
	}
	if len(outcome.Findings) != 1 || outcome.Findings[0].Action != "audit" || outcome.Findings[0].ExceptionID != "exc-file-ref" {
		t.Fatalf("命中例外只记录（audit、带例外编号）：%+v", outcome.Findings)
	}

	checker, probe = newFileIDVerdictChecker(t, "not_found")
	checker.SetFileReferencePolicyReader(blockAll)
	outcome, _ = checker.CheckInputDetailed(ctx, envelope, "", 0, "user", "user")
	if outcome.Action != "block" || probe.checkInputCalls != 0 {
		t.Fatalf("没有例外照拦：action=%s checkInput=%d", outcome.Action, probe.checkInputCalls)
	}

	checker, probe = newFileIDVerdictChecker(t, "lookup_error")
	probe.exceptionRule = "file-id-lookup-failed"
	checker.SetFileReferencePolicyReader(blockAll)
	outcome, _ = checker.CheckInputDetailed(ctx, envelope, "", 0, "user", "user")
	if outcome.Action != "block" || probe.applyContextCalls != 0 {
		t.Fatalf("查询失败是故障类，不过例外：action=%s apply=%d", outcome.Action, probe.applyContextCalls)
	}
}

// 端到端：命中例外的请求照常转发给上游。
func TestFileIDReferenceExceptionForwardsChat(t *testing.T) {
	checker, probe := newFileIDVerdictChecker(t, "not_found")
	probe.exceptionRule = "file-id-unverified"
	checker.SetFileReferencePolicyReader(staticFileReferencePolicy(filereference.Policy{Unverified: filereference.Block, LookupFailure: filereference.Block}))
	caller := fileIDChatCaller()
	h := newFileIDChatHandler(caller, checker, &MockAuditWriter{}, &config.Config{})
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, fileIDProtocolRequest("/v1/chat/completions", []byte(`{"model":"file-chat","messages":[{"role":"user","content":[{"type":"input_file","file_id":"file-blocked","filename":"report.pdf"}]}]}`)))
	if w.Code != http.StatusOK || len(caller.CallCalls) != 1 {
		t.Fatalf("命中例外应转发：status=%d calls=%d body=%s", w.Code, len(caller.CallCalls), w.Body.String())
	}
}

// 合流前次要项：一次请求里所有该过例外的命中合成一次 /apply-context/。
func TestFileIDReferenceExceptionsUseOneCallPerRequest(t *testing.T) {
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", Provider: "openai"}
	ctx := withAttachments(context.Background(), []map[string]interface{}{
		{"file_id": "file-blocked", "file_name": "a.pdf"}, {"file_id": "file-blocked", "file_name": "b.pdf"},
	})
	checker, probe := newFileIDVerdictChecker(t, "not_found")
	probe.exceptionRule = "file-id-unverified"
	checker.SetFileReferencePolicyReader(staticFileReferencePolicy(filereference.Policy{Unverified: filereference.Block, LookupFailure: filereference.Block}))
	outcome, err := checker.CheckInputDetailed(ctx, envelope, "", 0, "user", "user")
	if err != nil {
		t.Fatal(err)
	}
	if probe.applyContextCalls != 1 || probe.applyFindings != 2 || outcome.Action == "block" || len(outcome.Findings) != 2 {
		t.Fatalf("两个引用应合成一次核对且都放行：calls=%d findings=%d action=%s %+v", probe.applyContextCalls, probe.applyFindings, outcome.Action, outcome.Findings)
	}
	for _, finding := range outcome.Findings {
		if finding.ExceptionID == "" || finding.Action != "audit" {
			t.Fatalf("命中例外只记录：%+v", finding)
		}
	}
}

// 例外核对单独 2 秒超时，超时按文件策略原处置。
func TestFileIDReferenceExceptionTimeoutKeepsDisposition(t *testing.T) {
	saved := fileReferenceExceptionTimeout
	fileReferenceExceptionTimeout = 50 * time.Millisecond
	t.Cleanup(func() { fileReferenceExceptionTimeout = saved })
	if saved != filereference.ExceptionCheckTimeout {
		t.Fatalf("缺省超时应为 %s：%s", filereference.ExceptionCheckTimeout, saved)
	}
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", Provider: "openai"}
	ctx := withAttachments(context.Background(), []map[string]interface{}{{"file_id": "file-blocked", "file_name": "a.pdf"}})
	checker, probe := newFileIDVerdictChecker(t, "not_found")
	probe.exceptionRule = "file-id-unverified"
	probe.applyDelay = 500 * time.Millisecond
	checker.SetFileReferencePolicyReader(staticFileReferencePolicy(filereference.Policy{Unverified: filereference.Block, LookupFailure: filereference.Block}))
	started := time.Now()
	outcome, _ := checker.CheckInputDetailed(ctx, envelope, "", 0, "user", "user")
	if outcome.Action != "block" || time.Since(started) > 400*time.Millisecond {
		t.Fatalf("超时应按原处置拦且不等满引擎：action=%s elapsed=%s", outcome.Action, time.Since(started))
	}
}

// 缺省告警放行：引擎这次已有会提升告警的命中时，压不压文件引用的告警都一样，不调 /apply-context/；
// 没有时才核对。
func TestFileIDReferenceAlertSkipsExceptionCheckWhenEngineFindingsSurface(t *testing.T) {
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", Provider: "openai"}
	ctx := withAttachments(context.Background(), []map[string]interface{}{{"file_id": "file-blocked", "file_name": "a.pdf"}})

	checker, probe := newFileIDVerdictChecker(t, "not_found")
	probe.exceptionRule = "file-id-unverified"
	probe.checkInputBody = `{"action":"audit","findings":[{"type":"pii","category":"phone_cn","severity":"medium","rule_id":"pii_phone","matched_text_preview":"138****","action":"audit"}]}`
	outcome, err := checker.CheckInputDetailed(ctx, envelope, "", 0, "user", "user")
	if err != nil {
		t.Fatal(err)
	}
	if probe.applyContextCalls != 0 || len(outcome.Findings) != 2 {
		t.Fatalf("引擎已有告警命中时不核对：calls=%d findings=%+v", probe.applyContextCalls, outcome.Findings)
	}

	checker, probe = newFileIDVerdictChecker(t, "not_found")
	probe.exceptionRule = "file-id-unverified"
	outcome, _ = checker.CheckInputDetailed(ctx, envelope, "", 0, "user", "user")
	if probe.applyContextCalls != 1 || len(outcome.Findings) != 1 || outcome.Findings[0].ExceptionID == "" {
		t.Fatalf("没有其他告警命中时核对一次并压掉：calls=%d findings=%+v", probe.applyContextCalls, outcome.Findings)
	}
}
