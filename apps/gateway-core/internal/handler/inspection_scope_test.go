package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func inspectionTestClient(policy inspectionscope.Policy) *ToolRiskClient {
	c := &ToolRiskClient{httpClient: &http.Client{Timeout: time.Second}, runtimeCache: &runtimeSettingsCache{ttl: time.Minute}}
	c.runtimeCache.setSemanticConfig(semanticRuntimeConfig{InspectionPolicy: &policy})
	return c
}
func allInspectionTestClient() *ToolRiskClient {
	p := inspectionscope.Default()
	p.InspectBuiltinContext = true
	p.InspectHistory = true
	return inspectionTestClient(p)
}

func TestDefaultInspectionSkipsAllDetectorsForHistoryAndBuiltin(t *testing.T) {
	checker := &MockSecurityChecker{}
	h := &ChatCompletionsHandler{securityClient: checker, auditWriter: &MockAuditWriter{}}
	req := &ChatCompletionRequest{Messages: []Message{
		{Role: "system", Content: jsonQuote("builtin secret fixture")},
		{Role: "user", Content: jsonQuote("old user secret fixture")},
		{Role: "tool", Content: jsonQuote("old tool secret fixture")},
		{Role: "assistant", Content: jsonQuote("old answer")},
		{Role: "user", Content: jsonQuote("<system-reminder>latest credential</system-reminder>")},
		{Role: "tool", Content: jsonQuote("current tool credential")},
		{Role: "future_role", Content: jsonQuote("unknown credential")},
	}}
	_, err := h.applyInputSecurity(context.Background(), &modelrouter.RequestEnvelope{RequestID: "scope"}, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(checker.InputCheckCalls) != 3 {
		t.Fatalf("checked=%+v", checker.InputCheckCalls)
	}
	for i, want := range []int{4, 5, 6} {
		if checker.InputCheckCalls[i].MessageIndex != want {
			t.Fatalf("anchors=%+v", checker.InputCheckCalls)
		}
	}
	plan := gatewayInputInspectionPlan(req.Messages, inspectionscope.Default())
	if plan.targets[4].source != "user" || plan.targets[5].history {
		t.Fatalf("sources=%+v", plan.targets)
	}
	ctx := context.WithValue(context.Background(), inputInspectionPlanKey{}, plan)
	ctx = context.WithValue(ctx, inputInspectionTargetKey{}, plan.targets[5])
	wire := buildInputCheckRequest(ctx, &modelrouter.RequestEnvelope{}, "current tool credential", 5, "tool", "tool_result")
	if wire.Context["user_task"] != messageText(req.Messages[4].Content) || len(wire.Context["judgment_context"].([]map[string]any)) != 4 {
		t.Fatalf("judgment context missing: %+v", wire.Context)
	}
}

func TestGatewayInputInspectionCarriesStructuredToolAction(t *testing.T) {
	req := &ChatCompletionRequest{Messages: []Message{{
		Role:    "user",
		Content: jsonQuote("run the requested operation"),
		ToolCalls: []ToolCall{{
			ID: "call-1", Type: "function",
			Function: ToolCallFunc{
				Name: "shell_exec", Arguments: `{"cmd":"rm -rf /tmp/synthetic-policy-probe"}`,
			},
		}},
	}}}
	plan := gatewayInputInspectionPlan(req.Messages, inspectionscope.Default())
	target, ok := plan.targets[0]
	if !ok {
		t.Fatal("latest user message was not selected for inspection")
	}
	ctx := context.WithValue(context.Background(), inputInspectionPlanKey{}, plan)
	ctx = context.WithValue(ctx, inputInspectionTargetKey{}, target)
	wire := buildInputCheckRequest(
		ctx, &modelrouter.RequestEnvelope{}, messageText(req.Messages[0].Content),
		0, "user", "user",
	)
	action, ok := wire.Context["agent_action"].(map[string]interface{})
	if !ok || action["tool"] != "shell_exec" {
		t.Fatalf("agent_action missing: %+v", wire.Context)
	}
	args, ok := action["args"].(map[string]interface{})
	if !ok || args["cmd"] != "rm -rf /tmp/synthetic-policy-probe" {
		t.Fatalf("agent_action args=%+v", action["args"])
	}
}

func TestAnthropicToolImageKeepsToolProvenance(t *testing.T) {
	var req AnthropicMessagesRequest
	if err := json.Unmarshal([]byte(`{"model":"m","messages":[{"role":"user","content":"old"},{"role":"user","content":[{"type":"text","text":"latest"},{"type":"tool_result","tool_use_id":"call","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGVsbG8="}}]}]}]}`), &req); err != nil {
		t.Fatal(err)
	}
	chat, err := (&MessagesHandler{}).convertToChatRequest(&req)
	if err != nil {
		t.Fatal(err)
	}
	p := inspectionscope.Default()
	p.InspectToolResults = false
	plan := gatewayInputInspectionPlan(chat.Messages, p)
	if len(plan.targets) != 1 {
		t.Fatalf("tool image became user input: %+v %+v", chat.Messages, plan.targets)
	}
	for _, target := range plan.targets {
		if target.messageIndex != 1 || target.source != "user" {
			t.Fatalf("wire anchor lost: %+v", target)
		}
	}
}

func TestOutputScopeIsIndependentFromInputAndSemantic(t *testing.T) {
	p := inspectionscope.Default()
	p.InspectModelOutput = false
	checker := &MockSecurityChecker{}
	h := &ChatCompletionsHandler{securityClient: checker, toolRiskClient: inspectionTestClient(p)}
	if _, _, _, err := h.checkOutputWithStatus(context.Background(), &modelrouter.RequestEnvelope{}, "output", 0, nil); err != nil {
		t.Fatal(err)
	}
	if len(checker.OutputCheckCalls) != 0 {
		t.Fatal("disabled output scanned")
	}
	p.InspectModelOutput = true
	p.InspectUserInput = false
	h.toolRiskClient = inspectionTestClient(p)
	if _, _, _, err := h.checkOutputWithStatus(context.Background(), &modelrouter.RequestEnvelope{}, "output", 0, nil); err != nil {
		t.Fatal(err)
	}
	if len(checker.OutputCheckCalls) != 1 {
		t.Fatal("input or semantic flag hid output rules")
	}
}

func TestNativeMessagesInspectionKeepsOriginalTurnAndWholeTask(t *testing.T) {
	doc, err := parseNativeMessagesDocument([]byte(`{"model":"m","system":"builtin","messages":[{"role":"user","content":"old"},{"role":"user","content":[{"type":"text","text":"first"},{"type":"text","text":"second"},{"type":"tool_result","tool_use_id":"c","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGVsbG8="}}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	p := inspectionscope.Default()
	p.InspectToolResults = false
	plan := gatewayInputInspectionPlan(doc.request.Messages, p)
	if len(plan.targets) != 2 || plan.userTask != "first\nsecond" {
		t.Fatalf("latest blocks lost: %+v", plan)
	}
	for _, target := range plan.targets {
		if target.source != "user" || target.messageIndex != 1 {
			t.Fatalf("wrong origin: %+v", target)
		}
	}
}

func TestReverseInspectionDefaultAndTelemetryKeepSeparateEvidence(t *testing.T) {
	server, received := captureEngine(t, func(p map[string]interface{}) string {
		if p["content"] == "current credential" {
			return `{"action":"block","findings":[{"type":"secret","severity":"high"}],"semantic_status":"incomplete","semantic_reason":"judge_timeout"}`
		}
		return `{"action":"allow","findings":[],"semantic_status":"completed"}`
	})
	defer server.Close()
	h := &ReverseProxyHandler{securityURL: server.URL, client: server.Client()}
	body := []byte(`{"messages":[{"role":"system","content":"builtin"},{"role":"user","content":"old"},{"role":"user","content":"latest task"},{"role":"tool","content":"current credential"}]}`)
	req := httptest.NewRequest("POST", "https://gateway/v1/chat/completions", nil)
	out, err := h.checkRequestSecurityStructured(context.Background(), "r", req, body, "application/json", "api.openai.com", "/v1/chat/completions")
	if err != nil || out.Action != "block" || out.SemanticStatus != "incomplete" || len(received()) != 2 {
		t.Fatalf("risk/status lost: %+v %v", out, err)
	}
	ctx := received()[1]["context"].(map[string]interface{})
	if ctx["message_index"] != float64(3) || ctx["user_task"] != "latest task" || ctx["inspection_is_history"] != false || len(ctx["judgment_context"].([]interface{})) != 2 {
		t.Fatalf("context=%+v", ctx)
	}
	_, err = h.checkRequestSecurityStructured(context.Background(), "telemetry", req, []byte(`{"histogram":"metadata"}`), "application/json", "ab.chatgpt.com", "/v1/rgstr")
	if err != nil || len(received()) != 2 {
		t.Fatal("telemetry became dialogue evidence")
	}
}

// C2: a history segment's fingerprint must be stable when the latest user
// task changes; otherwise every turn re-judges the whole agent history.
func TestHistoryFingerprintScopeIsPerMessageSegment(t *testing.T) {
	env := &modelrouter.RequestEnvelope{TenantID: "t", UserID: "u", ProjectID: "p"}
	policy := inspectionscope.Default()
	history := inputInspectionTarget{
		source: "user_history", role: "user", path: "/messages/2", history: true,
	}
	newSegment := inputInspectionTarget{
		source: "tool_result", role: "tool", path: "/messages/9", history: false,
	}
	makeCtx := func(taskHash, taskText string, target inputInspectionTarget) context.Context {
		plan := inputInspectionPlan{
			policy: policy, userTask: taskText,
			judgment: []map[string]any{{"role": "user", "text": taskText}},
		}
		ctx := context.WithValue(context.Background(), inputInspectionPlanKey{}, plan)
		ctx = context.WithValue(ctx, inputInspectionTargetKey{}, target)
		return withSemanticTaskContext(ctx, semanticTaskContext{
			Enabled: true, Status: "complete", Hash: taskHash, Complete: true, Text: taskText,
		})
	}
	a := inspectionFingerprintScope(makeCtx("task-a", "first task", history), env, history.source, "")
	b := inspectionFingerprintScope(makeCtx("task-b", "second task", history), env, history.source, "")
	if a != b {
		t.Fatal("history segment scope changed with the latest user task: cache cannot be reused")
	}
	c := inspectionFingerprintScope(makeCtx("task-a", "first task", newSegment), env, newSegment.source, "")
	d := inspectionFingerprintScope(makeCtx("task-b", "second task", newSegment), env, newSegment.source, "")
	if c == d {
		t.Fatal("new segment must keep the causal-task-aware scope")
	}
	if a == c {
		t.Fatal("history and new segments must not share a cache scope")
	}
	// A policy change still invalidates history reuse.
	other := inspectionscope.Default()
	other.InspectHistory = true
	plan := inputInspectionPlan{policy: other, userTask: "first task"}
	ctx := context.WithValue(context.Background(), inputInspectionPlanKey{}, plan)
	ctx = context.WithValue(ctx, inputInspectionTargetKey{}, history)
	e := inspectionFingerprintScope(ctx, env, history.source, "")
	if e == a {
		t.Fatal("policy change must invalidate history fingerprint reuse")
	}
}
