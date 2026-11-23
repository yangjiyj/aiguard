package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

func TestRealSecurityChecker_CheckInputDetailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{
			"request_id":"r1","action":"audit",
			"findings":[{"rule_id":"pi-1","severity":"high","type":"prompt_injection"}],
			"engine_build":"b1","rule_pack_version":"rp1",
			"semantic_status":"incomplete","semantic_reason":"breaker_open",
			"raw_findings":[{"rule_id":"pi-1","severity":"critical"}],"latency_ms":1}`)
	}))
	defer srv.Close()

	chk := NewRealSecurityChecker(&config.Config{SecurityEngineURL: srv.URL})
	out, err := chk.CheckInputDetailed(context.Background(),
		&modelrouter.RequestEnvelope{RequestID: "r1", TenantID: "t1"}, "content", 0, "system", "system_prompt")
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "audit" || len(out.Findings) != 1 || out.Findings[0].RuleID != "pi-1" {
		t.Fatalf("outcome = %+v", out)
	}
	if out.EngineBuild != "b1" || out.RulePackVersion != "rp1" || len(out.RawFindings) == 0 {
		t.Fatalf("版本/原始 findings 未透传: %+v", out)
	}
	if out.SemanticStatus != "incomplete" || out.SemanticReason != "breaker_open" {
		t.Fatalf("语义裁判状态未透传: %+v", out)
	}
	// CheckInput 四元组包装与 detailed 同源（P1-A 起接口带 contentSource 第 6 参）
	action, _, findings, err := chk.CheckInput(context.Background(),
		&modelrouter.RequestEnvelope{RequestID: "r1", TenantID: "t1"}, "content", 0, "system", "system_prompt")
	if err != nil || action != "audit" || len(findings) != 1 {
		t.Fatalf("CheckInput 包装失效: %s %v %v", action, findings, err)
	}
}

func TestAnnotateSemanticStatus(t *testing.T) {
	matchedSummary := map[string]interface{}{"summary": "x"}
	annotateSemanticStatus(context.Background(), matchedSummary)
	if _, ok := matchedSummary["semantic_status"]; ok {
		t.Fatal("无状态上下文时不得伪造语义完成度")
	}

	ctx := withSemanticStatus(context.Background(), "incomplete", "breaker_open")
	annotateSemanticStatus(ctx, matchedSummary)
	if matchedSummary["semantic_status"] != "incomplete" {
		t.Fatalf("semantic_status missing: %+v", matchedSummary)
	}
	if matchedSummary["semantic_reason"] != "breaker_open" {
		t.Fatalf("semantic_reason missing: %+v", matchedSummary)
	}
}

func TestRealSecurityChecker_ApplyContext(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apply-context/" {
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &gotBody)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"action":"audit","findings":[{"rule_id":"pi-1","severity":"high"}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	chk := NewRealSecurityChecker(&config.Config{SecurityEngineURL: srv.URL})
	env := &modelrouter.RequestEnvelope{
		RequestID: "r2", TenantID: "t1", ProjectID: "p1", UserID: "u1", AgentType: "claude-code",
	}
	action, findings, err := chk.ApplyContext(context.Background(), env,
		json.RawMessage(`[{"rule_id":"pi-1"}]`), "system_prompt")
	if err != nil || action != "audit" || len(findings) != 1 {
		t.Fatalf("action=%s findings=%v err=%v", action, findings, err)
	}
	ctxMap := gotBody["context"].(map[string]any)
	if ctxMap["agent_type"] != "claude-code" || ctxMap["project_id"] != "p1" ||
		ctxMap["user_id"] != "u1" || ctxMap["content_source"] != "system_prompt" ||
		ctxMap["access_type"] != "api" {
		t.Fatalf("重放上下文透传不全: %v", ctxMap)
	}
}

func TestAnnotateFingerprintReuse(t *testing.T) {
	ms := map[string]interface{}{"summary": "x"}
	annotateFingerprintReuse(context.Background(), ms)
	if _, ok := ms["scan_mode"]; ok {
		t.Fatal("非重放 ctx 不得标注")
	}
	ctx := withFingerprintReuse(context.Background(), "req-1")
	annotateFingerprintReuse(ctx, ms)
	if ms["scan_mode"] != "fingerprint_reuse" || ms["first_seen_request_id"] != "req-1" {
		t.Fatalf("标注缺失: %+v", ms)
	}
}

// 400 条历史消息（其中只有一条非空 system prompt）重复发送 10 次时，只保留
// 首条完整 security_event；后续请求写轻量 occurrence，既不复制 findings，
// 也不丢发生次数。空历史消息用于固定真实请求尺寸，不应制造额外检测信号。
func TestFingerprintCache_400MessageHistoryRepeated10Times(t *testing.T) {
	chk := &MockSecurityChecker{
		InputAction:          "audit",
		InputFindings:        []SecurityFinding{{Type: "prompt_injection", RuleID: "pi-1", Severity: "high", MatchedLocation: "input"}},
		InputRawFindings:     json.RawMessage(`[{"type":"prompt_injection","rule_id":"pi-1","severity":"high"}]`),
		InputRulePackVersion: "rp-1",
		InputEngineBuild:     "build-1",
		ApplyAction:          "audit",
		ApplyFindings:        []SecurityFinding{{Type: "prompt_injection", RuleID: "pi-1", Severity: "high", MatchedLocation: "input"}},
	}
	aw := &MockAuditWriter{}
	h := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(),
		securityClient: chk,
		auditWriter:    aw,
		cfg:            &config.Config{},
		fingerprints:   scanfp.NewStore(nil, 16), // 纯 LRU，无 DB
	}

	systemPrompt := "You are Claude Code, Anthropic's official CLI."
	messages := make([]Message, 400)
	messages[0] = Message{Role: "system", Content: jsonQuote(systemPrompt)}
	for i := 1; i < len(messages); i++ {
		messages[i] = Message{Role: "assistant", Content: jsonQuote("")}
	}
	for round := 1; round <= 10; round++ {
		req := &ChatCompletionRequest{Messages: append([]Message(nil), messages...)}
		envelope := &modelrouter.RequestEnvelope{RequestID: fmt.Sprintf("req-%d", round), TenantID: "t1"}
		if _, err := h.applyInputSecurity(context.Background(), envelope, req); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}

	if got := len(chk.InputCheckCalls); got != 1 {
		t.Fatalf("引擎应只被调用一次(首见), got %d", got)
	}
	if got := len(chk.ApplyCalls); got != 9 {
		t.Fatalf("后九轮应走 /apply-context/ 重放, got %d", got)
	}
	if chk.ApplyCalls[0].ContentSource != "system_prompt" {
		t.Fatalf("重放上下文 content_source 应为 system_prompt, got %q", chk.ApplyCalls[0].ContentSource)
	}
	if got := len(aw.SecurityEventWrites); got != 1 {
		t.Fatalf("重复上下文只应保留首条完整 security_event, got %d", got)
	}
	if aw.SecurityEventWrites[0].ScanMode != "" {
		t.Fatal("首轮是真实检测，不得标 fingerprint_reuse")
	}
	if aw.SecurityEventWrites[0].EventID == "" {
		t.Fatal("首条完整事件必须生成稳定 event_id，供 occurrence 引用")
	}
	if got := len(aw.SecurityOccurrenceWrites); got != 9 {
		t.Fatalf("后九轮各写一条轻量 occurrence, got %d", got)
	}
	for i, occurrence := range aw.SecurityOccurrenceWrites {
		if occurrence.RepresentativeEventID != aw.SecurityEventWrites[0].EventID {
			t.Fatalf("occurrence %d 未引用首事件: %+v", i+2, occurrence)
		}
		if occurrence.RequestID != fmt.Sprintf("req-%d", i+2) {
			t.Fatalf("occurrence %d request_id 错误: %+v", i+2, occurrence)
		}
	}
}

func TestFingerprintCache_ContextChangesDoNotFoldSecurityEvents(t *testing.T) {
	t.Run("content source changes", func(t *testing.T) {
		chk := &MockSecurityChecker{
			InputAction:          "audit",
			InputFindings:        []SecurityFinding{{Type: "prompt_injection", RuleID: "pi-1", Severity: "high"}},
			InputRawFindings:     json.RawMessage(`[{"type":"prompt_injection","rule_id":"pi-1","severity":"high"}]`),
			InputRulePackVersion: "rp-1",
			InputEngineBuild:     "build-1",
			ApplyAction:          "audit",
			ApplyFindings:        []SecurityFinding{{Type: "prompt_injection", RuleID: "pi-1", Severity: "high"}},
		}
		aw := &MockAuditWriter{}
		h := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(),
			securityClient: chk, auditWriter: aw, cfg: &config.Config{},
			fingerprints: scanfp.NewStore(nil, 16),
		}
		for round, role := range []string{"system", "user"} {
			req := &ChatCompletionRequest{Messages: []Message{{Role: role, Content: jsonQuote("same text")}}}
			env := &modelrouter.RequestEnvelope{RequestID: fmt.Sprintf("source-%d", round), TenantID: "t1"}
			if _, err := h.applyInputSecurity(context.Background(), env, req); err != nil {
				t.Fatal(err)
			}
		}
		if len(aw.SecurityEventWrites) != 2 || len(aw.SecurityOccurrenceWrites) != 0 {
			t.Fatalf("source change must keep full events: events=%d occurrences=%d", len(aw.SecurityEventWrites), len(aw.SecurityOccurrenceWrites))
		}
	})

	t.Run("policy action changes", func(t *testing.T) {
		chk := &MockSecurityChecker{
			InputAction:          "audit",
			InputFindings:        []SecurityFinding{{Type: "prompt_injection", RuleID: "pi-1", Severity: "high"}},
			InputRawFindings:     json.RawMessage(`[{"type":"prompt_injection","rule_id":"pi-1","severity":"high"}]`),
			InputRulePackVersion: "rp-1",
			InputEngineBuild:     "build-1",
			ApplyAction:          "block",
			ApplyFindings:        []SecurityFinding{{Type: "prompt_injection", RuleID: "pi-1", Severity: "high"}},
		}
		aw := &MockAuditWriter{}
		h := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(),
			securityClient: chk, auditWriter: aw, cfg: &config.Config{},
			fingerprints: scanfp.NewStore(nil, 16),
		}
		for round := 1; round <= 2; round++ {
			req := &ChatCompletionRequest{Messages: []Message{{Role: "system", Content: jsonQuote("same prompt")}}}
			env := &modelrouter.RequestEnvelope{RequestID: fmt.Sprintf("action-%d", round), TenantID: "t1"}
			_, _ = h.applyInputSecurity(context.Background(), env, req)
		}
		if len(aw.SecurityEventWrites) != 2 || len(aw.SecurityOccurrenceWrites) != 0 {
			t.Fatalf("action change must keep full events: events=%d occurrences=%d", len(aw.SecurityEventWrites), len(aw.SecurityOccurrenceWrites))
		}
	})
}

func TestFingerprintCache_CompletedSemanticStatusWithoutSemanticFindingStillFolds(t *testing.T) {
	chk := &MockSecurityChecker{
		InputAction:                 "audit",
		InputFindings:               []SecurityFinding{{Type: "prompt_injection", RuleID: "pi-1", Severity: "high"}},
		InputRawFindings:            json.RawMessage(`[{"type":"prompt_injection","rule_id":"pi-1","severity":"high"}]`),
		InputRulePackVersion:        "rp-1",
		InputEngineBuild:            "build-1",
		InputSemanticConfigRevision: "sem-1",
		InputSemanticStatus:         "completed",
		ApplyAction:                 "audit",
		ApplyFindings:               []SecurityFinding{{Type: "prompt_injection", RuleID: "pi-1", Severity: "high"}},
	}
	aw := &MockAuditWriter{}
	h := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(),
		securityClient: chk, auditWriter: aw, cfg: &config.Config{},
		fingerprints: scanfp.NewStore(nil, 16),
	}
	for round := 1; round <= 2; round++ {
		req := &ChatCompletionRequest{Messages: []Message{{Role: "system", Content: jsonQuote("same rule finding")}}}
		env := &modelrouter.RequestEnvelope{RequestID: fmt.Sprintf("completed-%d", round), TenantID: "t1"}
		if _, err := h.applyInputSecurity(context.Background(), env, req); err != nil {
			t.Fatal(err)
		}
	}
	if len(aw.SecurityEventWrites) != 1 || len(aw.SecurityOccurrenceWrites) != 1 {
		t.Fatalf("completed without semantic finding should fold: events=%d occurrences=%d", len(aw.SecurityEventWrites), len(aw.SecurityOccurrenceWrites))
	}
}

// 契约 9：首见无 findings 的重复内容静默跳过（不写事件，与现状一致）。
func TestFingerprintCache_NoFindingsRepeatSilentlySkipped(t *testing.T) {
	chk := &MockSecurityChecker{
		InputAction:          "allow",
		InputRawFindings:     json.RawMessage(`[]`),
		InputRulePackVersion: "rp-1",
		InputEngineBuild:     "build-1",
	}
	aw := &MockAuditWriter{}
	h := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(),
		securityClient: chk, auditWriter: aw,
		cfg: &config.Config{}, fingerprints: scanfp.NewStore(nil, 16),
	}
	for round := 1; round <= 3; round++ {
		req := &ChatCompletionRequest{Messages: []Message{{Role: "system", Content: jsonQuote("clean prompt")}}}
		env := &modelrouter.RequestEnvelope{RequestID: fmt.Sprintf("r%d", round), TenantID: "t1"}
		if _, err := h.applyInputSecurity(context.Background(), env, req); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(chk.InputCheckCalls); got != 1 {
		t.Fatalf("引擎应只调一次, got %d", got)
	}
	if got := len(chk.ApplyCalls); got != 0 {
		t.Fatalf("无 findings 重复不走重放, got %d", got)
	}
	if got := len(aw.SecurityEventWrites); got != 0 {
		t.Fatalf("无 findings 不写事件（与现状一致）, got %d", got)
	}
}

// 契约 9：重放后 action=mask → 回退全量 check（重放无法产出 masked_content）。
func TestFingerprintCache_ReplayMaskFallsBackToFullCheck(t *testing.T) {
	chk := &MockSecurityChecker{
		InputAction:          "mask",
		InputMasked:          "***",
		InputFindings:        []SecurityFinding{{Type: "data_leak", RuleID: "dl-1", Severity: "high", MatchedLocation: "input"}},
		InputRawFindings:     json.RawMessage(`[{"rule_id":"dl-1"}]`),
		InputRulePackVersion: "rp-1",
		InputEngineBuild:     "build-1",
		ApplyAction:          "mask",
	}
	aw := &MockAuditWriter{}
	h := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(),
		securityClient: chk, auditWriter: aw,
		cfg: &config.Config{}, fingerprints: scanfp.NewStore(nil, 16),
	}
	for round := 1; round <= 2; round++ {
		req := &ChatCompletionRequest{Messages: []Message{{Role: "user", Content: jsonQuote("secret: AKIA...")}}}
		env := &modelrouter.RequestEnvelope{RequestID: fmt.Sprintf("r%d", round), TenantID: "t1"}
		if _, err := h.applyInputSecurity(context.Background(), env, req); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(chk.InputCheckCalls); got != 2 {
		t.Fatalf("重放判 mask 必须回退全量检测：两轮各调引擎一次, got %d", got)
	}
	if got := len(chk.ApplyCalls); got != 1 {
		t.Fatalf("第二轮应先尝试重放, got %d", got)
	}
	// 回退产生的是真实检测事件，不带 fingerprint_reuse
	for _, w := range aw.SecurityEventWrites {
		if w.ScanMode != "" {
			t.Fatalf("mask 回退路径不得标 fingerprint_reuse: %+v", w)
		}
	}
}

func TestFingerprintCacheRecordsHitAndMissMetricsWithoutExposingKeys(t *testing.T) {
	checker := &MockSecurityChecker{
		InputAction:                 "allow",
		InputRawFindings:            json.RawMessage("[]"),
		InputRulePackVersion:        "rules-1",
		InputEngineBuild:            "engine-1",
		InputSemanticConfigRevision: "semantic-1",
	}
	audit := &MockAuditWriter{}
	metrics := relay.NewMetrics()
	handler := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(),
		securityClient: checker,
		auditWriter:    audit,
		relayMetrics:   metrics,
		cfg:            &config.Config{},
		fingerprints:   scanfp.NewStore(nil, 8),
	}
	for index := 1; index <= 2; index++ {
		req := &ChatCompletionRequest{Messages: []Message{{Role: "user", Content: jsonQuote("same prompt")}}}
		env := &modelrouter.RequestEnvelope{RequestID: fmt.Sprintf("metrics-%d", index), TenantID: "tenant-1"}
		if _, err := handler.applyInputSecurity(context.Background(), env, req); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := metrics.Snapshot()
	if snapshot["scan_cache_miss"] != 1 || snapshot["scan_cache_hit"] != 1 {
		t.Fatalf("scan cache metrics=%v", snapshot)
	}
}

func TestFingerprintCache_ReplayUsesCurrentMessageAnchor(t *testing.T) {
	originalIndex := 0
	original := SecurityFinding{Type: "prompt_injection", RuleID: "pi-anchor",
		Severity: "high", MessageIndex: &originalIndex, MessageRole: "system",
		ContentSource: "system_prompt", MatchedLocation: "content[0:4]"}
	chk := &MockSecurityChecker{
		InputAction: "audit", InputFindings: []SecurityFinding{original},
		InputRawFindings:     json.RawMessage(`[{"type":"prompt_injection","rule_id":"pi-anchor","severity":"high","message_index":0,"message_role":"system"}]`),
		InputRulePackVersion: "rp-anchor", InputEngineBuild: "build-anchor",
		ApplyAction: "block", ApplyFindings: []SecurityFinding{original},
	}
	var recorded [][]SecurityFinding
	aw := &MockAuditWriter{OnSecurityEvent: func(_ string, fs []SecurityFinding) {
		recorded = append(recorded, append([]SecurityFinding(nil), fs...))
	}}
	h := &ChatCompletionsHandler{toolRiskClient: allInspectionTestClient(), securityClient: chk, auditWriter: aw,
		cfg: &config.Config{}, fingerprints: scanfp.NewStore(nil, 16)}
	text := jsonQuote("same reusable detector input")
	first := &ChatCompletionRequest{Messages: []Message{{Role: "system", Content: text}}}
	_, _ = h.applyInputSecurity(context.Background(),
		&modelrouter.RequestEnvelope{RequestID: "anchor-first", TenantID: "t1"}, first)
	later := &ChatCompletionRequest{Messages: []Message{
		{Role: "user", Content: jsonQuote("")}, {Role: "assistant", Content: jsonQuote("")},
		{Role: "system", Content: text},
	}}
	_, _ = h.applyInputSecurity(context.Background(),
		&modelrouter.RequestEnvelope{RequestID: "anchor-later", TenantID: "t1"}, later)
	if len(chk.InputCheckCalls) != 1 || len(chk.ApplyCalls) != 1 {
		t.Fatalf("expected cached replay: checks=%d replays=%d", len(chk.InputCheckCalls), len(chk.ApplyCalls))
	}
	if len(aw.SecurityEventWrites) != 2 {
		t.Fatalf("events=%d", len(aw.SecurityEventWrites))
	}
	findings := recorded[1]
	if len(findings) != 1 || findings[0].MessageIndex == nil || *findings[0].MessageIndex != 2 || findings[0].MessageRole != "system" {
		t.Fatalf("replayed evidence kept a stale anchor: %+v", findings)
	}
	if *chk.ApplyFindings[0].MessageIndex != 0 || *chk.InputFindings[0].MessageIndex != 0 {
		t.Fatal("reanchoring mutated cached/source findings")
	}
	if findings[0].ContentSource != "system_prompt" || findings[0].MatchedLocation != "content[0:4]" {
		t.Fatal("content provenance or relative span changed")
	}
}

func TestFingerprintContextKeyIgnoresOnlyRequestMessageAnchor(t *testing.T) {
	a, b := 0, 7
	env := &modelrouter.RequestEnvelope{TenantID: "t1"}
	first := []SecurityFinding{{RuleID: "r", Severity: "high", MessageIndex: &a, MessageRole: "system", ContentSource: "system_prompt"}}
	later := []SecurityFinding{{RuleID: "r", Severity: "high", MessageIndex: &b, MessageRole: "developer", ContentSource: "system_prompt"}}
	key := fingerprintDetectionContextKey(env, "audit", first, "system_prompt", "", "")
	if key != fingerprintDetectionContextKey(env, "audit", later, "system_prompt", "", "") {
		t.Fatal("physical message positions must not prevent equivalent evidence folding")
	}
	later[0].Severity = "critical"
	if key == fingerprintDetectionContextKey(env, "audit", later, "system_prompt", "", "") {
		t.Fatal("risk changes must still produce distinct evidence context")
	}
}
