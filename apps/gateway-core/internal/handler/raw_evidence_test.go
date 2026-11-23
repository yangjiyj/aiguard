package handler

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// rawEvidenceAudit 在 MockAuditWriter 之上记录留证调用，且保证原文不进入内容日志。
type rawEvidenceAudit struct {
	*MockAuditWriter
	mu      sync.Mutex
	records []RawEvidenceRecord
}

func (a *rawEvidenceAudit) WriteRawEvidence(_ context.Context, _ *modelrouter.RequestEnvelope, rec RawEvidenceRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, rec)
}

func rawEvidenceHandler(client *MockSecurityChecker) (*ChatCompletionsHandler, *rawEvidenceAudit) {
	audit := &rawEvidenceAudit{MockAuditWriter: &MockAuditWriter{}}
	return &ChatCompletionsHandler{securityClient: client, auditWriter: audit}, audit
}

func rawEvidenceEnvelope() *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{RequestID: "req-raw", TenantID: "tenant-raw", ProjectID: "p", Model: "gpt-4"}
}

func TestRawEvidenceInputMaskedKeepsOriginalOutOfUpstream(t *testing.T) {
	idx := 1
	h, audit := rawEvidenceHandler(&MockSecurityChecker{
		InputAction: "mask", InputMasked: "电话 <MASKED>",
		InputFindings: []SecurityFinding{{Type: "pii", Category: "phone", RuleID: "r-phone", RuleName: "手机号", Severity: "medium", MessageIndex: &idx}},
	})
	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("电话 13800138000")}}}
	result := h.applyChatInputSecurity(withBlockLedger(context.Background()), rawEvidenceEnvelope(), req)
	if result.err != nil {
		t.Fatal(result.err)
	}
	if got := messageText(req.Messages[0].Content); got != "电话 <MASKED>" {
		t.Fatalf("upstream must receive masked text, got %q", got)
	}
	if len(audit.records) != 1 {
		t.Fatalf("records=%d want 1", len(audit.records))
	}
	rec := audit.records[0]
	if rec.Text != "电话 13800138000" || rec.Disposition != rawEvidenceMasked || rec.Direction != rawEvidenceInput || rec.Role != "user" || rec.Index != 0 {
		t.Fatalf("bad record %+v", rec)
	}
	if len(rec.RuleIDs) != 1 || rec.RuleIDs[0] != "r-phone" || rec.RuleNames[0] != "手机号" {
		t.Fatalf("rule attribution lost: %+v", rec)
	}
}

func TestRawEvidenceInputUnchangedWritesNothing(t *testing.T) {
	h, audit := rawEvidenceHandler(&MockSecurityChecker{InputAction: "allow"})
	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("你好")}}}
	if r := h.applyChatInputSecurity(context.Background(), rawEvidenceEnvelope(), req); r.err != nil {
		t.Fatal(r.err)
	}
	if len(audit.records) != 0 {
		t.Fatalf("unexpected evidence %+v", audit.records)
	}
}

func TestRawEvidenceInputBlockedKeepsTargetMessageAndBlockID(t *testing.T) {
	h, audit := rawEvidenceHandler(&MockSecurityChecker{
		InputAction:   "block",
		InputFindings: []SecurityFinding{{Type: "secret", Severity: "critical", RuleID: "r-key", RuleName: "密钥"}},
	})
	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{
		{Role: "system", Content: jsonQuote("规则")},
		{Role: "user", Content: jsonQuote("我的密钥 sk-ABCDEF")},
	}}
	ctx := withBlockLedger(context.Background())
	// 模拟审计写入器登记的阻断编号。
	blockLedgerFromContext(ctx).entry = &blockAttribution{BlockID: "evt-9", RuleID: "r-key"}
	r := h.applyChatInputSecurity(ctx, rawEvidenceEnvelope(), req)
	if r.err == nil {
		t.Fatal("expected block")
	}
	found := false
	for _, rec := range audit.records {
		if rec.Disposition == rawEvidenceBlocked && rec.Text == "我的密钥 sk-ABCDEF" {
			found = true
			if rec.BlockID != "evt-9" || rec.Index != 1 || len(rec.RuleIDs) == 0 {
				t.Fatalf("bad block attribution %+v", rec)
			}
		}
		if rec.Text == "规则" {
			t.Fatal("unrelated system message must not be retained")
		}
	}
	if !found {
		t.Fatalf("blocked original not retained: %+v", audit.records)
	}
}

func TestRawEvidenceOutputMaskedAndBlocked(t *testing.T) {
	body := []byte(`{"id":"c","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"phone 13800138000"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`)
	h, audit := rawEvidenceHandler(&MockSecurityChecker{OutputAction: "mask", OutputMasked: "[redacted]",
		OutputFindings: []SecurityFinding{{Type: "pii", Category: "dlp", RuleID: "r-out", RuleName: "手机号"}}})
	secured, _, err := h.applyOutputSecurity(context.Background(), rawEvidenceEnvelope(), nil, body)
	if err != nil || strings.Contains(string(secured), "13800138000") {
		t.Fatalf("masked body wrong: %v %s", err, secured)
	}
	if len(audit.records) != 1 || audit.records[0].Text != "phone 13800138000" || audit.records[0].Direction != rawEvidenceOutput ||
		audit.records[0].Disposition != rawEvidenceMasked || audit.records[0].RuleIDs[0] != "r-out" {
		t.Fatalf("bad output evidence %+v", audit.records)
	}

	h, audit = rawEvidenceHandler(&MockSecurityChecker{OutputAction: "block",
		OutputFindings: []SecurityFinding{{Type: "pii", Category: "dlp", RuleID: "r-out"}}})
	ctx := withBlockLedger(context.Background())
	blockLedgerFromContext(ctx).entry = &blockAttribution{BlockID: "evt-out"}
	if _, _, err := h.applyOutputSecurity(ctx, rawEvidenceEnvelope(), nil, body); err == nil {
		t.Fatal("expected output block")
	}
	if len(audit.records) != 1 || audit.records[0].Disposition != rawEvidenceBlocked || audit.records[0].BlockID != "evt-out" ||
		audit.records[0].Text != "phone 13800138000" {
		t.Fatalf("blocked output evidence wrong %+v", audit.records)
	}
}
