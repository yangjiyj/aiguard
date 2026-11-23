package nasexport

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
	"github.com/yangjiyj/aiguard/packages/shared-go/outbox"
)

// Processor 实现 auditpipe.Processor：Claim 到安全事件后转 ExportEvent 写 NAS。
// 设计§13：只导脱敏事件；NAS不可用返回error由outbox有限重试，不阻塞DLP判定。

func TestProcessorWritesSecurityEvent(t *testing.T) {
	root := safeTempDir(t)
	p, _ := NewProcessor(root)
	payload := eventbus.AuditSecurityEventPayload{
		EventID:     "sec_evt_1",
		EventType:   "file_content_phone_cn",
		Severity:    "high",
		ActionTaken: "block",
		RuleID:      "phone-cn",
	}
	raw, _ := json.Marshal(payload)
	ev := outbox.Event{ID: "ob1", Type: eventbus.EventTypeAuditSecurityEventWrite, Payload: raw}
	if err := p.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process: %v", err)
	}
	// 事件 EventID 落为幂等文件名
	if _, err := os.Stat(filepath.Join(root, "sec_evt_1.json")); err != nil {
		t.Fatalf("expected sec_evt_1.json: %v", err)
	}
}

func TestProcessorIgnoresOtherEventTypes(t *testing.T) {
	root := safeTempDir(t)
	p, _ := NewProcessor(root)
	ev := outbox.Event{ID: "ob2", Type: "some.other.event", Payload: []byte("{}")}
	if err := p.Process(context.Background(), ev); err != nil {
		t.Fatalf("non-security event should be ignored, got: %v", err)
	}
	ents, _ := os.ReadDir(root)
	if len(ents) != 0 {
		t.Fatalf("no file expected for non-security event, got %d", len(ents))
	}
}

func TestProcessorBadPayloadReturnsError(t *testing.T) {
	root := safeTempDir(t)
	p, _ := NewProcessor(root)
	ev := outbox.Event{ID: "ob3", Type: eventbus.EventTypeAuditSecurityEventWrite, Payload: []byte("not json")}
	if err := p.Process(context.Background(), ev); err == nil {
		t.Fatalf("bad payload should return error for outbox retry")
	}
}

func TestProcessorNasUnavailableReturnsError(t *testing.T) {
	// 相对路径根（管理员必须配绝对路径）→ 构造即拒
	if _, err := NewProcessor("relative/nas"); err == nil {
		t.Fatalf("relative NAS root must be rejected at construction")
	}
}

// 非文件内容 DLP 安全事件不导出（严格白名单，设计§13）。
func TestProcessorSkipsNonFileDLPSecurityEvents(t *testing.T) {
	root := safeTempDir(t)
	p, _ := NewProcessor(root)
	// 各类非文件 DLP 安全事件
	nonFileEvents := []eventbus.AuditSecurityEventPayload{
		{EventID: "e1", EventType: "prompt_injection", Severity: "high", ActionTaken: "block"},
		{EventID: "e2", EventType: "jailbreak", Severity: "high", ActionTaken: "block"},
		{EventID: "e3", EventType: "phone_cn", Severity: "medium", ActionTaken: "audit"}, // 普通文字 PII，非文件
		{EventID: "e4", EventType: "aws_access_key", Severity: "high", ActionTaken: "block"},
		{EventID: "e5", EventType: "secret_openai_key", Severity: "high", ActionTaken: "block"},
	}
	for _, payload := range nonFileEvents {
		raw, _ := json.Marshal(payload)
		ev := outbox.Event{ID: "ob-" + payload.EventID, Type: eventbus.EventTypeAuditSecurityEventWrite, Payload: raw}
		if err := p.Process(context.Background(), ev); err != nil {
			t.Fatalf("non-file event should be skipped (nil), got err: %v", err)
		}
	}
	ents, _ := os.ReadDir(root)
	if len(ents) != 0 {
		t.Fatalf("non-file DLP events must not be exported, got %d files", len(ents))
	}
}

// 文件内容 DLP 事件（event_type 或 rule_id 命中白名单前缀）才导出。
func TestProcessorExportsFileDLPEvents(t *testing.T) {
	root := safeTempDir(t)
	p, _ := NewProcessor(root)
	fileEvents := []eventbus.AuditSecurityEventPayload{
		{EventID: "f1", EventType: "file_content_phone_cn", Severity: "high", ActionTaken: "block"},
		{EventID: "f2", EventType: "file_content_parse_failed", Severity: "high", ActionTaken: "block"},
		{EventID: "f3", EventType: "security_check", RuleID: "file-content-parse-failed", Severity: "high", ActionTaken: "block"},
		{EventID: "f4", EventType: "file_policy_blocked_type", Severity: "high", ActionTaken: "block"},
		{EventID: "f5", EventType: "file_id_verdict_block", Severity: "high", ActionTaken: "block"},
	}
	for _, payload := range fileEvents {
		raw, _ := json.Marshal(payload)
		ev := outbox.Event{ID: "ob-" + payload.EventID, Type: eventbus.EventTypeAuditSecurityEventWrite, Payload: raw}
		if err := p.Process(context.Background(), ev); err != nil {
			t.Fatalf("file DLP event should export, got err: %v", err)
		}
	}
	ents, _ := os.ReadDir(root)
	if len(ents) != len(fileEvents) {
		t.Fatalf("expected %d exported, got %d", len(fileEvents), len(ents))
	}
}

// 普通文字 PII（phone_cn 非 file_content_ 前缀）不导出，即使 action=block。
func TestProcessorDoesNotLeakNonFilePII(t *testing.T) {
	root := safeTempDir(t)
	p, _ := NewProcessor(root)
	// phone_cn 是文字消息 PII，不是文件内容 DLP，不该导出
	payload := eventbus.AuditSecurityEventPayload{
		EventID:     "leak1",
		EventType:   "phone_cn",
		Severity:    "high",
		ActionTaken: "block",
		MatchedSummary: map[string]any{
			"sample": "电话13812345678内容",
		},
	}
	raw, _ := json.Marshal(payload)
	ev := outbox.Event{ID: "ob-leak", Type: eventbus.EventTypeAuditSecurityEventWrite, Payload: raw}
	p.Process(context.Background(), ev)
	ents, _ := os.ReadDir(root)
	if len(ents) != 0 {
		t.Fatalf("non-file PII event must not be exported: %d files", len(ents))
	}
}
