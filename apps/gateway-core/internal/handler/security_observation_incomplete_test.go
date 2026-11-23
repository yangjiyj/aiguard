package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 复审 I2：语义检测未完成（裁判熔断 breaker_open）时，观察事件不能被改写成 security_check_failed /
// category=system（那样告警桥会把它当 runtime_fault 进收件箱）；应保留观察事件本来的类型与类别。
func TestIncompleteSemanticKeepsObservationEventType(t *testing.T) {
	notCounted := false
	telemetry := SecurityFinding{Type: "semantic_telemetry", Category: "semantic_unavailable", Severity: "low",
		RuleID: "semantic_runtime_unavailable", Action: "audit", CountsAsSecurityFinding: &notCounted,
		Triage: map[string]any{"semantic_status": "incomplete", "semantic_reason": "breaker_open"}}
	findings := []SecurityFinding{profanityDiscussion(), telemetry}
	ctx := withRetainedObservationEvent(withSemanticStatus(context.Background(), "incomplete", "breaker_open"))

	writer, db := realWriterWithDB()
	writer.WriteSecurityEvent(ctx, &modelrouter.RequestEnvelope{RequestID: "r-breaker", TenantID: "t"}, findings,
		"security_audit", "input observation in message 0 (evidence only, not a security finding)")
	if db.execCalls != 1 {
		t.Fatalf("观察事件应落库一条, got %d", db.execCalls)
	}
	args := db.args[0]
	if args[5] == "security_check_failed" || args[14] == "system" {
		t.Fatalf("观察事件被改写成检测故障: event_type=%v class_key=%v", args[5], args[14])
	}
	if args[5] != eventTypeForFindings(findings) || args[14] != "content_profanity_abuse" {
		t.Fatalf("应保留观察事件本来的类型与类别, got event_type=%v class_key=%v", args[5], args[14])
	}
	summary, _ := args[9].([]byte)
	if strings.Contains(string(summary), `"category":"system"`) {
		t.Fatalf("matched_summary 不应被改成 system: %s", summary)
	}
}

// 真正的检测故障事件（无 findings、语义未完成）仍按原逻辑改写为 security_check_failed。
func TestIncompleteSemanticWithoutFindingsStillRecordsFailure(t *testing.T) {
	writer, db := realWriterWithDB()
	writer.WriteSecurityEvent(withSemanticStatus(context.Background(), "incomplete", "breaker_open"),
		&modelrouter.RequestEnvelope{RequestID: "r-fail", TenantID: "t"}, nil, "security_audit", "semantic incomplete")
	if db.execCalls != 1 || db.args[0][5] != "security_check_failed" || db.args[0][14] != "system" {
		t.Fatalf("检测故障事件行为应与 main 一致, got %v", db.args)
	}
}
