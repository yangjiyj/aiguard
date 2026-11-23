package alert

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"strings"
	"testing"
	"time"
)

func TestMixedFindingsKeepDominantEvidenceTogether(t *testing.T) {
	email := map[string]any{"type": "pii", "category": "email", "severity": "low", "confidence": 0.99, "rule_name": "Email address"}
	semantic := map[string]any{"type": "semantic_attack", "category": "semantic_harassment", "severity": "medium", "confidence": 0.95}
	secret := map[string]any{"type": "secret", "category": "api_key", "severity": "critical", "confidence": 1.0, "rule_id": "secret-rule", "rule_name": "API credential", "evidence": "redacted-secret"}
	for _, findings := range [][]map[string]any{{email, semantic, secret}, {secret, semantic, email}} {
		ev := secEventWithFindings("mixed", "audit", findings...)
		ev.RuleName = "Email address"
		ev.Severity = "critical"
		src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
		groups := &fakeAlertGrouper{}
		_, err := gateBridge(src, &fakePusher{}, &fakeNotifier{}, 0.5).WithAlertGroups(groups).RunOnce(context.Background())
		if err != nil || len(groups.inputs) != 1 {
			t.Fatalf("bridge err=%v groups=%v", err, groups.inputs)
		}
		in := groups.inputs[0]
		if strings.Contains(in.Title, "语义骚扰") || in.BodyJSON["rule_name"] != "API credential" || in.BodyJSON["category"] != "api_key" || in.BodyJSON["rule_id"] != "secret-rule" {
			t.Fatalf("mixed attribution: title=%s body=%v", in.Title, in.BodyJSON)
		}
		if in.Severity != "critical" || in.ClassKey != "api_key" {
			t.Fatalf("wrong dominant severity/category: %+v", in)
		}
	}
}
func TestFalsePositiveScopeDoesNotCrossProject(t *testing.T) {
	a := secEventSha("a", "same-evidence")
	b := secEventSha("b", "same-evidence")
	a.ProjectID = "project-a"
	b.ProjectID = "project-b"
	if eventGroupKey(a) == eventGroupKey(b) {
		t.Fatal("same tenant projects share a false-positive suppression key")
	}
}

func TestRuntimeFailureUsesOperationalNotification(t *testing.T) {
	ev := secEventWithFindings("runtime-failure", "allow")
	ev.EventType = "security_check_failed"
	ev.Severity = "low"
	ev.MatchedSummary = map[string]any{"category": "system", "counts_as_security_finding": false, "semantic_status": "unavailable", "semantic_reason": "upstream unavailable"}
	groups := &fakeAlertGrouper{}
	inbox := &fakePusher{}
	_, err := gateBridge(&fakeSecEventSource{events: []*repository.SecurityEvent{ev}}, inbox, &fakeNotifier{}, 0.5).WithAlertGroups(groups).RunOnce(context.Background())
	if err != nil || len(groups.inputs) != 1 {
		t.Fatalf("missing operational group: %v %v", err, groups.inputs)
	}
	in := groups.inputs[0]
	if in.AlertType != "runtime_fault" || in.BodyJSON["notification_kind"] != "runtime_fault" || !strings.Contains(in.Title, "检测运行故障") {
		t.Fatalf("operational failure represented as attack: %+v", in)
	}
}

func TestFalsePositiveScopeDoesNotCrossStageOrToolProject(t *testing.T) {
	a := secEventSha("a", "same")
	b := secEventSha("b", "same")
	a.MatchedSummary["stage"] = "input"
	b.MatchedSummary["stage"] = "output"
	if eventGroupKey(a) == eventGroupKey(b) {
		t.Fatal("input disposition silences output event")
	}
	a.EventType = "tool_execution_risk"
	b.EventType = "tool_execution_risk"
	a.ProjectID = "a"
	b.ProjectID = "b"
	if eventGroupKey(a) == eventGroupKey(b) {
		t.Fatal("tool disposition crosses project")
	}
}

func TestSameSeverityDeterministicSecretWinsSemanticScore(t *testing.T) {
	secret := map[string]any{"type": "secret", "category": "api_key", "severity": "critical", "confidence": 0.8}
	semantic := map[string]any{"type": "semantic_attack", "category": "semantic_harassment", "severity": "critical", "confidence": 1.0}
	ev := secEventWithFindings("same-severity", "audit", semantic, secret)
	if dominantCategory(ev) != "api_key" {
		t.Fatal("model confidence score displaced deterministic secret evidence")
	}
}

func TestPendingReviewThenConfirmedRiskBecomesVisible(t *testing.T) {
	finding := map[string]any{"type": "pii", "category": "pii_phone", "severity": "high", "confidence": 0.95, "content_source": "verified_user_input", "review_state": "review_pending"}
	ev := secEventWithFindings("pending-confirmed", "security_audit", finding)
	ev.CreatedAt = time.Now().UTC()
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	inbox := &fakePusher{}
	bridge := gateBridge(src, inbox, &fakeNotifier{}, 0.5)
	if count, err := bridge.RunOnce(context.Background()); err != nil || count != 0 || len(src.markedIDs) != 0 {
		t.Fatalf("pending prematurely delivered: %d %v", count, err)
	}
	finding["review_state"] = "confirmed_risk"
	if count, err := bridge.RunOnce(context.Background()); err != nil || count != 1 || len(src.markedIDs) != 1 {
		t.Fatalf("confirmed risk swallowed after pending: %d %v", count, err)
	}
}
