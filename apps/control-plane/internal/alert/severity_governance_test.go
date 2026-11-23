package alert

import (
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"testing"
)

func TestInspectionFailureClassificationRequiresNoSiblingThreat(t *testing.T) {
	fault := map[string]any{"type": "file", "category": "file_unknown_type", "evidence_kind": "runtime", "counts_as_security_finding": false}
	ev := &repository.SecurityEvent{EventType: "proxy_input_block", MatchedSummary: map[string]any{"findings": []any{fault}}}
	if alertTypeForSecurityEvent(ev) != "runtime_fault" {
		t.Fatal("failure counted as attack")
	}
	ev.MatchedSummary["findings"] = []any{fault, map[string]any{"type": "secret", "category": "openai_key", "severity": "critical"}}
	if alertTypeForSecurityEvent(ev) == "runtime_fault" {
		t.Fatal("fault hid real threat")
	}
}
