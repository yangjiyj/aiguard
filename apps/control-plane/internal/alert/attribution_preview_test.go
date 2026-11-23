package alert

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAttributionPreviewIsReadOnlyAndDoesNotExposeEvidence(t *testing.T) {
	body := map[string]any{"event_id": "historic", "event_type": "data_security", "rule_name": "Email", "rule_type": "pii", "severity": "critical", "matched": map[string]any{"findings": []any{map[string]any{"type": "pii", "category": "email", "severity": "low"}, map[string]any{"type": "secret", "category": "api_key", "severity": "critical", "rule_name": "API credential", "evidence": "synthetic-never-output-evidence"}}}}
	before, _ := json.Marshal(body)
	preview := PreviewAlertBodyAttribution(body)
	after, _ := json.Marshal(body)
	encoded, _ := json.Marshal(preview)
	if string(before) != string(after) {
		t.Fatal("dry run mutated historical body")
	}
	if !preview.Changed || preview.RuleName != "API credential" || preview.Severity != "critical" || strings.Contains(string(encoded), "synthetic-never-output-evidence") {
		t.Fatalf("unsafe/inaccurate metadata preview: %s", encoded)
	}
}
