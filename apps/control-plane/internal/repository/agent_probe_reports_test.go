package repository

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/probereports"
)

func TestAiprobeAssetEvidenceRetainsTypedT08Projection(t *testing.T) {
	report := &probereports.Report{
		Status:     "partial",
		Collectors: []probereports.CollectorResult{{Name: "agents", Status: "partial", ErrorCode: "collector_error"}},
	}
	asset := probereports.Asset{
		SourceID:         "source-hash",
		Kind:             "cli_agent",
		Name:             "stable-source-name",
		DisplayName:      "Human-readable label",
		CollectionStatus: "stale",
		Running:          true,
		Confidence:       91,
		EvidenceLabels:   []string{"catalog", "signed_binary"},
		RiskFlags:        []string{"exposed_gateway"},
	}
	raw, err := projectAiprobeAssetEvidence(report, asset, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["name"] != asset.Name || got["display_name"] != asset.DisplayName ||
		got["collection_status"] != asset.CollectionStatus || got["report_status"] != report.Status ||
		got["running"] != true || got["confidence"] != float64(asset.Confidence) {
		t.Fatalf("typed asset metadata missing from T08 evidence: %#v", got)
	}
	labels, ok := got["evidence_labels"].([]any)
	if !ok || len(labels) != 2 || labels[0] != "catalog" || labels[1] != "signed_binary" {
		t.Fatalf("evidence labels missing from T08 evidence: %#v", got["evidence_labels"])
	}
	risks, ok := got["risk_flags"].([]any)
	if !ok || len(risks) != 1 || risks[0] != "exposed_gateway" {
		t.Fatalf("risk flags missing from T08 evidence: %#v", got["risk_flags"])
	}
}
