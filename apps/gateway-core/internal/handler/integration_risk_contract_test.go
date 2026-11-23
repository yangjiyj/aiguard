package handler

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestIntegrationRiskContractMatchesNativeSummaryWriter(t *testing.T) {
	const fixturePath = "../../../../docs/integration/fixtures/gateway-risk-contract.json"
	type nativeFinding struct {
		Type        string `json:"type"`
		Category    string `json:"category"`
		Severity    string `json:"severity"`
		PolicyScene string `json:"policy_scene,omitempty"`
		Counts      *bool  `json:"counts_as_security_finding,omitempty"`
	}
	var fixture struct {
		SchemaVersion string `json:"schema_version"`
		Cases         []struct {
			Name                 string          `json:"name"`
			NativeFindings       []nativeFinding `json:"native_findings"`
			EventType            string          `json:"event_type"`
			MatchedSummary       map[string]any  `json:"matched_summary"`
			ExpectedRiskFactors  []string        `json:"expected_risk_factors"`
			ExpectedRiskCategory string          `json:"expected_risk_category"`
		} `json:"cases"`
	}
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	update := os.Getenv("JJD_UPDATE_RISK_CONTRACT") == "1"
	for i := range fixture.Cases {
		tc := &fixture.Cases[i]
		t.Run(tc.Name, func(t *testing.T) {
			findings := make([]SecurityFinding, 0, len(tc.NativeFindings))
			for _, f := range tc.NativeFindings {
				findings = append(findings, SecurityFinding{Type: f.Type, Category: f.Category, Severity: f.Severity, PolicyScene: f.PolicyScene, CountsAsSecurityFinding: f.Counts, RuleID: "contract_" + f.Category})
			}
			if got := eventTypeForFindings(findings); got != tc.EventType {
				t.Fatalf("native event type=%q want=%q", got, tc.EventType)
			}
			encoded, err := json.Marshal(buildSecurityMatchedSummary(findings, "audit", "synthetic native metadata contract"))
			if err != nil {
				t.Fatal(err)
			}
			var actual map[string]any
			if err = json.Unmarshal(encoded, &actual); err != nil {
				t.Fatal(err)
			}
			if update {
				tc.MatchedSummary = actual
			} else if !reflect.DeepEqual(actual, tc.MatchedSummary) {
				t.Fatalf("committed fixture differs from native writer: actual=%s", encoded)
			}
		})
	}
	// Regeneration records actual writer output and preserves independent risk expectations.
	if update && !t.Failed() {
		encoded, err := json.MarshalIndent(fixture, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(fixturePath, append(encoded, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
}
