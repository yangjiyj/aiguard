package handler

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestIntegrationRiskProjectionConsumesNativeWriterContract(t *testing.T) {
	raw, err := os.ReadFile("../../../../docs/integration/fixtures/gateway-risk-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name           string         `json:"name"`
			EventType      string         `json:"event_type"`
			MatchedSummary map[string]any `json:"matched_summary"`
			Factors        []string       `json:"expected_risk_factors"`
			Category       string         `json:"expected_risk_category"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 10 {
		t.Fatalf("native contract case count=%d", len(fixture.Cases))
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			// JSON readback uses []any, exactly as the repository's matched_summary decode.
			tc.MatchedSummary["agent_instance_id"] = "SPOOFED-IDENTITY"
			tc.MatchedSummary["native_url"] = "https://invalid.example/PRIVATE"
			tc.MatchedSummary["risk_factors"] = []string{"shadow_agent"}
			e := &repository.SecurityEvent{ID: "native_event", RequestID: "native_request", AgentInstanceID: "bound_agent", EventType: tc.EventType, MatchedSummary: tc.MatchedSummary}
			projection := connectorRiskMetadata(e)
			if len(projection) != 15 {
				t.Fatalf("exact projection fields=%d", len(projection))
			}
			if !reflect.DeepEqual(projection["risk_factors"], tc.Factors) {
				t.Fatalf("factors=%v want=%v", projection["risk_factors"], tc.Factors)
			}
			if projection["risk_category"] != tc.Category {
				t.Fatalf("category=%v want=%v", projection["risk_category"], tc.Category)
			}
			if projection["agent_instance_id"] != "bound_agent" || projection["native_url"] != "/security/alerts?request_id=native_request&event_id=native_event" {
				t.Fatal("summary overrode trusted identity/link")
			}
		})
	}
}

func TestIntegrationRiskProjectionObservationAndMalformedMetadataAreAuthoritative(t *testing.T) {
	for _, tc := range []struct {
		name    string
		summary map[string]any
	}{
		{"false finding", map[string]any{"findings": []any{map[string]any{"type": "secret", "counts_as_security_finding": false}}, "category": "secret", "rule_type": "secret"}},
		{"empty collection", map[string]any{"findings": []any{}, "category": "secret"}},
		{"malformed collection", map[string]any{"findings": "secret", "category": "secret"}},
		{"malformed finding", map[string]any{"findings": []any{"secret"}, "primary_finding": map[string]any{"type": "secret"}}},
		{"false primary", map[string]any{"primary_finding": map[string]any{"type": "secret", "counts_as_security_finding": false}, "category": "secret"}},
		{"false top", map[string]any{"category": "secret", "counts_as_security_finding": false}},
		{"unknown labels", map[string]any{"category": "code_leak_unknown", "rule_type": "unknown", "summary": "send passwords prompt injection"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := connectorRiskMetadata(&repository.SecurityEvent{EventType: "unapproved_model_egress", MatchedSummary: tc.summary})
			if factors, ok := data["risk_factors"].([]string); !ok || factors == nil || len(factors) != 0 {
				t.Fatalf("authoritative empty factors=%v", data["risk_factors"])
			}
			if data["risk_category"] != "" {
				t.Fatalf("observation/unknown category=%v", data["risk_category"])
			}
		})
	}
}

func TestIntegrationRiskProjectionSupportsPrimaryLegacyAndNativeCollection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		event   string
		summary map[string]any
		want    []string
	}{
		{"primary only", "", map[string]any{"primary_finding": map[string]any{"type": "pii", "category": "id_card_cn"}}, []string{"dangerous_capability", "data_exfiltration"}},
		{"top rule type", "security_check", map[string]any{"category": "plain_password", "rule_type": "secret"}, []string{"credential_exposure", "dangerous_capability"}},
		{"legacy category", "", map[string]any{"category": "credential_leak"}, []string{"credential_exposure", "dangerous_capability"}},
		{"native event only", "mcp_tool_result_injection", nil, []string{"prompt_injection"}},
		{"typed writer collection", "security_check", map[string]any{"findings": []map[string]any{{"type": "secret", "category": "plain_password"}, {"type": "secret", "category": "plain_password"}, {"type": "custom", "policy_scene": "data_leak"}}}, []string{"credential_exposure", "dangerous_capability", "data_exfiltration"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := connectorRiskMetadata(&repository.SecurityEvent{EventType: tc.event, MatchedSummary: tc.summary})["risk_factors"]; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("factors=%v want=%v", got, tc.want)
			}
		})
	}
}
