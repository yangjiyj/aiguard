package handler

import (
	"encoding/json"
	"testing"
	"time"
)

// W5 5.5: the sequence window is delivered; a behavior object that carries
// only the window keeps the default burst thresholds instead of zeroing them.
func TestWS5ConvertAgentGuardPolicySequenceWindow(t *testing.T) {
	var data agentGuardPolicyData
	if err := json.Unmarshal([]byte(`{"id":"p","mode":"strict","behavior":{"sensitive_read_egress_window_seconds":600}}`), &data); err != nil {
		t.Fatal(err)
	}
	policy := convertAgentGuardPolicy(&data)
	if policy.Behavior == nil || policy.Behavior.SensitiveReadEgressWindow != 10*time.Minute {
		t.Fatalf("window not mapped: %#v", policy.Behavior)
	}
	if policy.Behavior.FileReadBurst != defaultAgentGuardBehaviorThresholds.FileReadBurst ||
		policy.Behavior.NetworkEgressBurst != defaultAgentGuardBehaviorThresholds.NetworkEgressBurst ||
		policy.Behavior.CommandExecuteBurst != defaultAgentGuardBehaviorThresholds.CommandExecuteBurst {
		t.Fatalf("burst thresholds must keep defaults: %#v", policy.Behavior)
	}

	var withBurst agentGuardPolicyData
	if err := json.Unmarshal([]byte(`{"id":"p","behavior":{"file_read_burst_10s":7,"sensitive_read_egress_window_seconds":999999}}`), &withBurst); err != nil {
		t.Fatal(err)
	}
	converted := convertAgentGuardPolicy(&withBurst)
	if converted.Behavior.FileReadBurst != 7 || converted.Behavior.SensitiveReadEgressWindow != 24*time.Hour {
		t.Fatalf("explicit burst kept and window clamped expected, got %#v", converted.Behavior)
	}

	var legacy agentGuardPolicyData
	if err := json.Unmarshal([]byte(`{"id":"p","behavior":{"file_read_burst_10s":50,"network_egress_burst_10s":50,"command_execute_burst_10s":20}}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if got := convertAgentGuardPolicy(&legacy).Behavior; got.SensitiveReadEgressWindow != 0 || got.FileReadBurst != 50 {
		t.Fatalf("legacy behavior must be unchanged with the rule off, got %#v", got)
	}
}
