package handler

import (
	"encoding/json"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// maxAgentGuardSequenceWindowSeconds mirrors the control-plane bound on the
// sensitive-read -> egress window (24h); larger values are clamped.
const maxAgentGuardSequenceWindowSeconds = 24 * 60 * 60

// defaultAgentGuardBehaviorThresholds are the burst thresholds the gateway
// uses when a policy delivers no behavior baseline.
var defaultAgentGuardBehaviorThresholds = agentguard.BehaviorThresholds{
	FileReadBurst: 100, NetworkEgressBurst: 100, CommandExecuteBurst: 50,
}

// UnmarshalJSON records which burst keys the control plane actually sent, so
// a behavior object that only carries the sequence window (W5 5.5) does not
// silently turn the burst thresholds into 0 (= disabled).
func (d *agentGuardBehaviorData) UnmarshalJSON(raw []byte) error {
	type plain agentGuardBehaviorData
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return err
	}
	*d = agentGuardBehaviorData(decoded)
	d.present = map[string]bool{}
	for key := range keys {
		d.present[key] = true
	}
	return nil
}

// sent reports whether key was delivered; literals built in code (present ==
// nil) count every field as delivered.
func (d *agentGuardBehaviorData) sent(key string) bool {
	return d.present == nil || d.present[key]
}

// applyAgentGuardSequenceBehavior copies the sequence rule window. When the
// control plane sent none of the burst keys (a behavior object that only
// carries the sequence rule), the burst thresholds keep the gateway defaults,
// exactly as if no behavior object had been sent. A zero or negative window
// disables the sequence rule.
func applyAgentGuardSequenceBehavior(thresholds *agentguard.BehaviorThresholds, data *agentGuardBehaviorData) {
	if thresholds == nil || data == nil {
		return
	}
	if !data.sent("file_read_burst_10s") && !data.sent("network_egress_burst_10s") && !data.sent("command_execute_burst_10s") {
		thresholds.FileReadBurst = defaultAgentGuardBehaviorThresholds.FileReadBurst
		thresholds.NetworkEgressBurst = defaultAgentGuardBehaviorThresholds.NetworkEgressBurst
		thresholds.CommandExecuteBurst = defaultAgentGuardBehaviorThresholds.CommandExecuteBurst
	}
	seconds := data.SensitiveReadEgressWindowSeconds
	if seconds <= 0 {
		thresholds.SensitiveReadEgressWindow = 0
		return
	}
	if seconds > maxAgentGuardSequenceWindowSeconds {
		seconds = maxAgentGuardSequenceWindowSeconds
	}
	thresholds.SensitiveReadEgressWindow = time.Duration(seconds) * time.Second
}
