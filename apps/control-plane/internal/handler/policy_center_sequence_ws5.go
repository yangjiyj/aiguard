package handler

import (
	"errors"
	"math"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// agentGuardSequenceWindowKey is the behavior_json key of the
// sensitive-read -> egress sequence rule (W5 5.5). 0 or absent = off.
const agentGuardSequenceWindowKey = "sensitive_read_egress_window_seconds"

// maxPolicyCenterSequenceWindowSeconds bounds the window (24h); the gateway
// clamps to the same value.
const maxPolicyCenterSequenceWindowSeconds = 24 * 60 * 60

func validatePolicyCenterSequenceWindow(seconds int) error {
	if seconds < 0 || seconds > maxPolicyCenterSequenceWindowSeconds {
		return errors.New("sensitive_read_egress_window_seconds must be between 0 and 86400")
	}
	return nil
}

// applyPolicyCenterSequenceWindow writes the window into the managed policy's
// behavior_json; nil leaves the stored value untouched, 0 removes it.
func applyPolicyCenterSequenceWindow(policy *repository.AgentGuardPolicy, seconds *int) {
	if policy == nil || seconds == nil {
		return
	}
	if policy.BehaviorJSON == nil {
		policy.BehaviorJSON = map[string]any{}
	}
	if *seconds <= 0 {
		delete(policy.BehaviorJSON, agentGuardSequenceWindowKey)
		return
	}
	policy.BehaviorJSON[agentGuardSequenceWindowKey] = *seconds
}

// policyCenterSequenceWindowSeconds reads the stored window (0 = off).
func policyCenterSequenceWindowSeconds(policy *repository.AgentGuardPolicy) int {
	if policy == nil || policy.BehaviorJSON == nil {
		return 0
	}
	var value float64
	switch typed := policy.BehaviorJSON[agentGuardSequenceWindowKey].(type) {
	case int:
		value = float64(typed)
	case int64:
		value = float64(typed)
	case float64:
		value = typed
	default:
		return 0
	}
	if value <= 0 || math.IsNaN(value) {
		return 0
	}
	if value > maxPolicyCenterSequenceWindowSeconds {
		return maxPolicyCenterSequenceWindowSeconds
	}
	return int(value)
}
