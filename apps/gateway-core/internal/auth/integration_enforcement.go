package auth

import (
	"context"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"sort"
	"sync"
)

const (
	KeyModelEnforcementKey     contextKey = "key_model_enforcement"
	KeyDLPEnforcementKey       contextKey = "key_dlp_enforcement"
	KeyModelObservationKey     contextKey = "key_model_observation"
	IntegrationDLPBlockKeysKey contextKey = "integration_dlp_block_key_ids"
)

type ModelObservation struct {
	mu      sync.Mutex
	models  map[string]bool
	emitted bool
}

func integrationDLPBlockGateOpen() bool { return ai.EnforcementGate() == "allow_block" }

func keyModelAdmission(ctx context.Context, name string, observe bool) bool {
	if KeyModelAllowed(ctx, name) {
		return true
	}
	agent, _ := ctx.Value(AgentInstanceIDKey).(string)
	configured, _ := ctx.Value(KeyModelEnforcementKey).(string)
	if ai.EffectiveEnforcement(configured, agent != "") != "record" {
		return false
	}
	if state, ok := ctx.Value(KeyModelObservationKey).(*ModelObservation); observe && ok {
		state.mu.Lock()
		defer state.mu.Unlock()
		if state.models == nil {
			state.models = map[string]bool{}
		}
		state.models[name] = true
	}
	return true
}

// 列举模型不构成调用，不产生名单外审计。
func UserModelVisible(ctx context.Context, name string) bool {
	access, ok := ctx.Value(modelAccessContextKey{}).(*modelaccess.Access)
	return keyModelAdmission(ctx, name, false) && (!ok || access.Allows(name))
}

func TakeModelObservations(ctx context.Context) []string {
	state, ok := ctx.Value(KeyModelObservationKey).(*ModelObservation)
	if !ok {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.emitted || len(state.models) == 0 {
		return nil
	}
	state.emitted = true
	names := make([]string, 0, len(state.models))
	for name := range state.models {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func EffectiveDLPEnforcement(ctx context.Context) string {
	agent, _ := ctx.Value(AgentInstanceIDKey).(string)
	configured, _ := ctx.Value(KeyDLPEnforcementKey).(string)
	if agent == "" {
		return "record"
	}
	return ai.EffectiveEnforcement(configured, true)
}
