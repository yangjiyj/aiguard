package alert

import (
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alertconfig"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// trustedDevRouteName is the triage_route value written into the alert group
// body. The console renders it as "已分流留观".
const trustedDevRouteName = "trusted_dev_observation"

// trustedDevRoute is the routing decision. Route is always
// trustedDevRouteName; Reason names WHY the event was routed, so an operator
// reading the group can tell "tool_result of claude code" from "the principal
// was named trusted" without opening the event.
type trustedDevRoute struct {
	Route  string
	Reason string
}

// trustedDevConfig is the resolved policy: which encoder agents prove a trusted
// development context, and which principal keys bypass the machine-context
// requirement.
type trustedDevConfig struct {
	Agents     map[string]bool
	Principals map[string]bool
}

// trustedDevMachineSources lists the finding content_source values that
// describe machine-authored context the coding agent read or was handed — file
// bodies, tool schemas, system prompts — rather than something a human typed
// into the conversation.
var trustedDevMachineSources = map[string]bool{
	"tool_result":   true,
	"tool_def":      true,
	"system_prompt": true,
}

// trustedDevMachineRoles marks the same thing when the detector only recorded
// the message role.
var trustedDevMachineRoles = map[string]bool{"tool": true, "system": true}

// trustedDevNeverRoutedFindingTypes are evidence classes that keep their
// actionable disposition wherever they were observed.
var trustedDevNeverRoutedFindingTypes = map[string]bool{"secret": true, "data_leak": true, "file": true}

// trustedDevBridgeHandledTypes are the event types computeLifecycleFields
// dispositions with an earlier return, before this rule is ever consulted:
// tool_execution_risk is forced to action_required and tool_attempt_blocked to
// informational. This rule must agree with that, or a maintenance sweep would
// downgrade a group the live bridge keeps raising as actionable.
var trustedDevBridgeHandledTypes = map[string]bool{
	"tool_execution_risk":  true,
	"tool_attempt_blocked": true,
}

// trustedDevInjectionCategory keeps illegal-system-command instructions
// actionable even inside tool output: a "system command" found in a file the
// agent read is exactly the prompt-injection success we must not downgrade.
const trustedDevInjectionCategory = "illegal_system_command_instructions"

// trustedDevCanaryPrefix keeps canary leaks actionable: a canary in tool output
// proves a working exfiltration path, not a false positive.
const trustedDevCanaryPrefix = "agent_canary"

// trustedDevDefaults is the shipped policy, independent of the environment so
// shared fixtures stay deterministic.
func trustedDevDefaults() trustedDevConfig {
	return trustedDevConfigFromLists(alertconfig.DefaultTrustedDevAgents, nil)
}

func trustedDevConfigFromEnv() trustedDevConfig {
	return trustedDevConfigFromLists(alertconfig.TrustedDevAgents(), alertconfig.TrustedDevPrincipals())
}

// trustedDevRouteConfig resolves the policy once per event. Tests inject a
// fixed policy on the bridge so their outcome does not depend on the ambient
// environment.
func (b *SecEventBridge) trustedDevRouteConfig() trustedDevConfig {
	if b != nil && b.trustedDev != nil {
		return *b.trustedDev
	}
	return trustedDevConfigFromEnv()
}

func trustedDevConfigFromLists(agents, principals []string) trustedDevConfig {
	cfg := trustedDevConfig{
		Agents:     make(map[string]bool, len(agents)),
		Principals: make(map[string]bool, len(principals)),
	}
	for _, agent := range agents {
		if key := strings.ToLower(strings.TrimSpace(agent)); key != "" {
			cfg.Agents[key] = true
		}
	}
	for _, principal := range principals {
		if key := strings.TrimSpace(principal); key != "" {
			cfg.Principals[key] = true
		}
	}
	return cfg
}

// trustedDevelopmentRoute decides whether an event may be routed to
// observation instead of asking a human to act. It returns false whenever any
// required proof is missing, so the default for an unknown event shape is
// "still needs a human".
func trustedDevelopmentRoute(ev *repository.SecurityEvent, cfg trustedDevConfig) (trustedDevRoute, bool) {
	if ev == nil {
		return trustedDevRoute{}, false
	}
	// 0. Event types the bridge dispositions before this rule runs are not ours
	// to re-decide: the sweep and the live path have to reach the same verdict.
	if trustedDevBridgeHandledTypes[ev.EventType] {
		return trustedDevRoute{}, false
	}
	// 1. Red lines and enforcement actions always keep the actionable bucket:
	// something actually happened to the traffic, or the evidence is a class we
	// never downgrade.
	if isRedline(ev) || isEnforcementAction(ev.ActionTaken) {
		return trustedDevRoute{}, false
	}
	findingsRaw, _ := ev.MatchedSummary["findings"].([]any)
	// 2. The event must prove it came from a coding agent we trust.
	agentCategory, ok := trustedDevAgentCategory(ev, findingsRaw, cfg)
	if !ok {
		return trustedDevRoute{}, false
	}
	// 4. The dominant finding must be a class where context genuinely explains
	// the hit. A missing dominant finding cannot be vetted, so it stays
	// actionable (fail closed).
	dominant := dominantFinding(ev)
	if !trustedDevDominantRoutable(dominant) {
		return trustedDevRoute{}, false
	}
	// 3a. The matched text is machine context, not something the human wrote.
	if marker := trustedDevMachineMarker(dominant); marker != "" {
		return trustedDevRoute{Route: trustedDevRouteName, Reason: marker + "_of_" + agentCategory}, true
	}
	// 3b. Or the operator explicitly named this principal as trusted.
	if key := strings.TrimSpace(ev.PrincipalKey); key != "" && cfg.Principals[key] {
		return trustedDevRoute{Route: trustedDevRouteName, Reason: "trusted_principal_of_" + agentCategory}, true
	}
	return trustedDevRoute{}, false
}

// trustedDevAgentCategory returns the coding-agent category that makes this a
// trusted development context. An agent_detect finding wins over the summary
// field so the reason names the client the detector actually identified.
func trustedDevAgentCategory(ev *repository.SecurityEvent, findingsRaw []any, cfg trustedDevConfig) (string, bool) {
	for _, raw := range findingsRaw {
		fm, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if strings.ToLower(strings.TrimSpace(trustedDevText(fm["rule_type"]))) != "agent_detect" {
			continue
		}
		category := strings.ToLower(strings.TrimSpace(trustedDevText(fm["category"])))
		if cfg.Agents[category] {
			return category, true
		}
	}
	agentType := strings.ToLower(strings.TrimSpace(trustedDevText(ev.MatchedSummary["agent_type"])))
	if cfg.Agents[agentType] {
		return agentType, true
	}
	return "", false
}

// trustedDevDominantRoutable rejects the evidence classes that stay actionable
// regardless of where they were observed.
func trustedDevDominantRoutable(fm map[string]any) bool {
	if fm == nil {
		return false
	}
	if trustedDevNeverRoutedFindingTypes[strings.ToLower(strings.TrimSpace(trustedDevText(fm["type"])))] {
		return false
	}
	category := strings.ToLower(strings.TrimSpace(trustedDevText(fm["category"])))
	if strings.HasPrefix(category, trustedDevCanaryPrefix) || category == trustedDevInjectionCategory {
		return false
	}
	return true
}

// trustedDevMachineMarker returns the content_source (preferred) or message_role
// that proves the hit is machine context, or "" when the finding looks like
// something a human authored.
func trustedDevMachineMarker(fm map[string]any) string {
	if fm == nil {
		return ""
	}
	if source := strings.ToLower(strings.TrimSpace(trustedDevText(fm["content_source"]))); trustedDevMachineSources[source] {
		return source
	}
	if role := strings.ToLower(strings.TrimSpace(trustedDevText(fm["message_role"]))); trustedDevMachineRoles[role] {
		return role
	}
	return ""
}

func trustedDevText(value any) string {
	text, _ := value.(string)
	return text
}
