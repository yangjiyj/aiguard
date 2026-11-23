package handler

import (
	"sort"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
)

func validIntegrationAgentFilter(id string) bool { return ai.ValidID(id) }

func connectorRiskCategory(e *repository.SecurityEvent) string {
	for _, finding := range connectorRiskFindings(e) {
		if !connectorFindingCounts(finding) {
			continue
		}
		for _, key := range []string{"category", "type", "policy_scene"} {
			label, _ := finding[key].(string)
			if category, _ := connectorRiskLabel(label); category != "" {
				return category
			}
		}
	}
	return ""
}

func connectorRiskFactors(e *repository.SecurityEvent) []string {
	set := map[string]bool{}
	for _, finding := range connectorRiskFindings(e) {
		if !connectorFindingCounts(finding) {
			continue
		}
		for _, key := range []string{"type", "category", "policy_scene"} {
			label, _ := finding[key].(string)
			_, factors := connectorRiskLabel(label)
			for _, factor := range factors {
				set[factor] = true
			}
		}
	}
	factors := make([]string, 0, len(set))
	for factor := range set {
		factors = append(factors, factor)
	}
	sort.Strings(factors)
	return factors
}

// Presence is authoritative: observation-only or malformed findings must not
// regain risk through the primary finding, summary bucket, or event type.
func connectorRiskFindings(e *repository.SecurityEvent) []map[string]any {
	if raw, present := e.MatchedSummary["findings"]; present {
		switch findings := raw.(type) {
		case []map[string]any:
			return findings
		case []any:
			out := make([]map[string]any, 0, len(findings))
			for _, raw := range findings {
				if finding, ok := raw.(map[string]any); ok {
					out = append(out, finding)
				}
			}
			return out
		default:
			return nil
		}
	}
	if raw, present := e.MatchedSummary["primary_finding"]; present {
		if finding, ok := raw.(map[string]any); ok {
			return []map[string]any{finding}
		}
		return nil
	}
	for _, key := range []string{"category", "rule_type", "policy_scene", "counts_as_security_finding"} {
		if _, present := e.MatchedSummary[key]; present {
			return []map[string]any{{"category": e.MatchedSummary["category"], "type": e.MatchedSummary["rule_type"], "policy_scene": e.MatchedSummary["policy_scene"], "counts_as_security_finding": connectorLegacyFindingCounts(e.MatchedSummary)}}
		}
	}
	return []map[string]any{{"type": e.EventType}}
}

func connectorLegacyFindingCounts(finding map[string]any) any {
	if value, present := finding["counts_as_security_finding"]; present {
		return value
	}
	return true
}

func connectorFindingCounts(finding map[string]any) bool {
	if value, present := finding["counts_as_security_finding"]; present {
		counts, valid := value.(bool)
		return valid && counts
	}
	return true
}

// Map finite trusted type/category/scene labels only. Fine native categories
// inherit their detector type; unknown prefixes and event prose carry no risk.
func connectorRiskLabel(label string) (string, []string) {
	switch label {
	case "prompt_injection", "indirect_prompt_injection", "indirect_injection", "direct_injection", "jailbreak", "semantic_jailbreak", "mcp_tool_result_injection",
		"semantic_instruction_override", "semantic_roleplay":
		return "prompt_injection", []string{"prompt_injection"}
	// 语义判官“数据外泄诱导”：诱导把数据发往外部/未授权接收方，同时属于注入与外发风险。
	case "semantic_exfil_induce":
		return "data_leak", []string{"data_exfiltration", "prompt_injection"}
	case "indirect_private_data_exfil":
		return "prompt_injection", []string{"prompt_injection", "data_exfiltration", "dangerous_capability"}
	case "pii", "data_leak":
		return label, []string{"data_exfiltration", "dangerous_capability"}
	case "sensitive_data", "data_security", "data_exfiltration", "sensitive_data_exfiltration", "data_leakage":
		return "data_leak", []string{"data_exfiltration", "dangerous_capability"}
	case "secret", "credential_leak":
		return label, []string{"credential_exposure", "dangerous_capability"}
	case "code_config", "credential_theft", "credential_stealing", "credential_exposure":
		return "secret", []string{"credential_exposure", "dangerous_capability"}
	case "code_leak_password_in_code", "code_leak_access_key", "code_leak_database_url", "code_leak_api_key_leak", "code_leak_token_leak", "code_leak_cloud_credential":
		return "data_leak", []string{"data_exfiltration", "credential_exposure", "dangerous_capability"}
	case "tool_poisoning", "mcp_description_poison", "mcp_description_poison_semantic":
		return "tool_poisoning", []string{"prompt_injection", "dangerous_capability", "supply_chain"}
	case "mcp_supply_chain", "tool_definition_drift", "mcp_tools_list_drift", "supply_chain":
		return "dangerous_capability", []string{"dangerous_capability", "supply_chain"}
	case "mcp_policy", "agent_tool_abuse", "restricted_file_access":
		return label, []string{"dangerous_capability"}
	case "dangerous_capability", "unauthorized_tool_call", "unauthorized_tool", "high_risk_command", "destructive_change", "tool_destructive_intent", "tool_attempt_blocked", "tool_execution_risk", "mcp_server_request_blocked":
		return "dangerous_capability", []string{"dangerous_capability"}
	case "resource_exhaustion", "dos_resource_exhaustion_instruction", "infinite_loop", "unattended_automation":
		return "resource_exhaustion", []string{"unattended_automation", "dangerous_capability"}
	case "unapproved_model_egress", "model_access", "unauthorized_model":
		return "unapproved_model_egress", []string{"unapproved_model_egress"}
	case "identity_spoofing", "shadow_agent":
		return "identity_spoofing", []string{"shadow_agent"}
	default:
		return "", nil
	}
}
