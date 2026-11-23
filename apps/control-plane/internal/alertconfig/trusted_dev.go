package alertconfig

import (
	"os"
	"strings"
)

// DefaultTrustedDevAgents is the shipped encoder-agent inventory. A security
// event only counts as a trusted development context when it can prove the
// traffic came from one of these clients (an agent_detect finding with a
// matching category, or matched_summary.agent_type).
var DefaultTrustedDevAgents = []string{
	"agent_claude_code",
	"agent_openai_codex",
	"agent_workbuddy",
	"agent_cursor",
	"agent_opencode",
	"agent_codebuddy",
	"agent_copilot",
	"agent_cline",
}

// TrustedDevAgents returns the agent inventory, overridable with
// SECEVENT_TRUSTED_DEV_AGENTS so a customer running a client we do not ship a
// category for can still be covered without a release.
func TrustedDevAgents() []string {
	return commaList("SECEVENT_TRUSTED_DEV_AGENTS", DefaultTrustedDevAgents)
}

// TrustedDevPrincipals returns the principal keys (user id / key id /
// upstream:…) that may be routed even when the dominant finding is not machine
// context. Empty by default: naming a principal is a deliberate act, and the
// list is the only way to relax the machine-context requirement.
func TrustedDevPrincipals() []string {
	return commaList("SECEVENT_TRUSTED_DEV_PRINCIPALS", nil)
}

// commaList reads a comma-separated override. An unset or blank variable keeps
// the fallback; an explicitly set-but-empty list (e.g. ",") yields an empty
// list, which is how an operator disables an override they no longer want.
func commaList(name string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return append([]string(nil), fallback...)
	}
	items := make([]string, 0, 8)
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}
