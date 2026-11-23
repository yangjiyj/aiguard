package agentendpoint

import "github.com/yangjiyj/aiguard/packages/shared-go/protection"

// RE2-only subset of high-confidence signatures in gateway-core analyzers.go.
// Entropy-dependent detection and PII are not equivalent to regex-only matching.
func BuiltinSecretPatterns() []SecretPattern {
	return []SecretPattern{
		{"aws_access_key_id", `\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`},
		{"private_key", `-----BEGIN [A-Z ]*PRIVATE KEY-----`},
		{"github_token", `\bgh[pousr]_[A-Za-z0-9_]{36,}\b`},
		{"openai_api_key", `\bsk-[A-Za-z0-9_-]{32,}\b`},
		{"canary_token", `\bcanary-[A-Za-z0-9_-]*(?:token|secret|credential)[A-Za-z0-9_-]*\b`},
	}
}

// Command signatures are directly sourced from analyzers.go; the endpoint
// evaluator applies command_regex only to args_summary.command.
func BuiltinRules() []Rule {
	return []Rule{
		{ID: "builtin_destructive_rm", Match: Match{ToolType: "system", CommandRegex: `(?i)(?:^|[;&|]\s*)rm\s+(?:-[a-z]*r[a-z]*\s+)+/(?:\s|$|\*)`}, Decision: "confirm", Risk: "high", Enabled: true},
		{ID: "builtin_destructive_system", Match: Match{ToolType: "system", CommandRegex: `(?i)(?:^|[;&|]\s*)(?:mkfs(?:\.[a-z0-9]+)?|shutdown|reboot)(?:\s|$)`}, Decision: "confirm", Risk: "high", Enabled: true},
		{ID: "builtin_destructive_dd", Match: Match{ToolType: "system", CommandRegex: `(?i)(?:^|[;&|]\s*)dd\s+[^;&|]*\bof=/dev/`}, Decision: "confirm", Risk: "high", Enabled: true},
		{ID: "builtin_secret_arguments", Match: Match{ArgsSecretPattern: true}, Decision: "confirm", Risk: "high", Enabled: true},
		{ID: "builtin_ssh_authorized_keys", Match: Match{ToolType: "file", PathGlob: []string{"**/.ssh/authorized_keys", "~/.ssh/authorized_keys"}}, Decision: "confirm", Risk: "high", Enabled: true},
		{ID: "builtin_ssh_private_keys", Match: Match{ToolType: "file", PathGlob: []string{"**/.ssh/id_*", "~/.ssh/id_*"}}, Decision: "confirm", Risk: "high", Enabled: true},
		{ID: "builtin_env_files", Match: Match{ToolType: "file", PathGlob: []string{"**/.env", "**/.env.*", ".env", ".env.*"}}, Decision: "confirm", Risk: "high", Enabled: true},
		{ID: "builtin_curl_file_egress", Match: Match{ToolType: "system", CommandRegex: `(?i)(?:^|[;&|]\s*)curl\s+[^;&|]*(?:-d|--data|--data-binary|--data-raw|--data-urlencode)\s+['"]?@[^\s;&|]+`}, Decision: "confirm", Risk: "high", Enabled: true},
	}
}

// BuiltinRulesFor 按租户的防护项 endpoint.rule.<规则 ID> 给 8 条端侧内置规则定动作（2.9.22）：
// 仅记录 → allow、告警放行（默认）→ audit：hookd 本地按 allow < audit < confirm < block 取最严命中，
// 只有阻断（Skill 还有确认）在本地拦，allow、audit 都不拦、命中照常上报，告警与否由网关 decide 按
// 防护项定；确认、阻断 → 照原语义。规则一律启用（注册表四档没有“停用”），匹配条件不变。
func BuiltinRulesFor(settings protection.Settings) []Rule {
	rules := BuiltinRules()
	for i := range rules {
		switch settings.ActionFor(protection.EndpointRuleKey(rules[i].ID)) {
		case protection.ActionRecord:
			rules[i].Decision = "allow"
		case protection.ActionConfirm:
			rules[i].Decision = "confirm"
		case protection.ActionBlock:
			rules[i].Decision = "block"
		default:
			rules[i].Decision = "audit"
		}
	}
	return rules
}
