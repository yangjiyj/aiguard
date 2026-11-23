package agentguardmatch

import "strings"

// ClassifyToolType is the canonical name classifier shared by observed inventory
// and gateway dispatch. Names identify an analyzer family, never a risk verdict.
func ClassifyToolType(name string) string {
	normalized := strings.ToLower(strings.TrimSpace(name))
	switch normalized {
	case "skill", "use_skill", "use-skill", "useskill", "load_skill", "load-skill", "loadskill", "activate_skill", "activate-skill", "activateskill":
		return "skill"
	}
	if strings.HasPrefix(normalized, "skills/") || strings.HasPrefix(normalized, "skill/") || strings.HasPrefix(normalized, "skill__") {
		return "skill"
	}
	if strings.HasPrefix(normalized, "mcp__") || strings.HasPrefix(normalized, "mcp/") {
		return "mcp"
	}
	switch normalized {
	case "exec_command", "shell", "local_shell", "local_shell_call", "shell_command", "run_shell", "write_stdin":
		return "system"
	case "view_image", "read_file", "apply_patch":
		return "file"
	case "spawn_agent", "wait", "sleep", "request_user_input_async":
		return "unknown"
	}
	containsAny := func(fragments ...string) bool {
		for _, fragment := range fragments {
			if strings.Contains(normalized, fragment) {
				return true
			}
		}
		return false
	}
	if containsAny("read", "write", "edit", "file", "glob", "listfiles", "deletefile", "mkdir", "copyfile", "movefile") {
		return "file"
	}
	if containsAny("http", "fetch", "request", "curl", "wget", "download", "upload", "websearch", "webfetch", "browser", "open_url", "send_data", "egress", "exfil") {
		return "network"
	}
	if containsAny("query", "sql", "database", "postgres", "mysql", "sqlite") {
		return "database"
	}
	if containsAny("bash", "shell", "execute", "command", "process", "sudo", "docker") || normalized == "run" || strings.HasPrefix(normalized, "run_") {
		return "system"
	}
	return "unknown"
}

// ResolveObservedToolType uses only authenticated current configuration and
// canonical names. Old event classifications and missing schemas are unverified.
func ResolveObservedToolType(name, configured string) (toolType, source string) {
	byName := ClassifyToolType(name)
	if byName == "skill" || byName == "mcp" {
		return byName, "name_classification"
	}
	configured = strings.ToLower(strings.TrimSpace(configured))
	switch configured {
	case "file", "network", "database", "system", "mcp":
		return configured, "configured_mapping"
	}
	if byName != "unknown" {
		return byName, "name_classification"
	}
	return "unknown", "unverified"
}
