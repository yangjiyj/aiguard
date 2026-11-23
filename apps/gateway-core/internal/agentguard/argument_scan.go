package agentguard

import (
	"net/url"
	"sort"
	"strings"
)

// W5 5.8: analyzers used to read only fixed argument keys (url/path/body…),
// so a tool that names its field "location" or nests it under "options" was
// never inspected. collectStringArguments walks every string argument
// (bounded) so target and secret checks see all of them.

const (
	maxScannedArgumentDepth  = 6
	maxScannedArgumentValues = 256
	maxScannedArgumentLength = 16 << 10
)

type scannedArgument struct {
	Path  string
	Value string
}

// collectStringArguments returns every string leaf in args in a stable
// order (sorted keys, array order), up to the scan bounds.
func collectStringArguments(args map[string]any) []scannedArgument {
	out := make([]scannedArgument, 0, 8)
	var walk func(prefix string, value any, depth int)
	walk = func(prefix string, value any, depth int) {
		if len(out) >= maxScannedArgumentValues || depth > maxScannedArgumentDepth {
			return
		}
		switch typed := value.(type) {
		case string:
			text := strings.TrimSpace(typed)
			if text == "" {
				return
			}
			if len(text) > maxScannedArgumentLength {
				text = text[:maxScannedArgumentLength]
			}
			out = append(out, scannedArgument{Path: prefix, Value: text})
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				child := key
				if prefix != "" {
					child = prefix + "." + key
				}
				walk(child, typed[key], depth+1)
			}
		case []any:
			for _, item := range typed {
				walk(prefix+"[]", item, depth+1)
			}
		case []string:
			for _, item := range typed {
				walk(prefix+"[]", item, depth+1)
			}
		}
	}
	walk("", args, 0)
	return out
}

// looksLikeURLArgument reports an absolute http(s)/ftp/ws URL.
func looksLikeURLArgument(value string) bool {
	if strings.ContainsAny(value, " \n\t") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "ftp", "ws", "wss":
		return true
	default:
		return false
	}
}

// shellNoteKeys are the free-text fields an agent attaches to a shell call to
// explain it (Claude Code Bash "description"). They are never executed or
// opened, so prose such as "List ~/.ssh and check git credential helper" is
// not a path.
var shellNoteKeys = map[string]bool{"description": true, "title": true, "summary": true, "explanation": true}

// builtinFreeTextArguments are the free-text arguments of built-in agent
// tools (Claude Code, CodeBuddy/Cline): replacement text, file content,
// search patterns, prompts and to-do items. They are never
// opened as files, so they are not judged as paths (design section 6); the
// fixed path arguments (file_path, path ...) still are. The table applies to
// built-in tools only: every argument of an MCP tool (isMCPToolCall), also
// one named write_file or edit_file, is still scanned.
var builtinFreeTextArguments = map[string]map[string]bool{
	"edit":          {"old_string": true, "new_string": true},
	"multiedit":     {"edits[].old_string": true, "edits[].new_string": true},
	"write":         {"content": true},
	"write_to_file": {"content": true},
	// The other file-writing tools of fileWriteToolNames (Cline, Gemini CLI,
	// the MCP filesystem server, Copilot): their content is not a path either.
	"replace_in_file": {"diff": true},
	"write_file":      {"content": true},
	"edit_file":       {"edits[].oldText": true, "edits[].newText": true, "old_string": true, "new_string": true},
	"create_file":     {"content": true},
	"notebookedit":    {"new_source": true},
	"grep":            {"pattern": true},
	"glob":            {"pattern": true},
	"search_files":    {"regex": true},
	"task":            {"prompt": true, "description": true},
	// Claude Code 的 Agent（Task 的新名字）与 SendMessage：给子代理的自然语言说明。
	"agent":       {"prompt": true, "description": true},
	"sendmessage": {"message": true, "summary": true},
	"todowrite":   {"todos[].content": true, "todos[].activeForm": true},
	"webfetch":    {"prompt": true},
}

func isBuiltinFreeTextArgument(toolName, path string) bool {
	return builtinFreeTextArguments[strings.ToLower(strings.TrimSpace(toolName))][path]
}

// analyzeAllArgumentTargets runs AnalyzeTarget on every URL-like (network) or
// path-like (file) string argument not already covered by the fixed keys and
// returns every sensitive-target hit merged into one finding (the first hit
// leads; all hits are kept in ProtectionHits so the strictest configured item
// decides).
//
// shellCommands are the command texts of a shell-type call. They are judged
// word by word (analyzeShellCommandTargets) instead of as a single path, and
// the argument holding one is not re-read as a path. A top-level note field
// of such a call whose text contains whitespace is not read as a path either.
func analyzeAllArgumentTargets(toolName string, args map[string]any, kind TargetKind, alreadyChecked string, mcp bool, shellCommands ...string) (Decision, bool) {
	commandArgument := map[string]bool{}
	var merged Decision
	found := false
	add := func(next Decision) {
		if !found {
			merged, found = next, true
			return
		}
		merged = mergeAnalyzerDecision(merged, next)
	}
	if kind == TargetFile {
		for _, command := range shellCommands {
			commandArgument[strings.TrimSpace(command)] = true
			if decision, hit := analyzeShellCommandTargets(command); hit {
				decision.Evidence = withArgumentSource(decision.Evidence, "command")
				add(decision)
			}
		}
	}
	for _, argument := range collectStringArguments(args) {
		if argument.Value == alreadyChecked || commandArgument[argument.Value] {
			continue
		}
		switch kind {
		case TargetURL:
			if !looksLikeURLArgument(argument.Value) {
				continue
			}
		case TargetFile:
			if strings.ContainsAny(argument.Value, "\n") || !looksLikeFileTarget(argument.Value) || looksLikeURLArgument(argument.Value) {
				continue
			}
			if len(shellCommands) > 0 && shellNoteKeys[strings.ToLower(argument.Path)] && strings.ContainsAny(argument.Value, " \t") {
				continue
			}
			if !mcp && isBuiltinFreeTextArgument(toolName, argument.Path) {
				continue
			}
		}
		target := AnalyzeTarget(argument.Value)
		if !target.Hit || target.Kind != kind {
			continue
		}
		risk := "critical"
		if kind == TargetURL {
			risk = targetRiskLevel(target)
		}
		add(targetFinding(target, argument.Value, risk, 0.9, withArgumentSource(target.Evidence, argument.Path)))
	}
	return merged, found
}

// allArgumentText joins every string argument except the destination so the
// secret detector sees payloads stored under any key.
func allArgumentText(args map[string]any, exclude string) string {
	parts := make([]string, 0, 4)
	for _, argument := range collectStringArguments(args) {
		if argument.Value == exclude {
			continue
		}
		parts = append(parts, argument.Value)
	}
	return strings.Join(parts, "\n")
}

// firstURLArgument returns the first URL-like string argument.
func firstURLArgument(args map[string]any) string {
	for _, argument := range collectStringArguments(args) {
		if looksLikeURLArgument(argument.Value) {
			return argument.Value
		}
	}
	return ""
}

func withArgumentSource(evidence []Evidence, path string) []Evidence {
	out := make([]Evidence, len(evidence))
	copy(out, evidence)
	for i := range out {
		if path != "" {
			out[i].SourceField = path
		}
	}
	return out
}
