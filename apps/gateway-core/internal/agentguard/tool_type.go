package agentguard

import (
	"encoding/json"
	"strings"
)

// W5 5.9: a tool with a custom name ("acme_sync") used to fall into
// "unknown" and skip every type analyzer. InferToolTypeFromSchema reads the
// tool's JSON-schema parameter names and picks the analyzer family.

var schemaTypeHints = []struct {
	toolType string
	keys     []string
}{
	{ToolTypeSystem, []string{"command", "cmd", "argv", "shell", "script", "executable"}},
	{ToolTypeDatabase, []string{"sql", "query_sql", "statement", "database", "db"}},
	{ToolTypeNetwork, []string{"url", "uri", "endpoint", "webhook", "href", "host"}},
	{ToolTypeFile, []string{"path", "file_path", "filepath", "file", "filename", "directory", "dir"}},
}

// InferToolTypeFromSchema returns the tool type implied by the parameter
// names of a JSON schema, or "" when nothing is conclusive.
func InferToolTypeFromSchema(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return ""
	}
	names := map[string]bool{}
	collectSchemaPropertyNames(schema, names, 0)
	for _, hint := range schemaTypeHints {
		for _, key := range hint.keys {
			if names[key] {
				return hint.toolType
			}
		}
	}
	return ""
}

func collectSchemaPropertyNames(schema map[string]any, names map[string]bool, depth int) {
	if depth > 4 || len(names) > 256 {
		return
	}
	properties, _ := schema["properties"].(map[string]any)
	for name, child := range properties {
		names[strings.ToLower(strings.TrimSpace(name))] = true
		if nested, ok := child.(map[string]any); ok {
			collectSchemaPropertyNames(nested, names, depth+1)
			if items, ok := nested["items"].(map[string]any); ok {
				collectSchemaPropertyNames(items, names, depth+1)
			}
		}
	}
}

// Generic MCP names have no schema in the call payload. Analyze every family
// represented by its arguments so a command field cannot hide an egress URL.
func inferArgumentToolTypes(arguments map[string]any) []string {
	names := map[string]bool{}
	var collect func(any, int)
	collect = func(value any, depth int) {
		if depth > 4 || len(names) > 256 {
			return
		}
		switch item := value.(type) {
		case map[string]any:
			for key, child := range item {
				names[strings.ToLower(strings.TrimSpace(key))] = true
				collect(child, depth+1)
			}
		case []any:
			for _, child := range item {
				collect(child, depth+1)
			}
		}
	}
	collect(arguments, 0)
	var toolTypes []string
	for _, hint := range schemaTypeHints {
		for _, key := range hint.keys {
			if names[key] {
				toolTypes = append(toolTypes, hint.toolType)
				break
			}
		}
	}
	return toolTypes
}

// ValidConfiguredToolType reports a tool type an administrator may map a
// tool to in the console.
func ValidConfiguredToolType(toolType string) bool {
	switch strings.ToLower(strings.TrimSpace(toolType)) {
	case ToolTypeFile, ToolTypeNetwork, ToolTypeDatabase, ToolTypeSystem, ToolTypeMCP:
		return true
	default:
		return false
	}
}

// ResolveToolType applies the W5 5.9 precedence: skill/MCP identified by name
// (supply-chain gating must not be bypassed), then the explicit console
// mapping, then the name heuristics, then schema inference.
func ResolveToolType(name, configured, schemaInferred string) string {
	byName := ClassifyToolType(name)
	if byName == ToolTypeSkill || byName == ToolTypeMCP {
		return byName
	}
	if ValidConfiguredToolType(configured) {
		return strings.ToLower(strings.TrimSpace(configured))
	}
	if byName != ToolTypeUnknown {
		return byName
	}
	if schemaInferred != "" {
		return schemaInferred
	}
	return ToolTypeUnknown
}
