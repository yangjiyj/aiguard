package agentintent

import (
	"errors"
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
)

var (
	ErrUnsupportedAuthorizationEffect = errors.New("unsupported or ambiguous authorization effect")
	mcpTaskIdentityPattern            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type AuthorizationEffect struct {
	Action       string
	ResourceType string
	ResourceID   string
}

// DeriveT16AuthorizationFacets implements the finite T14 effect surface used
// by T16. It accepts only exact tool names and unambiguous argument shapes.
// The raw arguments are used only in memory; callers must persist their digest,
// not the path or URL returned here.
func DeriveT16AuthorizationFacets(product, toolName, toolType, mcpServer string, args map[string]any) (AuthorizationEffect, []AuthorizationFacet, error) {
	product = strings.TrimSpace(product)
	toolName = strings.TrimSpace(toolName)
	toolType = strings.ToLower(strings.TrimSpace(toolType))
	if product != "claude-code" && product != "openclaw" && product != "opencode" || toolName == "" || len(toolName) > 255 || len(args) > 32 {
		return AuthorizationEffect{}, nil, ErrUnsupportedAuthorizationEffect
	}

	var effect AuthorizationEffect
	server := strings.TrimSpace(mcpServer)
	parts := strings.Split(toolName, "__")
	isCanonicalMCPName := len(parts) == 3 && parts[0] == "mcp" &&
		mcpTaskIdentityPattern.MatchString(parts[1]) && mcpTaskIdentityPattern.MatchString(parts[2])
	if isCanonicalMCPName || toolType == "mcp" || server != "" {
		if !isCanonicalMCPName || server != parts[1] {
			return AuthorizationEffect{}, nil, ErrUnsupportedAuthorizationEffect
		}
		var err error
		effect, err = deriveMCPAuthorizationEffect(parts[2], args)
		if err != nil {
			return AuthorizationEffect{}, nil, err
		}
		expectedToolType := "file"
		if effect.Action == "network.connect" {
			expectedToolType = "network"
		}
		if toolType != expectedToolType {
			return AuthorizationEffect{}, nil, ErrUnsupportedAuthorizationEffect
		}
	} else {
		var err error
		effect, err = deriveDirectAuthorizationEffect(product, toolName, toolType, args)
		if err != nil {
			return AuthorizationEffect{}, nil, err
		}
	}
	if effect.Action == "" || effect.ResourceType == "" || effect.ResourceID == "" {
		return AuthorizationEffect{}, nil, ErrUnsupportedAuthorizationEffect
	}
	facets := []AuthorizationFacet{{Action: "tool_execute", ResourceType: "tool", ResourceID: toolName}}
	if server != "" {
		facets = append(facets, AuthorizationFacet{Action: "mcp_invoke", ResourceType: "mcp_server", ResourceID: server})
	}
	facets = append(facets, AuthorizationFacet{Action: t13AuthorizationAction(effect.Action), ResourceType: effect.ResourceType, ResourceID: effect.ResourceID})
	return effect, facets, nil
}

func deriveDirectAuthorizationEffect(product, name, toolType string, args map[string]any) (AuthorizationEffect, error) {
	if toolType == "file" {
		action := ""
		switch product {
		case "claude-code":
			switch name {
			case "Read":
				action = "file.read"
			case "Write", "Edit", "MultiEdit", "NotebookEdit":
				action = "file.write"
			case "LS":
				action = "directory.list"
			}
		case "openclaw":
			switch name {
			case "read":
				action = "file.read"
			case "write", "edit":
				action = "file.write"
			}
		case "opencode":
			switch name {
			case "read":
				action = "file.read"
			case "write", "edit", "multiedit":
				action = "file.write"
			case "list":
				action = "directory.list"
			}
		}
		if action == "" {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		allowed := map[string]bool{"path": true, "file_path": true, "filepath": true, "notebook_path": true, "directory": true, "folder": true, "paths": true, "file_paths": true}
		if action == "file.write" {
			allowed["content"], allowed["text"], allowed["data"] = true, true, true
		}
		if action == "directory.list" {
			allowed["limit"], allowed["offset"] = true, true
		}
		if !onlyAuthorizationKeys(args, allowed) {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		resource, ok := oneAuthorizationPath(args, []string{"path", "file_path", "filepath", "notebook_path", "directory", "folder", "paths", "file_paths"})
		if !ok {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		typeName := "file"
		if action == "directory.list" {
			typeName = "directory"
		}
		return AuthorizationEffect{Action: action, ResourceType: typeName, ResourceID: resource}, nil
	}
	if toolType == "network" && ((product == "claude-code" && name == "WebFetch") || (product == "openclaw" && name == "web_fetch") || (product == "opencode" && name == "webfetch")) {
		allowed := map[string]bool{"url": true}
		if !onlyAuthorizationKeys(args, allowed) {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		value, ok := args["url"].(string)
		if !ok {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		host, ok := authorizationURLHost(value)
		if !ok {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		return AuthorizationEffect{Action: "network.connect", ResourceType: "domain", ResourceID: host}, nil
	}
	return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
}

func deriveMCPAuthorizationEffect(suffix string, args map[string]any) (AuthorizationEffect, error) {
	switch suffix {
	case "read_file", "get_file", "file_read":
		if !onlyAuthorizationKeys(args, map[string]bool{"file_path": true, "filepath": true, "notebook_path": true, "path": true, "directory": true, "folder": true, "paths": true, "file_paths": true}) {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		resource, ok := oneAuthorizationPath(args, []string{"file_path", "filepath", "notebook_path", "path", "directory", "folder", "paths", "file_paths"})
		if !ok {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		return AuthorizationEffect{Action: "file.read", ResourceType: "file", ResourceID: resource}, nil
	case "write_file", "edit_file", "create_file", "file_write":
		allowed := map[string]bool{"file_path": true, "filepath": true, "notebook_path": true, "path": true, "directory": true, "folder": true, "paths": true, "file_paths": true,
			"content": true, "text": true, "value": true, "old_string": true, "new_string": true}
		if !onlyAuthorizationKeys(args, allowed) {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		resource, ok := oneAuthorizationPath(args, []string{"file_path", "filepath", "notebook_path", "path", "directory", "folder", "paths", "file_paths"})
		if !ok {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		payloadKeys := []string{}
		for key, value := range args {
			switch strings.ToLower(key) {
			case "content", "text", "value", "old_string", "new_string":
				text, ok := value.(string)
				if !ok || len(text) > 16<<10 {
					return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
				}
				payloadKeys = append(payloadKeys, strings.ToLower(key))
			}
		}
		validPayload := len(payloadKeys) == 1
		if len(payloadKeys) == 2 {
			validPayload = (payloadKeys[0] == "old_string" && payloadKeys[1] == "new_string") ||
				(payloadKeys[0] == "new_string" && payloadKeys[1] == "old_string")
		}
		if !validPayload {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		return AuthorizationEffect{Action: "file.write", ResourceType: "file", ResourceID: resource}, nil
	case "list_directory", "list_files", "directory_list":
		if !onlyAuthorizationKeys(args, map[string]bool{"file_path": true, "filepath": true, "notebook_path": true, "path": true, "directory": true, "folder": true, "paths": true, "file_paths": true, "limit": true, "offset": true}) {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		resource, ok := oneAuthorizationPath(args, []string{"file_path", "filepath", "notebook_path", "path", "directory", "folder", "paths", "file_paths"})
		if !ok {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		if !validOptionalAuthorizationInt(args, "limit") || !validOptionalAuthorizationInt(args, "offset") {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		return AuthorizationEffect{Action: "directory.list", ResourceType: "directory", ResourceID: resource}, nil
	case "web_fetch", "fetch_url", "http_request", "network_connect":
		if !onlyAuthorizationKeys(args, map[string]bool{"url": true, "method": true, "headers": true, "body": true}) {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		value, ok := args["url"].(string)
		if !ok {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		if method, exists := args["method"]; exists {
			if _, ok := method.(string); !ok {
				return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
			}
		}
		if body, exists := args["body"]; exists {
			text, ok := body.(string)
			if !ok || len(text) > 16<<10 {
				return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
			}
		}
		if headers, exists := args["headers"]; exists {
			values, ok := headers.(map[string]any)
			if !ok || len(values) > 32 {
				return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
			}
			for key, item := range values {
				text, ok := item.(string)
				if !ok || len(key) > 128 || len(text) > 2048 {
					return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
				}
			}
		}
		host, ok := authorizationURLHost(value)
		if !ok {
			return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
		}
		return AuthorizationEffect{Action: "network.connect", ResourceType: "domain", ResourceID: host}, nil
	default:
		return AuthorizationEffect{}, ErrUnsupportedAuthorizationEffect
	}
}

func t13AuthorizationAction(action string) string {
	switch action {
	case "file.read":
		return "file_read"
	case "file.write":
		return "file_write"
	case "directory.list":
		return "directory_list"
	case "network.connect":
		return "network_connect"
	default:
		return ""
	}
}

func onlyAuthorizationKeys(args map[string]any, allowed map[string]bool) bool {
	for key := range args {
		if !allowed[strings.ToLower(strings.TrimSpace(key))] {
			return false
		}
	}
	return true
}

func oneAuthorizationPath(args map[string]any, aliases []string) (string, bool) {
	selected := ""
	found := false
	for key, value := range args {
		matched := false
		for _, alias := range aliases {
			if strings.EqualFold(key, alias) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if found {
			return "", false
		}
		found = true
		switch typed := value.(type) {
		case string:
			selected = typed
		case []any:
			if len(typed) != 1 {
				return "", false
			}
			selected, _ = typed[0].(string)
		case []string:
			if len(typed) != 1 {
				return "", false
			}
			selected = typed[0]
		default:
			return "", false
		}
	}
	if !found || !safeAuthorizationPath(selected) {
		return "", false
	}
	return selected, true
}

func safeAuthorizationPath(value string) bool {
	if value == "" || len(value) > maxT13AuthorizationResourceID || !path.IsAbs(value) || path.Clean(value) != value || strings.ContainsAny(value, "*?${}") || strings.ContainsRune(value, 0) {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) || unicode.IsSpace(char) {
			return false
		}
	}
	return true
}

// maxT13AuthorizationResourceID mirrors the T13 server and hookd resource
// bound; a longer path can never have a matching persisted T13 decision.
const maxT13AuthorizationResourceID = 256

// authorizationURLHost mirrors hookd's trusted T14 host extraction exactly so
// the pre-execution idempotency key GW recomputes is the one hookd authorized.
func authorizationURLHost(value string) (string, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "", false
	}
	if _, err := url.ParseRequestURI(value); err != nil {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if net.ParseIP(host) == nil {
		host = strings.TrimSuffix(host, ".")
		if !validAuthorizationDomain(host) {
			return "", false
		}
	}
	if len(host) > maxT13AuthorizationResourceID {
		return "", false
	}
	return host, true
}

func validAuthorizationDomain(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}

func validOptionalAuthorizationInt(args map[string]any, key string) bool {
	value, exists := args[key]
	if !exists {
		return true
	}
	switch typed := value.(type) {
	case int:
		return typed >= 0 && typed <= 1_000_000
	case int64:
		return typed >= 0 && typed <= 1_000_000
	case float64:
		return typed >= 0 && typed <= 1_000_000 && typed == float64(int64(typed))
	default:
		return false
	}
}
