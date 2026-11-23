package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
)

const (
	maxAgentOperationPolicyBodyBytes = 32 << 10
	maxAgentOperationScopeRefLength  = 128
	maxAgentOperationTenantIDLength  = 128
	maxAgentOperationPaths           = 32
	maxAgentOperationPathLength      = 256
	maxAgentOperationPathDepth       = 8
	maxAgentOperationChannelIDs      = 16
	maxAgentOperationChannelIDLength = 128
)

type agentOperationPolicyRequest struct {
	TenantScope            string   `json:"tenant_scope,omitempty"`
	TenantID               string   `json:"tenant_id,omitempty"`
	ScopeType              string   `json:"scope_type"`
	ScopeRef               string   `json:"scope_ref"`
	Mode                   string   `json:"mode"`
	Action                 string   `json:"action"`
	Protocol               string   `json:"protocol,omitempty"`
	DiscardablePaths       []string `json:"discardable_paths"`
	NotifyChannelIDs       []string `json:"notify_channel_ids"`
	RestrictedFilePatterns []string `json:"restricted_file_patterns,omitempty"`
	RestrictedFileAction   string   `json:"restricted_file_action,omitempty"`
	Version                int64    `json:"version"`
}

func decodeAgentOperationPolicyRequest(body io.Reader) (agentOperationPolicyRequest, error) {
	var req agentOperationPolicyRequest
	limited := io.LimitReader(body, maxAgentOperationPolicyBodyBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return req, fmt.Errorf("read request body: %w", err)
	}
	if len(raw) > maxAgentOperationPolicyBodyBytes {
		return req, fmt.Errorf("request body exceeds %d bytes", maxAgentOperationPolicyBodyBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, fmt.Errorf("invalid request body: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return req, err
	}
	if string(raw) == "null" {
		return req, fmt.Errorf("request body must be an object")
	}
	req.ScopeType = strings.ToLower(strings.TrimSpace(req.ScopeType))
	req.ScopeRef = strings.TrimSpace(req.ScopeRef)
	req.TenantScope = strings.ToLower(strings.TrimSpace(req.TenantScope))
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantScope != "" && req.TenantScope != "all" && req.TenantScope != "tenant" {
		return req, fmt.Errorf("tenant_scope must be all or tenant")
	}
	if len(req.TenantID) > maxAgentOperationTenantIDLength || strings.ContainsRune(req.TenantID, '\x00') {
		return req, fmt.Errorf("invalid tenant_id")
	}
	if req.TenantScope == "all" && req.TenantID != "" {
		return req, fmt.Errorf("tenant_id is not allowed for all tenants")
	}
	req.Mode = strings.ToLower(strings.TrimSpace(req.Mode))
	if req.Mode == "observe" {
		req.Mode = "audit"
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	req.Protocol = strings.ToLower(strings.TrimSpace(req.Protocol))
	if req.ScopeType != "tenant" && req.ScopeType != "application" && req.ScopeType != "agent" {
		return req, fmt.Errorf("scope_type must be tenant, application, or agent")
	}
	if (req.ScopeType == "tenant" && req.ScopeRef != "") || (req.ScopeType != "tenant" && req.ScopeRef == "") {
		return req, fmt.Errorf("scope_ref does not match scope_type")
	}
	if req.ScopeType == "agent" && strings.ContainsAny(req.ScopeRef, "*?") && req.ScopeRef != "*" {
		return req, fmt.Errorf("agent scope_ref must be an exact type or *")
	}
	if req.TenantScope == "all" && req.ScopeType == "application" {
		return req, fmt.Errorf("application scope is not available for all tenants")
	}
	if len(req.ScopeRef) > maxAgentOperationScopeRefLength {
		return req, fmt.Errorf("scope_ref exceeds %d bytes", maxAgentOperationScopeRefLength)
	}
	if req.Mode != "audit" && req.Mode != "light" && req.Mode != "strict" {
		return req, fmt.Errorf("mode must be audit, light, or strict")
	}
	if req.Action != "record" && req.Action != "alert_allow" && req.Action != "confirm" && req.Action != "block" {
		return req, fmt.Errorf("invalid action")
	}
	// protocol 为空表示所有协议，mcp 只对“确认”行有区别：解析有效策略时只对确认行按协议过滤（确认行
	// protocol=mcp 只管 MCP 请求），其余动作的行对所有协议生效（与 2.9.21 同口径，见仓库
	// ResolveEffectivePolicy）。2.9.22 起“确认”不再限定 MCP 与应用/智能体范围：非 MCP 协议在网关策略
	// 开了确认通道时走普通确认票据，没有时按 agent.confirm_without_channel。
	if req.Protocol != "" && req.Protocol != "mcp" {
		return req, fmt.Errorf("protocol must be mcp when set")
	}
	if req.Version <= 0 {
		return req, fmt.Errorf("version must be positive")
	}
	if len(req.DiscardablePaths) > maxAgentOperationPaths {
		return req, fmt.Errorf("too many discardable paths")
	}
	pathSeen := make(map[string]struct{}, len(req.DiscardablePaths))
	paths := make([]string, 0, len(req.DiscardablePaths))
	for _, candidate := range req.DiscardablePaths {
		normalized, err := normalizeAgentOperationPath(candidate)
		if err != nil {
			return req, err
		}
		if _, ok := pathSeen[normalized]; ok {
			continue
		}
		pathSeen[normalized] = struct{}{}
		paths = append(paths, normalized)
	}
	req.DiscardablePaths = paths
	if req.RestrictedFilePatterns != nil {
		if err := filerestrict.Validate(req.RestrictedFilePatterns); err != nil {
			return req, err
		}
	}
	if req.RestrictedFileAction != "" {
		action, err := filerestrict.ValidateAction(req.RestrictedFileAction)
		if err != nil {
			return req, err
		}
		req.RestrictedFileAction = string(action)
	}
	seen := make(map[string]struct{}, len(req.NotifyChannelIDs))
	channels := make([]string, 0, len(req.NotifyChannelIDs))
	for _, id := range req.NotifyChannelIDs {
		id = strings.TrimSpace(id)
		if id == "" || len(id) > maxAgentOperationChannelIDLength || strings.ContainsRune(id, '\x00') {
			return req, fmt.Errorf("invalid notify channel id")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		channels = append(channels, id)
		if len(channels) > maxAgentOperationChannelIDs {
			return req, fmt.Errorf("too many notify channel ids")
		}
	}
	req.NotifyChannelIDs = channels
	if req.TenantScope == "all" && len(req.NotifyChannelIDs) != 0 {
		return req, fmt.Errorf("notification channels are tenant-scoped")
	}
	return req, nil
}

func normalizeAgentOperationPath(candidate string) (string, error) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" || len(candidate) > maxAgentOperationPathLength ||
		strings.ContainsRune(candidate, '\x00') || strings.Contains(candidate, "\\") ||
		strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "~") {
		return "", fmt.Errorf("discardable path must be a bounded relative path")
	}
	segments := strings.Split(candidate, "/")
	if len(segments) > maxAgentOperationPathDepth {
		return "", fmt.Errorf("discardable path is too deep")
	}
	for _, segment := range segments {
		if !validAgentOperationPathSegment(segment) {
			return "", fmt.Errorf("discardable path contains an unsafe segment")
		}
		switch strings.ToLower(segment) {
		case ".git", ".ssh", "home", "repo":
			return "", fmt.Errorf("discardable path contains a protected segment")
		}
	}
	return strings.Join(segments, "/"), nil
}

func validAgentOperationPathSegment(segment string) bool {
	if segment == "" || segment == "." || segment == ".." {
		return false
	}
	for _, r := range segment {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}
