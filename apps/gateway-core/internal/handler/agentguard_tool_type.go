package handler

import (
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// W5 5.9: explicit tool -> type mapping (console tool_risk_config.tool_type)
// and schema inference, learnt on the request path (checkToolRisk) and read
// on the response path without extra control-plane calls.

const (
	agentGuardToolTypeTTL     = 10 * time.Minute
	agentGuardToolTypeMaxKeys = 20_000
)

type agentGuardToolTypeEntry struct {
	configured string
	inferred   string
	expiresAt  time.Time
}

type agentGuardToolTypeCache struct {
	mu      sync.Mutex
	entries map[string]agentGuardToolTypeEntry
}

func newAgentGuardToolTypeCache() *agentGuardToolTypeCache {
	return &agentGuardToolTypeCache{entries: map[string]agentGuardToolTypeEntry{}}
}

func agentGuardToolTypeKey(tenantID, toolName string) string {
	return tenantID + "\x00" + strings.ToLower(strings.TrimSpace(toolName))
}

func (c *agentGuardToolTypeCache) update(tenantID, toolName string, apply func(*agentGuardToolTypeEntry)) {
	if c == nil || strings.TrimSpace(toolName) == "" {
		return
	}
	now := time.Now()
	key := agentGuardToolTypeKey(tenantID, toolName)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= agentGuardToolTypeMaxKeys {
		for k, entry := range c.entries {
			if now.After(entry.expiresAt) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= agentGuardToolTypeMaxKeys {
			c.entries = map[string]agentGuardToolTypeEntry{}
		}
	}
	entry := c.entries[key]
	if now.After(entry.expiresAt) {
		entry = agentGuardToolTypeEntry{}
	}
	apply(&entry)
	entry.expiresAt = now.Add(agentGuardToolTypeTTL)
	c.entries[key] = entry
}

func (c *agentGuardToolTypeCache) get(tenantID, toolName string) (configured, inferred string) {
	if c == nil {
		return "", ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[agentGuardToolTypeKey(tenantID, toolName)]
	if !ok || time.Now().After(entry.expiresAt) {
		return "", ""
	}
	return entry.configured, entry.inferred
}

func envelopeTenant(envelope *modelrouter.RequestEnvelope) string {
	if envelope == nil {
		return ""
	}
	return envelope.TenantID
}

// rememberAgentGuardToolDefinition records the schema-inferred type of a
// tool declared in the request.
func (h *ChatCompletionsHandler) rememberAgentGuardToolDefinition(envelope *modelrouter.RequestEnvelope, tool ToolDef) {
	inferred := agentguard.InferToolTypeFromSchema(tool.Function.Parameters)
	h.agentGuardToolTypes.update(envelopeTenant(envelope), tool.Function.Name, func(entry *agentGuardToolTypeEntry) {
		entry.inferred = inferred
	})
}

// rememberAgentGuardToolConfig records the administrator's explicit type.
func (h *ChatCompletionsHandler) rememberAgentGuardToolConfig(envelope *modelrouter.RequestEnvelope, toolName string, config *ToolRiskConfigResponse) {
	configured := ""
	if config != nil && agentguard.ValidConfiguredToolType(config.ToolType) {
		configured = config.ToolType
	}
	h.agentGuardToolTypes.update(envelopeTenant(envelope), toolName, func(entry *agentGuardToolTypeEntry) {
		entry.configured = configured
	})
}

// resolveAgentGuardToolType returns the analyzer family for a tool call.
func (h *ChatCompletionsHandler) resolveAgentGuardToolType(envelope *modelrouter.RequestEnvelope, toolName string) string {
	configured, inferred := h.agentGuardToolTypes.get(envelopeTenant(envelope), toolName)
	return agentguard.ResolveToolType(toolName, configured, inferred)
}
