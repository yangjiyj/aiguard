package handler

// W1 1.12：参数条件策略链（arg_chain）的拉取、last-known-good 与运行时求值。
//
// 控制面不接收 tools/call 参数：它下发「不看参数的胜出者」+ 排在胜出者前面的带条件策略
// （arg_chain，已按解析优先级排好）。网关逐条用 MatchMCPArgConditions 求值，取第一条成立的
// 覆盖胜出者；都不成立时用胜出者。arg_chain 放在 W1 自有的旁路存储里（按策略缓存键），
// 不改共享结构体 MCPEffectivePolicy。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
)

// mcpArgChainEntry 与 control-plane repository.MCPArgChainEntry 同形。
type mcpArgChainEntry struct {
	PolicyID      string            `json:"policy_id"`
	Mode          string            `json:"mode"`
	Action        string            `json:"action"`
	ScopeType     string            `json:"scope_type"`
	Priority      int               `json:"priority"`
	ArgConditions []MCPArgCondition `json:"arg_conditions"`
}

// mcpEffectivePolicyWire 解码生效策略 + arg_chain（嵌入结构体字段在 JSON 中平铺）。
type mcpEffectivePolicyWire struct {
	MCPEffectivePolicy
	ArgChain []mcpArgChainEntry `json:"arg_chain"`
}

// mcpArgChainStore 按策略缓存键记录最近一次成功拉取的 arg_chain（与 LKG 同步更新、同样有界）。
type mcpArgChainStore struct {
	mu      sync.Mutex
	entries map[string][]mcpArgChainEntry
}

var (
	mcpArgChainStoresMu sync.Mutex
	mcpArgChainStores   = map[*mcpPolicyCache]*mcpArgChainStore{}
)

func (c *mcpPolicyCache) argChainStore() *mcpArgChainStore {
	if c == nil {
		return nil
	}
	mcpArgChainStoresMu.Lock()
	defer mcpArgChainStoresMu.Unlock()
	store, ok := mcpArgChainStores[c]
	if !ok {
		store = &mcpArgChainStore{entries: make(map[string][]mcpArgChainEntry)}
		mcpArgChainStores[c] = store
	}
	return store
}

func (c *mcpPolicyCache) rememberArgChain(key string, chain []mcpArgChainEntry) {
	store := c.argChainStore()
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(chain) == 0 {
		delete(store.entries, key)
		return
	}
	if _, exists := store.entries[key]; !exists && len(store.entries) >= mcpLastKnownGoodMaxEntries {
		for victim := range store.entries {
			delete(store.entries, victim)
			break
		}
	}
	store.entries[key] = append([]mcpArgChainEntry(nil), chain...)
}

func (c *mcpPolicyCache) argChain(key string) []mcpArgChainEntry {
	store := c.argChainStore()
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]mcpArgChainEntry(nil), store.entries[key]...)
}

// fetchMCPToolPolicyWithArgChain 拉取工具目标生效策略（查询参数与基线 tools/call 拉取一致）。
func (c *ToolRiskClient) fetchMCPToolPolicyWithArgChain(ctx context.Context, envelope *modelrouter.RequestEnvelope, serverID, toolName string) (*MCPEffectivePolicy, []mcpArgChainEntry, error) {
	endpoint := fmt.Sprintf("%s/admin/v1/internal/mcp/effective-policy", strings.TrimRight(c.controlPlaneURL, "/"))
	params := url.Values{}
	params.Set("server_id", serverID)
	params.Set("tool_name", toolName)
	params.Set("project_id", envelope.ProjectID)
	params.Set("user_id", envelope.UserID)
	params.Set("key_prefix", envelope.KeyPrefix)
	params.Set("agent_id", envelope.AgentType)
	params.Set("session_id", envelope.SessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", envelope.TenantID)
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("mcp effective policy status %d: %s", resp.StatusCode, string(body))
	}
	raw := body
	var probe struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &probe); err == nil && len(probe.Data) > 0 && string(probe.Data) != "null" {
		raw = probe.Data
	}
	var payload mcpEffectivePolicyWire
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, nil, fmt.Errorf("decode mcp effective policy: %w", err)
	}
	policy := payload.MCPEffectivePolicy
	if policy.Mode == "" {
		policy.Mode = "audit"
	}
	if policy.Action == "" {
		policy.Action = "audit"
	}
	return &policy, payload.ArgChain, nil
}

// GetMCPToolPolicyWithArgChain = GetMCPEffectivePolicy + 同一缓存键下最近一次成功拉到的 arg_chain。
// 拉取失败走 LKG 时，arg_chain 同样是最近一次成功的那份（两者同步更新）。
func (c *ToolRiskClient) GetMCPToolPolicyWithArgChain(ctx context.Context, envelope *modelrouter.RequestEnvelope, serverID, toolName string) (*MCPEffectivePolicy, []mcpArgChainEntry) {
	policy := c.GetMCPEffectivePolicy(ctx, envelope, serverID, toolName)
	// 2.9.22：供应链发现不再是结构阻断，管理员的参数条件策略对未准入、地址/Schema 变化的工具照样生效。
	if c == nil || envelope == nil || policy == nil {
		return policy, nil
	}
	return policy, c.mcpPolicyCache.argChain(mcpTargetPolicyCacheKey(envelope, serverID, mcpTargetTool, toolName))
}

// applyMCPArgChain 按顺序取第一条参数条件成立的 arg_chain 条目覆盖胜出者。
// 供应链结论（StructuralBlock 与原因）随副本保留，由网关按管理员隔离/mcp.* 防护项另行处置。
func applyMCPArgChain(policy *MCPEffectivePolicy, chain []mcpArgChainEntry, argumentsJSON string) *MCPEffectivePolicy {
	if policy == nil {
		policy = mcpDefaultEffectivePolicy()
	}
	if len(chain) == 0 {
		return policy
	}
	for _, entry := range chain {
		if !MatchMCPArgConditions(entry.ArgConditions, argumentsJSON, entry.Action) {
			continue
		}
		selected := cloneMCPEffectivePolicy(policy)
		selected.Matched = true
		selected.PolicyID = entry.PolicyID
		selected.Mode = entry.Mode
		selected.Action = entry.Action
		selected.ScopeType = entry.ScopeType
		selected.Priority = entry.Priority
		if selected.Mode == "" {
			selected.Mode = "audit"
		}
		if selected.Action == "" {
			selected.Action = "audit"
		}
		return selected
	}
	return policy
}
