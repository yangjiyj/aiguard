package handler

// W1：MCP 目标策略拉取（tool/resource/prompt/method）与 last-known-good 缓存（D1）。
// 放在 W1 自有文件，避免扩大对共享文件 tool_interceptor.go 的改动面。

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

const (
	mcpTargetTool     = "tool"
	mcpTargetResource = "resource"
	mcpTargetPrompt   = "prompt"
	mcpTargetMethod   = "method"

	// mcpPolicyUnavailableReason：从未成功拉到过该目标的策略，本次放行并记覆盖缺口。
	mcpPolicyUnavailableReason = "mcp_policy_unavailable"
	// mcpPolicyLastKnownGoodReason：本次拉取失败，沿用最近一次成功拉到的策略。
	mcpPolicyLastKnownGoodReason = "mcp_policy_last_known_good"

	mcpLastKnownGoodMaxEntries = 20000
)

// mcpTargetPolicyCacheKey：tool 目标沿用旧键（兼容既有缓存语义），其他目标追加类别段。
func mcpTargetPolicyCacheKey(envelope *modelrouter.RequestEnvelope, serverID, kind, name string) string {
	if kind == "" || kind == mcpTargetTool {
		return mcpPolicyScopeCacheKey(envelope, serverID, name)
	}
	return mcpPolicyScopeCacheKey(envelope, serverID, kind+"\x1e"+name)
}

// last-known-good 存储挂在 mcpPolicyCache 实例上（旁路 map，不改共享结构体）。
type mcpLastKnownGoodStore struct {
	mu      sync.Mutex
	entries map[string]*MCPEffectivePolicy
}

var (
	mcpLastKnownGoodStoresMu sync.Mutex
	mcpLastKnownGoodStores   = map[*mcpPolicyCache]*mcpLastKnownGoodStore{}
)

func (c *mcpPolicyCache) lkgStore() *mcpLastKnownGoodStore {
	if c == nil {
		return nil
	}
	mcpLastKnownGoodStoresMu.Lock()
	defer mcpLastKnownGoodStoresMu.Unlock()
	store, ok := mcpLastKnownGoodStores[c]
	if !ok {
		store = &mcpLastKnownGoodStore{entries: make(map[string]*MCPEffectivePolicy)}
		mcpLastKnownGoodStores[c] = store
	}
	return store
}

func (c *mcpPolicyCache) rememberLastKnownGood(key string, policy *MCPEffectivePolicy) {
	store := c.lkgStore()
	if store == nil || policy == nil {
		return
	}
	copied := cloneMCPEffectivePolicy(policy)
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.entries[key]; !exists && len(store.entries) >= mcpLastKnownGoodMaxEntries {
		// 有界：超上限时随机淘汰一条（map 迭代顺序随机），防 session 维度无界增长。
		for victim := range store.entries {
			delete(store.entries, victim)
			break
		}
	}
	store.entries[key] = copied
}

func (c *mcpPolicyCache) lastKnownGood(key string) (*MCPEffectivePolicy, bool) {
	store := c.lkgStore()
	if store == nil {
		return nil, false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	policy, ok := store.entries[key]
	if !ok {
		return nil, false
	}
	return cloneMCPEffectivePolicy(policy), true
}

func cloneMCPEffectivePolicy(policy *MCPEffectivePolicy) *MCPEffectivePolicy {
	copied := *policy
	copied.SupplyChainReasons = append([]string(nil), policy.SupplyChainReasons...)
	return &copied
}

// mcpMarkLastKnownGood 给沿用的策略打证据标记，决策与留痕可区分「实时」与「沿用」。
func mcpMarkLastKnownGood(policy *MCPEffectivePolicy) *MCPEffectivePolicy {
	for _, reason := range policy.SupplyChainReasons {
		if reason == mcpPolicyLastKnownGoodReason {
			return policy
		}
	}
	policy.SupplyChainReasons = append(policy.SupplyChainReasons, mcpPolicyLastKnownGoodReason)
	return policy
}

// fetchMCPTargetPolicy：tool 目标连同 arg_chain 一起拉（W1 1.12，查询参数与既有
// fetchMCPEffectivePolicy 一致），成功时按同一缓存键记下 arg_chain，与 LKG 同步；
// 其他目标带 target_kind 查询同一内部端点。
func (c *ToolRiskClient) fetchMCPTargetPolicy(ctx context.Context, envelope *modelrouter.RequestEnvelope, serverID, kind, name string) (*MCPEffectivePolicy, error) {
	if kind == "" || kind == mcpTargetTool {
		policy, chain, err := c.fetchMCPToolPolicyWithArgChain(ctx, envelope, serverID, name)
		if err != nil {
			return nil, err
		}
		c.mcpPolicyCache.rememberArgChain(mcpTargetPolicyCacheKey(envelope, serverID, mcpTargetTool, name), chain)
		return policy, nil
	}
	endpoint := fmt.Sprintf("%s/admin/v1/internal/mcp/effective-policy", strings.TrimRight(c.controlPlaneURL, "/"))
	params := url.Values{}
	params.Set("server_id", serverID)
	params.Set("tool_name", name)
	params.Set("target_kind", kind)
	params.Set("project_id", envelope.ProjectID)
	params.Set("user_id", envelope.UserID)
	params.Set("key_prefix", envelope.KeyPrefix)
	params.Set("agent_id", envelope.AgentType)
	params.Set("session_id", envelope.SessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", envelope.TenantID)
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mcp effective policy status %d", resp.StatusCode)
	}
	raw := body
	var probe struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &probe); err == nil && len(probe.Data) > 0 && string(probe.Data) != "null" {
		raw = probe.Data
	}
	var payload MCPEffectivePolicy
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode mcp effective policy: %w", err)
	}
	if payload.Mode == "" {
		payload.Mode = "audit"
	}
	if payload.Action == "" {
		payload.Action = "audit"
	}
	return &payload, nil
}
