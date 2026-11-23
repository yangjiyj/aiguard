package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
)

// W1 1.11：内置红线的租户级处置配置（alert=只留证告警，block=防护模式下阻断）。
//
// 真源是控制面 mcp_redline_settings（迁移 862），经内部端点
// GET /admin/v1/internal/mcp/redline-settings 下发。默认（未配置/从未拉到）一律 alert，
// 与基线「红线只作证据」一致——管理员显式配了 block 才拦。
// 拉取失败沿用最近一次成功的配置（与 D1 同口径）。

const (
	mcpRedlineActionAlert  = "alert"
	mcpRedlineActionBlock  = "block"
	mcpRedlineActionOff    = "off"
	mcpRedlineActionRecord = "record"
	// mcpRedlineRecordCategory 是“仅记录”红线的证据类别：留在工具日志里，不触发安全事件。
	mcpRedlineRecordCategory = "mcp_redline_record"

	mcpRedlineSettingsTTL = 30 * time.Second
)

// mcpRedlineFailureLogInterval 是同一租户“拉取失败且无缓存”日志的最小间隔：失败期间每个 tools/call 都会尝试重拉，
// 不限频会让日志被同一条消息刷屏、淹没真正的告警。
const mcpRedlineFailureLogInterval = time.Minute

// mcpRedlineFetchState 记录红线配置拉取的健康状态，供日志限频与 /health 展示。
type mcpRedlineFetchState struct {
	mu       sync.Mutex
	failures int64
	// lastCategory 只是粗粒度的失败类别（connection_refused/timeout/dns/http_404/http_5xx/other），不含主机名、端口、路径；
	// 错误原文只写日志，绝不进入任何对外状态（复审 M-1）。
	lastCategory string
	lastLogged   map[string]time.Time // tenant -> 上次打 [WARN] 的时间
	lastFailure  time.Time
}

func (st *mcpRedlineFetchState) recordFailure(tenantID string, err error, now time.Time) (shouldLog bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.failures++
	st.lastFailure = now
	st.lastCategory = classifyRedlineFetchError(err.Error())
	if st.lastLogged == nil {
		st.lastLogged = map[string]time.Time{}
	}
	if last, ok := st.lastLogged[tenantID]; ok && now.Sub(last) < mcpRedlineFailureLogInterval {
		return false
	}
	st.lastLogged[tenantID] = now
	return true
}

func (st *mcpRedlineFetchState) recordSuccess(tenantID string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.lastLogged, tenantID)
	if len(st.lastLogged) == 0 {
		st.lastCategory = ""
	}
}

type mcpRedlineSettingsEntry struct {
	actions   map[string]string
	expiresAt time.Time
}

// mcpRedlineSettingsCache 按租户缓存红线动作；expiresAt 过期后重拉，失败时仍返回旧值（LKG）。
type mcpRedlineSettingsCache struct {
	mu      sync.Mutex
	entries map[string]mcpRedlineSettingsEntry
	ttl     time.Duration
	fetch   mcpRedlineFetchState
}

func newMCPRedlineSettingsCache() *mcpRedlineSettingsCache {
	return &mcpRedlineSettingsCache{entries: make(map[string]mcpRedlineSettingsEntry), ttl: mcpRedlineSettingsTTL}
}

// normalizeMCPRedlineActions 只保留已知规则名 + 合法动作，其他一律丢弃（按 alert 处理）。
func normalizeMCPRedlineActions(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	known := make(map[string]bool, len(mcpRedlineRules))
	for _, rule := range mcpRedlineRules {
		known[rule.Name] = true
	}
	for name, action := range in {
		name = strings.TrimSpace(name)
		action = strings.ToLower(strings.TrimSpace(action))
		if !known[name] {
			continue
		}
		switch action {
		case mcpRedlineActionBlock, mcpRedlineActionAlert, mcpRedlineActionOff, mcpRedlineActionRecord:
			out[name] = action
		}
	}
	return out
}

// mcpRedlineActions 返回租户的红线动作表（永不返回错误；取不到时为空表 = 全部 alert）。
func (h *MCPProxyHandler) mcpRedlineActions(ctx context.Context, tenantID string) map[string]string {
	if h == nil || h.redlineSettings == nil || h.toolRiskClient == nil || tenantID == "" {
		return nil
	}
	cache := h.redlineSettings
	cache.mu.Lock()
	entry, ok := cache.entries[tenantID]
	cache.mu.Unlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.actions
	}
	actions, err := h.toolRiskClient.fetchMCPRedlineSettings(ctx, tenantID)
	if err != nil {
		shouldLog := cache.fetch.recordFailure(tenantID, err, time.Now())
		if ok {
			if shouldLog {
				log.Printf("[WARN] MCP 红线配置拉取失败，沿用最近一次成功的配置（LKG）: tenant=%s err=%v", tenantID, err)
			}
			return entry.actions
		}
		// 原设计：拉取失败且没有缓存时，红线只告警（alert-only）。这是安全降级，但意味着管理员配置的“阻断”不会生效，
		// 运维必须看得见：带 [WARN] 级别标识、按租户限频，并通过 RedlineFetchStatus 在需内部密钥的 /admin/v1/internal/runtime-status 里暴露（只暴露失败次数与类别）。
		if shouldLog {
			log.Printf("[WARN] MCP 红线配置拉取失败且无缓存，红线暂时只告警（alert-only），租户配置的“阻断”不会生效，请检查控制面 /admin/v1/internal/mcp/redline-settings: tenant=%s err=%v", tenantID, err)
		}
		return nil
	}
	cache.fetch.recordSuccess(tenantID)
	cache.mu.Lock()
	cache.entries[tenantID] = mcpRedlineSettingsEntry{actions: actions, expiresAt: time.Now().Add(cache.ttl)}
	cache.mu.Unlock()
	return actions
}

func (c *ToolRiskClient) fetchMCPRedlineSettings(ctx context.Context, tenantID string) (map[string]string, error) {
	if c == nil || c.controlPlaneURL == "" {
		return nil, fmt.Errorf("control plane not configured")
	}
	endpoint := strings.TrimRight(c.controlPlaneURL, "/") + "/admin/v1/internal/mcp/redline-settings"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Tenant-ID", tenantID)
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}
	client := c.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mcp redline settings status %d", resp.StatusCode)
	}
	var payload struct {
		Actions map[string]string `json:"actions"`
		Data    *struct {
			Actions map[string]string `json:"actions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode mcp redline settings: %w", err)
	}
	actions := payload.Actions
	if payload.Data != nil && payload.Data.Actions != nil {
		actions = payload.Data.Actions
	}
	return normalizeMCPRedlineActions(actions), nil
}

// mcpEffectiveRedlines 按租户处置拆分命中的红线：off 丢弃；record 与被例外放开的 alert/block 只留证
// （recordOnly）；alert/block 照旧（active）。
func mcpEffectiveRedlines(hits []string, actions map[string]string, tenant mcpTenantContext, target string) (active, recordOnly []string) {
	for _, name := range hits {
		switch actions[name] {
		case mcpRedlineActionOff:
			continue
		case mcpRedlineActionRecord:
			recordOnly = append(recordOnly, name)
		case mcpRedlineActionBlock:
			if mcpRedlineExempt(name, tenant.Exceptions, target, time.Now()) {
				recordOnly = append(recordOnly, name)
				continue
			}
			active = append(active, name)
		default:
			// 告警档同样认例外：命中例外时只记录、不告警。
			if mcpRedlineExempt(name, tenant.Exceptions, target, time.Now()) {
				recordOnly = append(recordOnly, name)
				continue
			}
			active = append(active, name)
		}
	}
	return active, recordOnly
}

// mcpRedlineExempt 判断有没有放开这条红线的有效例外：rule_id 为红线名或 mcp_redline_<红线名>，目标口径
// 与调用路径相同（见 agentguard.MatchingMCPException）。
func mcpRedlineExempt(name string, exceptions []agentguard.PolicyException, target string, now time.Time) bool {
	return agentguard.MatchingMCPException(exceptions, []string{name, "mcp_redline_" + name}, target, now) != nil
}

// mcpRedlineBlockHits 返回命中且配置为 block 的红线规则名。
func mcpRedlineBlockHits(hits []string, actions map[string]string) []string {
	var out []string
	for _, name := range hits {
		if actions[name] == mcpRedlineActionBlock {
			out = append(out, name)
		}
	}
	return out
}

// RedlineFetchStatus 返回红线配置拉取的累计失败次数与最近一次失败的**类别**（恢复后为空）。
// 类别是固定的粗粒度枚举，不含主机名/端口/路径；错误原文只写日志。
func (h *MCPProxyHandler) RedlineFetchStatus() (failures int64, lastCategory string) {
	if h == nil || h.redlineSettings == nil {
		return 0, ""
	}
	st := &h.redlineSettings.fetch
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.failures, st.lastCategory
}

// recordRedlineFetchFailureForTest 仅供测试：模拟一次红线配置拉取失败（含日志）。
func (h *MCPProxyHandler) recordRedlineFetchFailureForTest(tenantID, rawErr string) {
	err := errors.New(rawErr)
	if h.redlineSettings.fetch.recordFailure(tenantID, err, time.Now()) {
		log.Printf("[WARN] MCP 红线配置拉取失败且无缓存，红线暂时只告警（alert-only）: tenant=%s err=%v", tenantID, err)
	}
}

// classifyRedlineFetchError 把底层错误归为固定枚举，避免对外泄漏内部地址。
func classifyRedlineFetchError(raw string) string {
	l := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case l == "":
		return ""
	case strings.Contains(l, "connection refused"):
		return "connection_refused"
	case strings.Contains(l, "deadline exceeded"), strings.Contains(l, "timeout"):
		return "timeout"
	case strings.Contains(l, "no such host"), strings.Contains(l, "lookup "):
		return "dns"
	case strings.Contains(l, "status 404"):
		return "http_404"
	case strings.Contains(l, "status 5"):
		return "http_5xx"
	case strings.Contains(l, "status 401"), strings.Contains(l, "status 403"):
		return "http_auth"
	default:
		return "other"
	}
}
