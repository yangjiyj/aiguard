package handler

// 复审 M-5：record（audit-only）模式下，红线命中会为每次 tools/call 写一条 security_events，写入量被放大。
// 复用仓库已有的「代表事件 + 窗口内重复折叠为 occurrence」框架（security_event_occurrences，见迁移 130）：
//   - 首次命中（窗口内第一次）写完整 security_events，并登记为代表事件；
//   - 同一 (租户, server, 工具, 红线规则集, 处置) 在窗口内的重复，只写一行幂等 occurrence
//     （告警组建立后计数 +1，未建立时挂账，由控制面 ReconcileOccurrences 回算），计数准确；
//   - 窗口过期后重新写一条完整代表事件；
//   - 只折叠「纯红线信号」。真实阻断/确认、record 下的 raw=block/confirm、tools/list 漂移、工具返回注入、
//     服务端反向请求等高价值事件一律逐条写，绝不折叠；
//   - tool_call_logs 的逐条审计完全不受影响（折叠只发生在 security_events 层）；
//   - 窗口 MCP_REDLINE_EVENT_DEDUPE_WINDOW（Go duration，默认 10m；0 或负数表示关闭去重、逐条写）。

import (
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

const (
	mcpRedlineEventDedupeDefaultWindow = 10 * time.Minute
	mcpRedlineEventDedupeMaxEntries    = 50000
)

type mcpRedlineDedupeEntry struct {
	representativeEventID string
	expiresAt             time.Time
}

// mcpRedlineEventDedupe 记住每个去重键的代表事件。并发安全；条目随窗口过期，数量有上限。
type mcpRedlineEventDedupe struct {
	mu      sync.Mutex
	window  time.Duration
	entries map[string]mcpRedlineDedupeEntry
	now     func() time.Time
}

func newMCPRedlineEventDedupe(window time.Duration) *mcpRedlineEventDedupe {
	return &mcpRedlineEventDedupe{window: window, entries: map[string]mcpRedlineDedupeEntry{}, now: time.Now}
}

// mcpRedlineEventDedupeWindowFromEnv 读取窗口配置；非法值回落默认，<=0 关闭去重。
func mcpRedlineEventDedupeWindowFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("MCP_REDLINE_EVENT_DEDUPE_WINDOW"))
	if raw == "" {
		return mcpRedlineEventDedupeDefaultWindow
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return mcpRedlineEventDedupeDefaultWindow
	}
	return d
}

// lookup 返回窗口内已有的代表事件 id；没有则 ok=false。命中时顺延窗口（持续刷屏不会每个窗口都重新写完整事件）。
func (d *mcpRedlineEventDedupe) lookup(key string) (string, bool) {
	if d == nil || d.window <= 0 || key == "" {
		return "", false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if e, ok := d.entries[key]; ok && now.Before(e.expiresAt) {
		e.expiresAt = now.Add(d.window)
		d.entries[key] = e
		return e.representativeEventID, true
	}
	return "", false
}

// register 登记代表事件；并发时先到先得。
func (d *mcpRedlineEventDedupe) register(key, eventID string) {
	if d == nil || d.window <= 0 || key == "" || eventID == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if len(d.entries) >= mcpRedlineEventDedupeMaxEntries {
		for k, e := range d.entries { // 先清过期；仍超限则整表重置（宁可多写完整事件，也不无界增长或丢记录）
			if !now.Before(e.expiresAt) {
				delete(d.entries, k)
			}
		}
		if len(d.entries) >= mcpRedlineEventDedupeMaxEntries {
			d.entries = map[string]mcpRedlineDedupeEntry{}
		}
	}
	if e, ok := d.entries[key]; ok && now.Before(e.expiresAt) {
		return
	}
	d.entries[key] = mcpRedlineDedupeEntry{representativeEventID: eventID, expiresAt: now.Add(d.window)}
}

// forget 在代表事件写入失败时撤销登记，避免后续重复被折叠到一个并不存在的事件上。
func (d *mcpRedlineEventDedupe) forget(key string) {
	if d == nil || key == "" {
		return
	}
	d.mu.Lock()
	delete(d.entries, key)
	d.mu.Unlock()
}

// mcpPureRedlineSignal 判定一条需要写 security_events 的决策是否只是「纯红线信号」，即可折叠。
// 任何带阻断/确认意图、漂移、注入、反向请求、破坏性的决策都不是纯红线信号。
func mcpPureRedlineSignal(d *mcpToolCallDecision) bool {
	if d == nil || !mcpDecisionHasRedlineEvidence(d) {
		return false
	}
	if len(d.ToolsListDrops) > 0 || d.ToolResultWouldBlock || d.ServerInitiated {
		return false
	}
	raw := d.Decision.RawDecision
	if raw == agentguard.DecisionBlock || raw == agentguard.DecisionConfirm {
		return false
	}
	eff := d.Decision.EffectiveDecision
	if eff == agentguard.DecisionBlock || eff == agentguard.DecisionConfirm {
		return false
	}
	if d.Decision.RiskCategory == agentguard.DestructiveRiskCategory || isDestructiveGateDecision(d.Decision) {
		return false
	}
	return true
}

// mcpRedlineDedupeKey 由 租户+server+工具+红线规则集+处置 派生；不含 request_id / 参数内容。
func mcpRedlineDedupeKey(record mcpProxyAuditRecord, d *mcpToolCallDecision, auditOnly bool) string {
	rules := make([]string, 0, len(d.Decision.Evidence))
	for _, ev := range d.Decision.Evidence {
		if ev.Category == "mcp_redline" {
			rules = append(rules, ev.RuleID)
		}
	}
	sort.Strings(rules)
	server := record.ServerID
	if d.MCPServerID != "" {
		server = d.MCPServerID
	}
	parts := []string{
		record.TenantID, server, d.Qualified, strings.Join(rules, ","),
		string(d.Decision.RawDecision), string(d.Decision.EffectiveDecision), boolToString(auditOnly),
	}
	return scanfp.SHA256Hex(strings.Join(parts, "\x00"))
}

func boolToString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
