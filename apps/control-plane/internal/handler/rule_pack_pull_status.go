package handler

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

// 方案A 下发可见性：引擎每次拉规则包时带 X-Node-ID（自身节点）与
// X-RulePack-Version（当前持有版本）；本模块登记「各节点持有版本 vs 本次下发版本」，
// 通过 GET /admin/v1/rules/pull-status 暴露，供运维查看各节点是否已收敛到最新版本。
// 仅进程内内存台账（轻量做法），不落库、不新增迁移。

const (
	nodeIDHeader                 = "X-Node-ID"
	rulePackVersionHeader        = "X-RulePack-Version"
	rulePackActiveCountHeader    = "X-RulePack-Active-Count"
	rulePackSkippedCountHeader   = "X-RulePack-Skipped-Count"
	rulePackPolicyCountHeader    = "X-RulePack-Policy-Count"
	rulePackRefreshSecondsHeader = "X-RulePack-Refresh-Seconds"
	// 引擎声明自己认识的新字段（逗号分隔）；与 security-engine ENGINE_CAPABILITIES_HEADER 一致。
	engineCapabilitiesHeader = "X-Engine-Capabilities"

	// 引擎默认每分钟刷新一次规则包；连续三个刷新周期未上报即视为 stale。
	rulePackRefreshPeriod     = time.Minute
	rulePackFreshnessCycles   = 3
	rulePackFreshnessWindow   = rulePackRefreshPeriod * rulePackFreshnessCycles
	rulePackLedgerRetention   = 24 * time.Hour
	rulePackMaxNodesPerTenant = 1000
	rulePackMaxNodesGlobal    = 10000
	rulePackNodeIDMaxLength   = 128
	maxRulePackRefreshSeconds = 3600

	rulePackNodeStatusStale     = "stale"
	rulePackNodeStatusLagging   = "lagging"
	rulePackNodeStatusConverged = "converged"
	// 节点引擎版本过旧：策略用到了它不认识的字段，已按旧格式下发（相关功能在该节点不生效）。
	rulePackNodeStatusEngineUpgradeRequired = "engine_upgrade_required"
)

// 可注入时钟让刷新窗口边界可被确定性测试；生产默认使用 UTC 当前时间。
var rulePackStatusNow = func() time.Time { return time.Now().UTC() }

type rulePackNodeKey struct {
	TenantID string
	NodeID   string
}

type rulePackNodePull struct {
	NodeID              string    `json:"node_id"`
	TenantID            string    `json:"-"`
	HeldVersion         string    `json:"held_version"`
	ServedVersion       string    `json:"served_version"`
	ActiveRuntimeCount  *int      `json:"active_runtime_count,omitempty"`
	SkippedRuntimeCount *int      `json:"skipped_runtime_count,omitempty"`
	PolicyRuntimeCount  *int      `json:"policy_runtime_count,omitempty"`
	RefreshSeconds      int       `json:"refresh_seconds,omitempty"`
	LastPullAt          time.Time `json:"last_pull_at"`
	// EngineUpgradeRequired 是该节点缺少、而本次规则包用到的引擎能力。
	EngineUpgradeRequired []string `json:"engine_upgrade_required,omitempty"`
}

// rulePackNodePullView 是面向当前租户管理员的响应结构，刻意不包含 TenantID。
type rulePackNodePullView struct {
	NodeID              string    `json:"node_id"`
	HeldVersion         string    `json:"held_version"`
	ServedVersion       string    `json:"served_version"`
	ActiveRuntimeCount  *int      `json:"active_runtime_count,omitempty"`
	SkippedRuntimeCount *int      `json:"skipped_runtime_count,omitempty"`
	PolicyRuntimeCount  *int      `json:"policy_runtime_count,omitempty"`
	RefreshSeconds      int       `json:"refresh_seconds,omitempty"`
	Status              string    `json:"status"`
	Converged           bool      `json:"converged"` // 兼容旧客户端；以动态状态为准。
	LastPullAt          time.Time `json:"last_pull_at"`
	// EngineUpgradeRequired 非空时该节点需先升级安全引擎，相关策略功能在该节点不生效。
	EngineUpgradeRequired []string `json:"engine_upgrade_required,omitempty"`
}

var rulePackPullStatus struct {
	sync.RWMutex
	nodes map[rulePackNodeKey]rulePackNodePull
}

// recordRulePackPull 登记一次按节点拉取。空 NodeID（旧引擎未上报身份）不记账，避免污染台账（向后兼容）。
func recordRulePackPull(nodeID, tenantID, heldVersion, servedVersion string, at time.Time) {
	recordRulePackPullWithTelemetry(nodeID, tenantID, heldVersion, servedVersion, nil, nil, 0, at)
}

func recordRulePackPullWithCounts(nodeID, tenantID, heldVersion, servedVersion string, activeCount, skippedCount *int, at time.Time) {
	recordRulePackPullWithTelemetry(nodeID, tenantID, heldVersion, servedVersion, activeCount, skippedCount, 0, at)
}

func recordRulePackPullWithTelemetry(nodeID, tenantID, heldVersion, servedVersion string, activeCount, skippedCount *int, refreshSeconds int, at time.Time) bool {
	return recordRulePackPullWithPolicyTelemetry(nodeID, tenantID, heldVersion, servedVersion, activeCount, skippedCount, nil, refreshSeconds, at)
}

func recordRulePackPullWithPolicyTelemetry(nodeID, tenantID, heldVersion, servedVersion string, activeCount, skippedCount, policyCount *int, refreshSeconds int, at time.Time) bool {
	if !validRulePackTenantID(tenantID) {
		return false
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return false
	}
	if len([]rune(nodeID)) > rulePackNodeIDMaxLength {
		return false
	}
	if activeCount != nil && *activeCount < 0 {
		activeCount = nil
	}
	if skippedCount != nil && *skippedCount < 0 {
		skippedCount = nil
	}
	if policyCount != nil && *policyCount < 0 {
		policyCount = nil
	}
	if refreshSeconds < 1 || refreshSeconds > maxRulePackRefreshSeconds {
		refreshSeconds = 0
	}
	rulePackPullStatus.Lock()
	defer rulePackPullStatus.Unlock()
	if rulePackPullStatus.nodes == nil {
		rulePackPullStatus.nodes = make(map[rulePackNodeKey]rulePackNodePull)
	}
	pruneRulePackPullLedgerLocked(at)
	rulePackPullStatus.nodes[rulePackNodeKey{TenantID: tenantID, NodeID: nodeID}] = rulePackNodePull{
		NodeID:              nodeID,
		TenantID:            tenantID,
		HeldVersion:         heldVersion,
		ServedVersion:       servedVersion,
		ActiveRuntimeCount:  copyOptionalCount(activeCount),
		SkippedRuntimeCount: copyOptionalCount(skippedCount),
		PolicyRuntimeCount:  copyOptionalCount(policyCount),
		RefreshSeconds:      refreshSeconds,
		LastPullAt:          at,
	}
	enforceRulePackTenantLimitLocked(tenantID)
	enforceRulePackGlobalLimitLocked()
	return true
}

// markRulePackNodeEngineUpgrade 记下节点本次拉取缺少的引擎能力（nil 表示无缺失，清除旧提示）。
func markRulePackNodeEngineUpgrade(tenantID, nodeID string, missing []string) {
	key := rulePackNodeKey{TenantID: tenantID, NodeID: strings.TrimSpace(nodeID)}
	rulePackPullStatus.Lock()
	defer rulePackPullStatus.Unlock()
	node, ok := rulePackPullStatus.nodes[key]
	if !ok {
		return
	}
	node.EngineUpgradeRequired = append([]string(nil), missing...)
	rulePackPullStatus.nodes[key] = node
}

func normalizeRulePackNodeID(nodeID string) string {
	nodeID = strings.TrimSpace(nodeID)
	if len([]rune(nodeID)) > rulePackNodeIDMaxLength {
		return ""
	}
	return nodeID
}

func enforceRulePackGlobalLimitLocked() {
	for len(rulePackPullStatus.nodes) > rulePackMaxNodesGlobal {
		var oldestKey rulePackNodeKey
		var oldestAt time.Time
		for key, node := range rulePackPullStatus.nodes {
			if oldestAt.IsZero() || node.LastPullAt.Before(oldestAt) || (node.LastPullAt.Equal(oldestAt) && (key.TenantID < oldestKey.TenantID || (key.TenantID == oldestKey.TenantID && key.NodeID < oldestKey.NodeID))) {
				oldestAt = node.LastPullAt
				oldestKey = key
			}
		}
		delete(rulePackPullStatus.nodes, oldestKey)
	}
}

func copyOptionalCount(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func pruneRulePackPullLedgerLocked(now time.Time) {
	for key, node := range rulePackPullStatus.nodes {
		if now.Sub(node.LastPullAt) > rulePackLedgerRetention {
			delete(rulePackPullStatus.nodes, key)
		}
	}
}

func enforceRulePackTenantLimitLocked(tenantID string) {
	for {
		count := 0
		var oldestKey rulePackNodeKey
		var oldestAt time.Time
		for key, node := range rulePackPullStatus.nodes {
			if key.TenantID != tenantID {
				continue
			}
			count++
			if oldestAt.IsZero() || node.LastPullAt.Before(oldestAt) || (node.LastPullAt.Equal(oldestAt) && key.NodeID < oldestKey.NodeID) {
				oldestAt = node.LastPullAt
				oldestKey = key
			}
		}
		if count <= rulePackMaxNodesPerTenant {
			return
		}
		delete(rulePackPullStatus.nodes, oldestKey)
	}
}

func rulePackNodeFreshnessWindow(n rulePackNodePull) time.Duration {
	if n.RefreshSeconds < 1 || n.RefreshSeconds > maxRulePackRefreshSeconds {
		return rulePackFreshnessWindow
	}
	window := time.Duration(n.RefreshSeconds) * time.Second * rulePackFreshnessCycles
	if window < rulePackRefreshPeriod {
		return rulePackRefreshPeriod
	}
	return window
}

func classifyRulePackNode(n rulePackNodePull, desiredVersion string, now time.Time) string {
	if now.Sub(n.LastPullAt) > rulePackNodeFreshnessWindow(n) {
		return rulePackNodeStatusStale
	}
	if len(n.EngineUpgradeRequired) > 0 && n.HeldVersion == n.ServedVersion {
		// 持有的就是按旧格式裁剪过的版本，再等也不会与完整版本收敛。
		return rulePackNodeStatusEngineUpgradeRequired
	}
	if n.HeldVersion != desiredVersion {
		return rulePackNodeStatusLagging
	}
	return rulePackNodeStatusConverged
}

func listRulePackPullStatus(tenantID, desiredVersion string, now time.Time) []rulePackNodePullView {
	rulePackPullStatus.RLock()
	nodes := make([]rulePackNodePullView, 0, len(rulePackPullStatus.nodes))
	for _, n := range rulePackPullStatus.nodes {
		if n.TenantID != tenantID {
			continue
		}
		status := classifyRulePackNode(n, desiredVersion, now)
		nodes = append(nodes, rulePackNodePullView{
			NodeID:                n.NodeID,
			HeldVersion:           n.HeldVersion,
			ServedVersion:         n.ServedVersion,
			ActiveRuntimeCount:    copyOptionalCount(n.ActiveRuntimeCount),
			SkippedRuntimeCount:   copyOptionalCount(n.SkippedRuntimeCount),
			PolicyRuntimeCount:    copyOptionalCount(n.PolicyRuntimeCount),
			RefreshSeconds:        n.RefreshSeconds,
			Status:                status,
			Converged:             status == rulePackNodeStatusConverged,
			LastPullAt:            n.LastPullAt,
			EngineUpgradeRequired: append([]string(nil), n.EngineUpgradeRequired...),
		})
	}
	rulePackPullStatus.RUnlock()

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })
	return nodes
}

func writeRulePackPullStatusResponse(w http.ResponseWriter, tenantID, desiredVersion string, now time.Time) {
	nodes := listRulePackPullStatus(tenantID, desiredVersion, now)
	groups := groupRulePackPullStatus(nodes)
	writeAgentGuardJSON(w, map[string]interface{}{
		"desired_version": desiredVersion,
		"nodes":           nodes,
		"count":           len(nodes),
		// Workers/replicas append #pid to the same hostname. The console shows
		// the group as well as every individual row: never just one worker.
		"groups":      groups,
		"group_count": len(groups),
	})
}

func parseOptionalRulePackCount(value string) *int {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < 0 {
		return nil
	}
	return &parsed
}

func parseRulePackRefreshSeconds(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < 1 || parsed > maxRulePackRefreshSeconds {
		return 0
	}
	return parsed
}

// GetRulePackPullStatus 暴露各节点的规则包拉取/收敛情况。
func GetRulePackPullStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if !roles.CanManageSecurityPolicy(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		pack, err := compileTenantRulePack(r.Context(), deps, user.TenantID)
		if err != nil {
			logRulePackSecurityEvent(r, user.TenantID, runtimeCompileUnavailableCode)
			writeErrorWithStatus(w, http.StatusServiceUnavailable, runtimeCompileUnavailableCode, "runtime rule status is unavailable")
			return
		}
		writeRulePackPullStatusResponse(w, user.TenantID, pack.Version, rulePackStatusNow())
	}
}

// rulePackNodeGroupView aggregates all workers that share one node_id prefix.
// A stable operator-pinned id (no #pid suffix) forms a group of one.
type rulePackNodeGroupView struct {
	NodeIDPrefix   string    `json:"node_id_prefix"`
	Nodes          int       `json:"nodes"`
	ConvergedNodes int       `json:"converged_nodes"`
	Status         string    `json:"status"`
	LastPullAt     time.Time `json:"last_pull_at"`
}

var rulePackStatusSeverity = map[string]int{
	rulePackNodeStatusConverged:             0,
	rulePackNodeStatusLagging:               1,
	rulePackNodeStatusStale:                 2,
	rulePackNodeStatusEngineUpgradeRequired: 3,
}

// rulePackNodePrefix strips a numeric #pid suffix and nothing else; hostnames
// containing '#' must not be silently mangled.
func rulePackNodePrefix(nodeID string) string {
	idx := strings.LastIndex(nodeID, "#")
	if idx <= 0 || idx == len(nodeID)-1 {
		return nodeID
	}
	for _, r := range nodeID[idx+1:] {
		if r < '0' || r > '9' {
			return nodeID
		}
	}
	return nodeID[:idx]
}

func groupRulePackPullStatus(nodes []rulePackNodePullView) []rulePackNodeGroupView {
	byPrefix := make(map[string]*rulePackNodeGroupView)
	for _, node := range nodes {
		prefix := rulePackNodePrefix(node.NodeID)
		group := byPrefix[prefix]
		if group == nil {
			group = &rulePackNodeGroupView{
				NodeIDPrefix: prefix,
				Status:       rulePackNodeStatusConverged,
			}
			byPrefix[prefix] = group
		}
		group.Nodes++
		if node.Converged {
			group.ConvergedNodes++
		}
		if node.LastPullAt.After(group.LastPullAt) {
			group.LastPullAt = node.LastPullAt
		}
		if rulePackStatusSeverity[node.Status] > rulePackStatusSeverity[group.Status] {
			group.Status = node.Status
		}
	}
	out := make([]rulePackNodeGroupView, 0, len(byPrefix))
	for _, group := range byPrefix {
		out = append(out, *group)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeIDPrefix < out[j].NodeIDPrefix })
	return out
}
