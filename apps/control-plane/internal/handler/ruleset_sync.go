package handler

import (
	"sort"
	"time"
)

// rulePackNodeConvergence 是单个引擎节点相对当前权威规则集版本的收敛快照。
type rulePackNodeConvergence struct {
	NodeID         string    `json:"node_id"`
	CurrentVersion string    `json:"current_version"` // 该节点最近一次回报的持有版本（HeldVersion）
	Status         string    `json:"status"`          // stale / lagging / converged
	Converged      bool      `json:"converged"`       // 是否 == 当前权威版本
	LastPullAt     time.Time `json:"last_pull_at"`
}

// rulePackConvergence 汇总某租户全部已上报节点相对权威版本的收敛情况。
type rulePackConvergence struct {
	AuthoritativeVersion    string                    `json:"authoritative_version"`
	NodeCount               int                       `json:"node_count"`
	ConvergedCount          int                       `json:"converged_count"`
	FreshCount              int                       `json:"fresh_count"`
	FreshConvergedCount     int                       `json:"fresh_converged_count"`
	StaleCount              int                       `json:"stale_count"`
	RuntimeCountReported    int                       `json:"runtime_count_reported"`
	PolicyCountReported     int                       `json:"policy_count_reported"`
	ActualActiveCount       *int                      `json:"actual_active_count,omitempty"`
	ActualSkippedCount      *int                      `json:"actual_skipped_count,omitempty"`
	ActualPolicyCount       *int                      `json:"actual_policy_count,omitempty"`
	RuntimeCountsConsistent bool                      `json:"runtime_counts_consistent"`
	AllConverged            bool                      `json:"all_converged"`
	StaleNodes              []rulePackNodeConvergence `json:"stale_nodes"`
}

// evaluateRulePackConvergence 基于 3.7 进程内拉取台账，核对指定租户各节点是否已
// 收敛到给定的权威版本。
//
// 关键正确性约束：判定收敛只采信节点在请求头里回报的 HeldVersion。响应中的
// ServedVersion 只证明 control-plane 已经下发，不能证明节点已经加载；节点必须在
// 下一次刷新回报新 HeldVersion 后才算收敛。超过三个刷新周期未上报的节点算 stale。
//
// 保守不编造：零节点（无任何上报）→ AllConverged=false，不谎称全网已收敛。
func evaluateRulePackConvergence(tenantID, authoritative string) rulePackConvergence {
	now := rulePackStatusNow()
	conv := rulePackConvergence{
		AuthoritativeVersion:    authoritative,
		StaleNodes:              []rulePackNodeConvergence{},
		RuntimeCountsConsistent: true,
	}

	rulePackPullStatus.Lock()
	for _, n := range rulePackPullStatus.nodes {
		if n.TenantID != tenantID {
			continue
		}
		conv.NodeCount++
		status := classifyRulePackNode(n, authoritative, now)
		node := rulePackNodeConvergence{
			NodeID:         n.NodeID,
			CurrentVersion: n.HeldVersion,
			Status:         status,
			Converged:      status == rulePackNodeStatusConverged,
			LastPullAt:     n.LastPullAt,
		}
		if status == rulePackNodeStatusStale {
			conv.StaleCount++
		} else {
			conv.FreshCount++
		}
		if node.Converged {
			conv.ConvergedCount++
			conv.FreshConvergedCount++
			if n.ActiveRuntimeCount != nil && n.SkippedRuntimeCount != nil {
				conv.RuntimeCountReported++
				if conv.ActualActiveCount == nil {
					conv.ActualActiveCount = copyOptionalCount(n.ActiveRuntimeCount)
					conv.ActualSkippedCount = copyOptionalCount(n.SkippedRuntimeCount)
				} else if *conv.ActualActiveCount != *n.ActiveRuntimeCount || *conv.ActualSkippedCount != *n.SkippedRuntimeCount {
					conv.RuntimeCountsConsistent = false
				}
			}
			if n.PolicyRuntimeCount != nil {
				conv.PolicyCountReported++
				if conv.ActualPolicyCount == nil {
					conv.ActualPolicyCount = copyOptionalCount(n.PolicyRuntimeCount)
				} else if *conv.ActualPolicyCount != *n.PolicyRuntimeCount {
					conv.RuntimeCountsConsistent = false
				}
			}
		} else {
			conv.StaleNodes = append(conv.StaleNodes, node)
		}
	}
	rulePackPullStatus.Unlock()

	sort.Slice(conv.StaleNodes, func(i, j int) bool {
		return conv.StaleNodes[i].NodeID < conv.StaleNodes[j].NodeID
	})
	// 全收敛要求「确有节点且无一落后」——零节点不算收敛（保守）。
	conv.AllConverged = conv.NodeCount > 0 && conv.ConvergedCount == conv.NodeCount
	return conv
}
