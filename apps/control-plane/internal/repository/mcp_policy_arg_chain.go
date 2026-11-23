package repository

// W1 1.12：参数条件列编解码、部门作用域排序、arg_chain 构造。

import (
	"encoding/json"
	"fmt"
)

// mcpScopeRank 在 agentGuardScopeRank 之上插入 department（成员 40 > 部门 35 > 项目 30）。
func mcpScopeRank(scopeType string) int {
	if scopeType == "department" {
		return 35
	}
	return agentGuardScopeRank(scopeType)
}

// IsMCPPolicyScopeType 列出 MCP 策略允许的作用档位。
func IsMCPPolicyScopeType(scopeType string) bool {
	switch scopeType {
	case "tenant", "project", "department", "user", "key", "agent", "session":
		return true
	default:
		return false
	}
}

func encodeMCPArgConditionsColumn(p *MCPPolicy) ([]byte, error) {
	if err := ValidateMCPArgConditions(p.ArgConditions); err != nil {
		return nil, err
	}
	if len(p.ArgConditions) == 0 {
		p.ArgConditions = []MCPArgCondition{}
		return []byte("[]"), nil
	}
	raw, err := json.Marshal(p.ArgConditions)
	if err != nil {
		return nil, fmt.Errorf("encode arg_conditions: %w", err)
	}
	return raw, nil
}

func decodeMCPArgConditionsColumn(raw []byte, p *MCPPolicy) error {
	p.ArgConditions = []MCPArgCondition{}
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &p.ArgConditions); err != nil {
		return fmt.Errorf("decode arg_conditions of %s: %w", p.ID, err)
	}
	return nil
}

// MCPArgChainEntry 是下发给网关的一条带参数条件的候选策略。
type MCPArgChainEntry struct {
	PolicyID      string            `json:"policy_id"`
	Mode          string            `json:"mode"`
	Action        string            `json:"action"`
	ScopeType     string            `json:"scope_type"`
	Priority      int               `json:"priority"`
	ArgConditions []MCPArgCondition `json:"arg_conditions"`
}

// ResolveMCPPolicyWithArgChain 返回不看参数时的胜出者（只在无条件策略中选），以及按解析
// 优先级排在它前面的带条件策略（arg_chain）。运行时按顺序取第一条参数条件成立的 arg_chain
// 条目，都不成立时用胜出者——与 ResolveMCPPolicy(scope 带 ArgumentsJSON) 结果一致。
func ResolveMCPPolicyWithArgChain(policies []*MCPPolicy, scope MCPPolicyScope) (*MCPPolicy, []MCPArgChainEntry) {
	scope.IncludeConditional = true
	scope.ArgumentsJSON = nil
	chain := []MCPArgChainEntry{}
	for _, p := range ResolveMCPPolicyCandidates(policies, scope) {
		if len(p.ArgConditions) == 0 {
			return p, chain
		}
		chain = append(chain, MCPArgChainEntry{
			PolicyID: p.ID, Mode: p.Mode, Action: p.DefaultAction,
			ScopeType: p.ScopeType, Priority: p.Priority, ArgConditions: p.ArgConditions,
		})
	}
	return nil, chain
}

// MCPPoliciesUseDepartmentScope 判断租户是否配置了部门档位策略（没有就不必反查部门）。
func MCPPoliciesUseDepartmentScope(policies []*MCPPolicy) bool {
	for _, p := range policies {
		if p != nil && p.Enabled && p.ScopeType == "department" {
			return true
		}
	}
	return false
}
