package repository

// W1 1.12：arg_chain 与「带参数直接解析」结果一致；部门档位排序在 user 与 project 之间。

import (
	"encoding/json"
	"testing"
	"time"
)

func TestWS1ArgChainEquivalentToDirectResolution(t *testing.T) {
	now := time.Now()
	cond := func(path, op, value string) []MCPArgCondition {
		return []MCPArgCondition{{Path: path, Op: op, Value: json.RawMessage(value)}}
	}
	policies := []*MCPPolicy{
		{ID: "tenant_block", TenantID: "t", ScopeType: "tenant", ToolPattern: "fs_*", DefaultAction: "block", Mode: "strict", Enabled: true, CreatedAt: now},
		{ID: "project_allow", TenantID: "t", ScopeType: "project", ScopeRef: "p1", ToolPattern: "fs_write", DefaultAction: "allow", Mode: "strict", Enabled: true, CreatedAt: now},
		{ID: "dept_confirm_etc", TenantID: "t", ScopeType: "department", ScopeRef: "d1", ToolPattern: "fs_write", DefaultAction: "confirm", Mode: "strict", Enabled: true, CreatedAt: now,
			ArgConditions: cond("$.path", "prefix", `"/etc/"`)},
		{ID: "user_block_pem", TenantID: "t", ScopeType: "user", ScopeRef: "u1", ToolPattern: "fs_write", DefaultAction: "block", Mode: "strict", Enabled: true, CreatedAt: now,
			ArgConditions: cond("$.path", "suffix", `".pem"`)},
		{ID: "session_allow_tmp", TenantID: "t", ScopeType: "session", ToolPattern: "fs_write", DefaultAction: "allow", Mode: "strict", Enabled: true, CreatedAt: now,
			ArgConditions: cond("$.path", "prefix", `"/tmp/"`)},
	}
	scope := MCPPolicyScope{TenantID: "t", ProjectID: "p1", UserID: "u1", DepartmentID: "d1", SessionID: "s1", ServerID: "srv", ToolName: "fs_write"}
	winner, chain := ResolveMCPPolicyWithArgChain(policies, scope)
	if winner == nil || winner.ID != "project_allow" {
		t.Fatalf("argument-independent winner must be project_allow, got %+v", winner)
	}
	if len(chain) != 3 || chain[0].PolicyID != "session_allow_tmp" || chain[1].PolicyID != "user_block_pem" || chain[2].PolicyID != "dept_confirm_etc" {
		t.Fatalf("chain must be ordered session > user > department, got %+v", chain)
	}
	for _, args := range []string{`{"path":"/tmp/a.pem"}`, `{"path":"/etc/a.pem"}`, `{"path":"/etc/hosts"}`, `{"path":"/srv/x"}`, `{}`, `[]`} {
		s := scope
		a := args
		s.ArgumentsJSON = &a
		direct := ResolveMCPPolicy(policies, s)
		got := winner.ID
		for _, e := range chain {
			if MatchMCPArgConditions(e.ArgConditions, args, e.Action) {
				got = e.PolicyID
				break
			}
		}
		if direct == nil || direct.ID != got {
			t.Fatalf("args %s: chain evaluation %s != direct %+v", args, got, direct)
		}
	}
	// 参数未知时带条件的策略不参与（只收窄）。
	if p := ResolveMCPPolicy(policies, scope); p == nil || p.ID != "project_allow" {
		t.Fatalf("unknown arguments must ignore conditional policies, got %+v", p)
	}
	// 部门不匹配：部门策略不进链。
	other := scope
	other.DepartmentID = "d2"
	if _, c := ResolveMCPPolicyWithArgChain(policies, other); len(c) != 2 {
		t.Fatalf("department d2 must not include dept policy, got %+v", c)
	}
}

func TestWS1DepartmentRankBetweenUserAndProject(t *testing.T) {
	if !(mcpScopeRank("user") > mcpScopeRank("department") && mcpScopeRank("department") > mcpScopeRank("project")) {
		t.Fatalf("rank order wrong: user=%d department=%d project=%d", mcpScopeRank("user"), mcpScopeRank("department"), mcpScopeRank("project"))
	}
	now := time.Now()
	policies := []*MCPPolicy{
		{ID: "proj", TenantID: "t", ScopeType: "project", ScopeRef: "p1", DefaultAction: "block", Enabled: true, CreatedAt: now},
		{ID: "dept", TenantID: "t", ScopeType: "department", ScopeRef: "d1", DefaultAction: "allow", Enabled: true, CreatedAt: now},
	}
	if p := ResolveMCPPolicy(policies, MCPPolicyScope{TenantID: "t", ProjectID: "p1", DepartmentID: "d1", ToolName: "x"}); p == nil || p.ID != "dept" {
		t.Fatalf("department must outrank project, got %+v", p)
	}
	if p := ResolveMCPPolicy(policies, MCPPolicyScope{TenantID: "t", ProjectID: "p1", ToolName: "x"}); p == nil || p.ID != "proj" {
		t.Fatalf("no department must fall back to project, got %+v", p)
	}
	if MCPPoliciesUseDepartmentScope(policies[:1]) || !MCPPoliciesUseDepartmentScope(policies) {
		t.Fatalf("MCPPoliciesUseDepartmentScope wrong")
	}
}
