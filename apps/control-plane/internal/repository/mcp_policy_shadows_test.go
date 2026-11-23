package repository

import (
	"testing"
	"time"
)

// mkMCPPolicyAction 造一条指定 default_action 的测试策略（enabled=true）。
func mkMCPPolicyAction(id, tenantID, scopeType, scopeRef, serverID, toolPattern, action string, priority, ageMinutes int) *MCPPolicy {
	p := mkMCPPolicy(id, tenantID, scopeType, scopeRef, serverID, toolPattern, priority, ageMinutes)
	p.DefaultAction = action
	return p
}

// TestDetectMCPPolicyShadows 表驱动规格：block 被更宽松/更高优先 allow 遮蔽的检测，
// 覆盖 scopeRank 遮蔽 / tool 特异性遮蔽 / 不遮蔽（block 更优先）/ 作用域不相交 / server 不相交 /
// disabled allow 不遮蔽。口径与 ResolveMCPPolicy 同源。
func TestDetectMCPPolicyShadows(t *testing.T) {
	cases := []struct {
		name          string
		policies      []*MCPPolicy
		wantBlockIDs  []string // 期望被遮蔽的 block id（顺序按 policies 中 block 出现顺序）
		wantWinnerFor map[string]string
	}{
		{
			name:         "无策略：无告警",
			policies:     []*MCPPolicy{},
			wantBlockIDs: nil,
		},
		{
			name: "scopeRank 遮蔽：user 级通配 allow 覆盖 tenant 级 block",
			policies: []*MCPPolicy{
				mkMCPPolicyAction("b_tenant_block", "t_a", "tenant", "", "", "", "block", 0, 10),
				mkMCPPolicyAction("a_user_allow", "t_a", "user", "", "", "", "allow", 0, 5),
			},
			wantBlockIDs:  []string{"b_tenant_block"},
			wantWinnerFor: map[string]string{"b_tenant_block": "a_user_allow"},
		},
		{
			name: "不遮蔽：block 作用域档位更高（block 胜出）",
			policies: []*MCPPolicy{
				mkMCPPolicyAction("b_user_block", "t_a", "user", "", "", "", "block", 0, 10),
				mkMCPPolicyAction("a_tenant_allow", "t_a", "tenant", "", "", "", "allow", 0, 5),
			},
			wantBlockIDs: nil,
		},
		{
			name: "tool 特异性遮蔽：精确 allow 覆盖 glob block（同档同 server）",
			policies: []*MCPPolicy{
				mkMCPPolicyAction("b_glob_block", "t_a", "tenant", "", "srv1", "fs.*", "block", 100, 10),
				mkMCPPolicyAction("a_exact_allow", "t_a", "tenant", "", "srv1", "fs.delete", "allow", 0, 5),
			},
			wantBlockIDs:  []string{"b_glob_block"},
			wantWinnerFor: map[string]string{"b_glob_block": "a_exact_allow"},
		},
		{
			name: "不遮蔽：block 工具更精确（即便 allow priority 更高）",
			policies: []*MCPPolicy{
				mkMCPPolicyAction("b_exact_block", "t_a", "tenant", "", "srv1", "fs.delete", "block", 0, 10),
				mkMCPPolicyAction("a_glob_allow", "t_a", "tenant", "", "srv1", "fs.*", "allow", 999, 5),
			},
			wantBlockIDs: nil,
		},
		{
			name: "作用域不相交：不同 project 的 allow 不遮蔽 block",
			policies: []*MCPPolicy{
				mkMCPPolicyAction("b_proj1_block", "t_a", "project", "proj1", "", "", "block", 0, 10),
				mkMCPPolicyAction("a_proj2_allow", "t_a", "project", "proj2", "", "", "allow", 0, 5),
			},
			wantBlockIDs: nil,
		},
		{
			name: "server 不相交：指定不同 server 的 allow 不遮蔽 block",
			policies: []*MCPPolicy{
				mkMCPPolicyAction("b_srv1_block", "t_a", "tenant", "", "srv1", "", "block", 0, 10),
				mkMCPPolicyAction("a_srv2_allow", "t_a", "tenant", "", "srv2", "", "allow", 0, 5),
			},
			wantBlockIDs: nil,
		},
		{
			name: "disabled allow 不遮蔽",
			policies: []*MCPPolicy{
				mkMCPPolicyAction("b_block", "t_a", "tenant", "", "", "", "block", 0, 10),
				func() *MCPPolicy {
					p := mkMCPPolicyAction("a_disabled_allow", "t_a", "user", "", "", "", "allow", 0, 5)
					p.Enabled = false
					return p
				}(),
			},
			wantBlockIDs: nil,
		},
		{
			name: "跨租户 allow 不遮蔽",
			policies: []*MCPPolicy{
				mkMCPPolicyAction("b_block_ta", "t_a", "tenant", "", "", "", "block", 0, 10),
				mkMCPPolicyAction("a_allow_tb", "t_b", "user", "", "", "", "allow", 0, 5),
			},
			wantBlockIDs: nil,
		},
		{
			name: "wildcard-server block 被 specific-server allow 遮蔽（该 server 场景）",
			policies: []*MCPPolicy{
				mkMCPPolicyAction("b_wild_block", "t_a", "tenant", "", "", "", "block", 0, 10),
				mkMCPPolicyAction("a_srv_allow", "t_a", "tenant", "", "srv1", "", "allow", 0, 5),
			},
			wantBlockIDs:  []string{"b_wild_block"},
			wantWinnerFor: map[string]string{"b_wild_block": "a_srv_allow"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warnings := DetectMCPPolicyShadows(tc.policies)
			if len(warnings) != len(tc.wantBlockIDs) {
				t.Fatalf("警告条数=%d，期望 %d；warnings=%+v", len(warnings), len(tc.wantBlockIDs), warnings)
			}
			for i, wantID := range tc.wantBlockIDs {
				if warnings[i].ShadowedBlockID != wantID {
					t.Errorf("第 %d 条 shadowed_block_id=%q，期望 %q", i, warnings[i].ShadowedBlockID, wantID)
				}
				if want, ok := tc.wantWinnerFor[wantID]; ok && warnings[i].WinningAllowID != want {
					t.Errorf("block %s 的 winning_allow_id=%q，期望 %q", wantID, warnings[i].WinningAllowID, want)
				}
				if warnings[i].Reason == "" || warnings[i].Scope == "" {
					t.Errorf("block %s 告警缺少 reason/scope: %+v", wantID, warnings[i])
				}
			}
		})
	}
}

// TestResolveMCPPolicyCandidatesOrder 校验候选切片按解析优先级降序（胜出者在 [0]）。
func TestResolveMCPPolicyCandidatesOrder(t *testing.T) {
	now := time.Now()
	_ = now
	policies := []*MCPPolicy{
		mkMCPPolicyAction("p_tenant", "t_a", "tenant", "", "", "", "audit", 0, 30),
		mkMCPPolicyAction("p_user", "t_a", "user", "u1", "", "", "block", 0, 20),
		mkMCPPolicyAction("p_session", "t_a", "session", "s1", "", "", "allow", 0, 10),
	}
	scope := MCPPolicyScope{TenantID: "t_a", UserID: "u1", SessionID: "s1", ServerID: "srv1", ToolName: "fs.read"}
	candidates := ResolveMCPPolicyCandidates(policies, scope)
	if len(candidates) != 3 {
		t.Fatalf("候选数=%d，期望 3", len(candidates))
	}
	wantOrder := []string{"p_session", "p_user", "p_tenant"} // session(70) > user(40) > tenant(20)
	for i, want := range wantOrder {
		if candidates[i].ID != want {
			t.Errorf("候选[%d]=%s，期望 %s", i, candidates[i].ID, want)
		}
	}
	if got := ResolveMCPPolicy(policies, scope); got == nil || got.ID != "p_session" {
		t.Errorf("ResolveMCPPolicy 胜出=%v，期望 p_session", got)
	}
}
