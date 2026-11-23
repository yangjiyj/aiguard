package repository

import (
	"testing"
	"time"
)

// mkMCPPolicy 造一条测试策略（enabled=true，created_at 用相对偏移保证可比）。
func mkMCPPolicy(id, tenantID, scopeType, scopeRef, serverID, toolPattern string, priority int, ageMinutes int) *MCPPolicy {
	return &MCPPolicy{
		ID:            id,
		TenantID:      tenantID,
		ScopeType:     scopeType,
		ScopeRef:      scopeRef,
		ServerID:      serverID,
		ToolPattern:   toolPattern,
		Mode:          "audit",
		DefaultAction: "audit",
		Priority:      priority,
		Enabled:       true,
		CreatedAt:     time.Now().Add(-time.Duration(ageMinutes) * time.Minute),
	}
}

// TestResolveMCPPolicy 是 ResolveMCPPolicy 纯函数的表驱动规格：
// 通配回退 / scopeRank 优先 / server 特定优先 / tool 精确>glob>通配 / priority /
// 全 miss 返回 nil（调用方折算默认 audit）。
func TestResolveMCPPolicy(t *testing.T) {
	scope := MCPPolicyScope{
		TenantID:  "tenant_a",
		ProjectID: "proj_1",
		UserID:    "user_1",
		KeyPrefix: "na_abc",
		AgentID:   "claude-code",
		SessionID: "sess_1",
		ServerID:  "mcp_srv1",
		ToolName:  "fs.read_file",
	}

	cases := []struct {
		name     string
		policies []*MCPPolicy
		scope    MCPPolicyScope
		wantID   string // "" = 期望全 miss（nil）
	}{
		{
			name:     "全 miss 返回 nil（默认姿态交给调用方折算 audit）",
			policies: []*MCPPolicy{},
			scope:    scope,
			wantID:   "",
		},
		{
			name: "disabled 与跨租户策略被过滤",
			policies: []*MCPPolicy{
				func() *MCPPolicy {
					p := mkMCPPolicy("p_disabled", "tenant_a", "tenant", "", "", "", 0, 10)
					p.Enabled = false
					return p
				}(),
				mkMCPPolicy("p_other_tenant", "tenant_b", "tenant", "", "", "", 0, 10),
			},
			scope:  scope,
			wantID: "",
		},
		{
			name: "租户级通配回退：无更特定策略时命中 tenant 通配",
			policies: []*MCPPolicy{
				mkMCPPolicy("p_tenant_wild", "tenant_a", "tenant", "", "", "", 0, 10),
			},
			scope:  scope,
			wantID: "p_tenant_wild",
		},
		{
			name: "scopeRank 优先：key 档位压过 tenant 档位（无关 priority）",
			policies: []*MCPPolicy{
				mkMCPPolicy("p_tenant", "tenant_a", "tenant", "", "", "", 100, 10),
				mkMCPPolicy("p_key", "tenant_a", "key", "na_abc", "", "", 0, 10),
			},
			scope:  scope,
			wantID: "p_key",
		},
		{
			name: "scopeRank 全序：session > key > agent > user > project > tenant",
			policies: []*MCPPolicy{
				mkMCPPolicy("p_tenant", "tenant_a", "tenant", "", "", "", 0, 10),
				mkMCPPolicy("p_project", "tenant_a", "project", "proj_1", "", "", 0, 10),
				mkMCPPolicy("p_user", "tenant_a", "user", "user_1", "", "", 0, 10),
				mkMCPPolicy("p_agent", "tenant_a", "agent", "claude-code", "", "", 0, 10),
				mkMCPPolicy("p_key", "tenant_a", "key", "na_abc", "", "", 0, 10),
				mkMCPPolicy("p_session", "tenant_a", "session", "sess_1", "", "", 0, 10),
			},
			scope:  scope,
			wantID: "p_session",
		},
		{
			name: "scope_ref 非空但与请求不符 = 不命中（回退到通配档）",
			policies: []*MCPPolicy{
				mkMCPPolicy("p_key_other", "tenant_a", "key", "na_zzz", "", "", 0, 10),
				mkMCPPolicy("p_tenant_wild", "tenant_a", "tenant", "", "", "", 0, 10),
			},
			scope:  scope,
			wantID: "p_tenant_wild",
		},
		{
			name: "scope_ref='' 档位通配：key 档通配仍按 key 档 rank 压过 tenant",
			policies: []*MCPPolicy{
				mkMCPPolicy("p_key_wild", "tenant_a", "key", "", "", "", 0, 10),
				mkMCPPolicy("p_tenant", "tenant_a", "tenant", "", "", "", 0, 10),
			},
			scope:  scope,
			wantID: "p_key_wild",
		},
		{
			name: "同档位下 server 特定 > server 通配",
			policies: []*MCPPolicy{
				mkMCPPolicy("p_all_servers", "tenant_a", "tenant", "", "", "", 100, 10),
				mkMCPPolicy("p_this_server", "tenant_a", "tenant", "", "mcp_srv1", "", 0, 10),
			},
			scope:  scope,
			wantID: "p_this_server",
		},
		{
			name: "server_id 指定但不符 = 不命中",
			policies: []*MCPPolicy{
				mkMCPPolicy("p_other_server", "tenant_a", "tenant", "", "mcp_srv2", "", 0, 10),
			},
			scope:  scope,
			wantID: "",
		},
		{
			name: "tool 精确 > 前缀 glob > 通配",
			policies: []*MCPPolicy{
				mkMCPPolicy("p_tool_wild", "tenant_a", "tenant", "", "", "", 100, 10),
				mkMCPPolicy("p_tool_glob", "tenant_a", "tenant", "", "", "fs.*", 100, 10),
				mkMCPPolicy("p_tool_exact", "tenant_a", "tenant", "", "", "fs.read_file", 0, 10),
			},
			scope:  scope,
			wantID: "p_tool_exact",
		},
		{
			name: "前缀 glob 只匹配同前缀工具",
			policies: []*MCPPolicy{
				mkMCPPolicy("p_net_glob", "tenant_a", "tenant", "", "", "net.*", 0, 10),
				mkMCPPolicy("p_fs_glob", "tenant_a", "tenant", "", "", "fs.*", 0, 10),
			},
			scope:  scope,
			wantID: "p_fs_glob",
		},
		{
			name: "维度特异性全部打平时按 priority 取大",
			policies: []*MCPPolicy{
				mkMCPPolicy("p_low", "tenant_a", "tenant", "", "", "", 1, 10),
				mkMCPPolicy("p_high", "tenant_a", "tenant", "", "", "", 9, 10),
			},
			scope:  scope,
			wantID: "p_high",
		},
		{
			name: "priority 也打平时取 created_at 较新者",
			policies: []*MCPPolicy{
				mkMCPPolicy("p_old", "tenant_a", "tenant", "", "", "", 5, 60),
				mkMCPPolicy("p_new", "tenant_a", "tenant", "", "", "", 5, 1),
			},
			scope:  scope,
			wantID: "p_new",
		},
		{
			name: "组合案例：key+server+tool 精确三特定压过一切",
			policies: []*MCPPolicy{
				mkMCPPolicy("p_tenant_wild", "tenant_a", "tenant", "", "", "", 100, 10),
				mkMCPPolicy("p_key_glob", "tenant_a", "key", "na_abc", "", "fs.*", 100, 10),
				mkMCPPolicy("p_key_exact", "tenant_a", "key", "na_abc", "mcp_srv1", "fs.read_file", 0, 10),
			},
			scope:  scope,
			wantID: "p_key_exact",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveMCPPolicy(tc.policies, tc.scope)
			if tc.wantID == "" {
				if got != nil {
					t.Fatalf("want nil (miss), got %s", got.ID)
				}
				return
			}
			if got == nil {
				t.Fatalf("want %s, got nil", tc.wantID)
			}
			if got.ID != tc.wantID {
				t.Fatalf("want %s, got %s", tc.wantID, got.ID)
			}
		})
	}
}

// TestMCPToolPatternMatches 覆盖工具模式匹配的边界：通配/精确/前缀 glob/不匹配。
func TestMCPToolPatternMatches(t *testing.T) {
	cases := []struct {
		pattern string
		tool    string
		want    bool
	}{
		{"", "anything", true},
		{"*", "anything", true},
		{"fs.read_file", "fs.read_file", true},
		{"fs.read_file", "fs.read_dir", false},
		{"fs.*", "fs.read_file", true},
		{"fs.*", "fsx.read", false}, // 前缀 glob 含点边界，不做裸前缀误匹配
		{"net.*", "fs.read_file", false},
	}
	for _, tc := range cases {
		if got := mcpToolPatternMatches(tc.pattern, tc.tool); got != tc.want {
			t.Errorf("mcpToolPatternMatches(%q, %q) = %v, want %v", tc.pattern, tc.tool, got, tc.want)
		}
	}
}
