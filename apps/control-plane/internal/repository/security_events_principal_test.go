package repository

import "testing"

// TestResolvePrincipalKey 覆盖 Plan D 契约第 6 条在管理面写入点的物化回退：
// principal_key = COALESCE(PrincipalKey, UserID)。
// 管理面/评估链路多带用户上下文，故显式 PrincipalKey 优先，缺省回退 UserID；
// 二者皆空则空串（由 SQL 侧 NULLIF 落 NULL，计数口径回退 request_id）。
// 该纯逻辑无需真 PG，独立单测（遵循 audit.go 现状：Upsert 的 DB 路径由集成链路另测）。
func TestResolvePrincipalKey(t *testing.T) {
	cases := []struct {
		name         string
		principalKey string
		userID       string
		want         string
	}{
		{"explicit_principal_wins", "u-42", "u-fallback", "u-42"},
		{"fallback_to_userid", "", "u-fallback", "u-fallback"},
		{"both_empty", "", "", ""},
		{"principal_only", "u-42", "", "u-42"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolvePrincipalKey(c.principalKey, c.userID); got != c.want {
				t.Fatalf("resolvePrincipalKey(%q, %q) = %q, want %q", c.principalKey, c.userID, got, c.want)
			}
		})
	}
}
