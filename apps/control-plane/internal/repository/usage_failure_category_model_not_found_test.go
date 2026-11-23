package repository

import (
	"fmt"
	"testing"
)

// 网关新增的 request_status=model_not_found（客户端写错模型名，HTTP 404）在使用明细里
// 必须是独立的失败类别，不能落进 unknown/upstream_5xx，否则控制台无法按「模型不存在」筛选。
func TestUsageFailureCategoryDistinguishesModelNotFound(t *testing.T) {
	db, ctx, _, _, _ := setupAuditStatsRegressionFixture(t)
	query := fmt.Sprintf(`
		SELECT (%s), (%s)
		FROM (SELECT $1::text AS request_status, $2::int AS upstream_status_code, NULL::jsonb AS routing_decision_json) rl
	`, UsageRequestStatusSQL, UsageFailureCategorySQL)
	cases := []struct {
		status       string
		code         int
		wantStatus   string
		wantCategory string
	}{
		{"model_not_found", 404, "failed", "model_not_found"},
		{"model_route_unavailable", 503, "failed", "upstream_5xx"}, // 原有行为不变
		{"forbidden_model", 403, "failed", "auth_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			var gotStatus, gotCategory string
			if err := db.QueryRow(ctx, query, tc.status, tc.code).Scan(&gotStatus, &gotCategory); err != nil {
				t.Fatal(err)
			}
			if gotStatus != tc.wantStatus || gotCategory != tc.wantCategory {
				t.Fatalf("status=%q category=%q want %q/%q", gotStatus, gotCategory, tc.wantStatus, tc.wantCategory)
			}
		})
	}
}
