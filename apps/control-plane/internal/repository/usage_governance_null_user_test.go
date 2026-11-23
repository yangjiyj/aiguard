package repository

import (
	"fmt"
	"testing"
	"time"
)

// chat-portal (A2) 回归守护：portal 机器通道发放的无归属 key（user_id=NULL）会产生
// 有真实费用的 chat_completion 行。getAnomalyRecommendations 按 rl.user_id 分组后把
// user_id 扫进裸 string——NULL 分组一旦近 1 小时费用超过 AnomalyCostFloor(=1)，
// pgx Scan NULL 进 *string 直接报错，连带 GetCostRecommendations（费用治理建议端点）
// 对整个租户挂掉。该测试锁定：NULL user_id 分组必须规整为空串、读取不得报错，
// 且有归属用户的异常识别行为不变。
func TestAnomalyRecommendationsHandleNullUserID(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	repo := NewUsageDailyRepository(db)

	suffix := time.Now().UnixNano()
	now := time.Now().UTC()

	// 无归属行：user_id 显式 NULL，费用超过 AnomalyCostFloor(=1)。
	nullReqID := fmt.Sprintf("req_anomaly_null_%d", suffix)
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, total_cost, created_at)
		VALUES ($1, $1, $2, $3, NULL, 'chat_completion', 'success', 5.0, $4)
	`, nullReqID, tenantID, projectID, now); err != nil {
		t.Fatalf("insert null-user request log: %v", err)
	}

	// 有归属行：回归护栏，归属用户的异常识别不受 NULL 规整影响。
	ownedReqID := fmt.Sprintf("req_anomaly_owned_%d", suffix)
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, total_cost, created_at)
		VALUES ($1, $1, $2, $3, $4, 'chat_completion', 'success', 6.0, $5)
	`, ownedReqID, tenantID, projectID, userID, now); err != nil {
		t.Fatalf("insert owned request log: %v", err)
	}

	scope := UsageScope{TenantID: tenantID, FullTenant: true}
	recs, err := repo.getAnomalyRecommendations(ctx, scope, now.Add(-24*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("getAnomalyRecommendations must tolerate NULL user_id groups, got: %v", err)
	}

	foundNull, foundOwned := false, false
	for _, rec := range recs {
		if rec.ID != "user_cost_anomaly" {
			continue
		}
		switch rec.UserID {
		case "":
			foundNull = true
		case userID:
			foundOwned = true
		}
	}
	if !foundNull {
		t.Fatalf("expected anomaly rec for NULL user_id group (normalized to empty string), got %+v", recs)
	}
	if !foundOwned {
		t.Fatalf("expected anomaly rec for attributed user %s, got %+v", userID, recs)
	}
}
