package repository

import (
	"fmt"
	"testing"
	"time"
)

// 反向代理写入的 content_logs 没有绑定用户（user_id 为 NULL）。
// 读路径若把 user_id 直接 Scan 进非空 string，会在 NULL 行上报错，
// 导致安全告警详情(ListByRequest)与内容数据安全会话详情(ListBySession)整体 400。
// 该回归测试锁定：NULL user_id 必须被规整为空串，读取不得报错。
func TestContentLogReadHandlesNullUserID(t *testing.T) {
	db, ctx, tenantID, _, projectID := setupAuditStatsRegressionFixture(t)

	suffix := time.Now().UnixNano()
	requestID := fmt.Sprintf("req_rp_null_user_%d", suffix)
	externalRequestID := fmt.Sprintf("external_rp_null_user_%d", suffix)
	rowID := fmt.Sprintf("log_rp_null_user_%d", suffix)
	sessionID := fmt.Sprintf("sess_rp_null_user_%d", suffix)
	now := time.Now().UTC()

	// content_logs.request_id stores request_logs.id, while callers may use either
	// that log ID or the external request_id UUID-like value.
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, endpoint_type, request_status, proxy_mode, created_at)
		VALUES ($1, $2, $3, $4, 'proxy', 'success', 'reverse', $5)
	`, requestID, externalRequestID, tenantID, projectID, now); err != nil {
		t.Fatalf("insert request log: %v", err)
	}

	// 反向代理内容日志：user_id 显式为 NULL。
	if _, err := db.Exec(ctx, `
		INSERT INTO content_logs (id, request_id, tenant_id, user_id, session_id, role, content, tokens, created_at)
		VALUES ($1, $2, $3, NULL, $4, 'user', '反代上行内容', 12, $5)
	`, rowID+"_u", requestID, tenantID, sessionID, now); err != nil {
		t.Fatalf("insert null-user content log (user): %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO content_logs (id, request_id, tenant_id, user_id, session_id, role, content, tokens, created_at)
		VALUES ($1, $2, $3, NULL, $4, 'assistant', '反代下行内容', 34, $5)
	`, rowID+"_a", requestID, tenantID, sessionID, now.Add(time.Second)); err != nil {
		t.Fatalf("insert null-user content log (assistant): %v", err)
	}

	repo := NewContentLogRepository(db)

	byReq, err := repo.ListByRequest(ctx, tenantID, requestID)
	if err != nil {
		t.Fatalf("ListByRequest must tolerate NULL user_id, got: %v", err)
	}
	if len(byReq) != 2 {
		t.Fatalf("expected 2 content logs by request, got %d", len(byReq))
	}
	for _, l := range byReq {
		if l.UserID != "" {
			t.Fatalf("expected NULL user_id normalized to empty string, got %q", l.UserID)
		}
	}
	byExternalRequest, err := repo.ListByRequest(ctx, tenantID, externalRequestID)
	if err != nil {
		t.Fatalf("ListByRequest must accept external request_id, got: %v", err)
	}
	if len(byExternalRequest) != 2 {
		t.Fatalf("expected 2 content logs by external request_id, got %d", len(byExternalRequest))
	}

	bySession, err := repo.ListBySession(ctx, tenantID, sessionID)
	if err != nil {
		t.Fatalf("ListBySession must tolerate NULL user_id, got: %v", err)
	}
	if len(bySession) != 2 {
		t.Fatalf("expected 2 content logs by session, got %d", len(bySession))
	}
}
