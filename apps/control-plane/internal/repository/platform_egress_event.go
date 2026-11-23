package repository

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type platformEgressEventExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// platformEgressProject 返回事件挂靠的项目：该租户自己的默认项目（启用的、名为“默认应用”的优先，
// 再按创建时间）。租户一个项目都没有时 ok=false：不新建项目，也不挂到别的租户。
func platformEgressProject(ctx context.Context, db platformEgressEventExecer, tenantID string) (project string, ok bool, err error) {
	err = db.QueryRow(ctx, `
		SELECT id FROM projects WHERE tenant_id = $1
		ORDER BY (status = 'active') DESC, (name = '默认应用') DESC, created_at NULLS LAST, id
		LIMIT 1`, tenantID).Scan(&project)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return project, true, nil
}

// RecordPlatformEgressDenied 记一条“平台自身出站被防跳板拒绝”的安全事件（通知渠道、身份源、LDAP，
// 设计 5.2）。和运行故障事件一样先建一条请求日志挂靠：endpoint_type/proxy_mode=platform_egress，
// 项目取该租户自己的默认项目（没有项目时只打日志、返回空 ID）；request_status=recorded（不是业务成功或失败），audit_outcome 直接 completed（不让审计流水线挂起），
// 事件的 request_id 指向它；同一条语句写入。
func RecordPlatformEgressDenied(ctx context.Context, db platformEgressEventExecer, tenantID, environmentScope, kind, target string) (string, error) {
	projectID, ok, err := platformEgressProject(ctx, db, tenantID)
	if err != nil {
		return "", err
	}
	if !ok {
		// 没有项目的租户只打日志：挂到平台租户会让平台租户里的租户级用户和门户集成看到别的租户的出站目标。
		log.Printf("platform egress denied (tenant has no project, event not recorded): tenant=%s kind=%s target=%s", tenantID, kind, target)
		return "", nil
	}
	eventID := "evt_" + uuid.New().String()[:16]
	requestID := "pegress_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:20]
	summary, _ := json.Marshal(map[string]string{
		"source": "platform_egress", "kind": kind, "target": target,
		"summary": "平台自身出站目标未通过防跳板出站校验（内网、回环、链路本地或元数据）",
	})
	_, err = db.Exec(ctx, `
		WITH rl AS (
			INSERT INTO request_logs (id, request_id, tenant_id, project_id, endpoint_type, request_status, proxy_mode, environment_scope, audit_outcome, created_at)
			VALUES ($1, $1, $2, $3, 'platform_egress', 'recorded', 'platform_egress', COALESCE(NULLIF($4, ''), 'legacy-unclassified'), 'completed', NOW())
			RETURNING request_id
		)
		INSERT INTO security_events (id, request_id, tenant_id, project_id, event_type, severity, action_taken, matched_summary, evidence_ref, created_at)
		SELECT $5, rl.request_id, $2, $3, 'platform_egress_denied', 'medium', 'block', $6, 'request_logs:' || rl.request_id, NOW() FROM rl`,
		requestID, tenantID, projectID, strings.TrimSpace(environmentScope), eventID, summary)
	if err != nil {
		return "", err
	}
	return eventID, nil
}
