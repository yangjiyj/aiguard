package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 额度准入的“预留超出”通知。
//
// 准入时按估算冻结额度，结算时按实际用量入账（超出部分照实记账，只发通知、不阻断）。
// 当估算偏低时，每个请求结算都会超出一次；原先每次写一条消息中心通知，一天可积压上万条同一事实。
// 这里把“同一租户、同一主体（用户，没有则按 key）、同一模型、同一类型、同一天”的超出合并成
// 一条未读通知，条数、峰值、累计超出量都写进 body，事实一个不丢，只是不再重复刷屏。
// 运维把这一条标为已读后，再发生的超出会重新开一条。
const (
	quotaOverrunTokenEvent = "quota.admission.reservation_overrun"
	quotaOverrunCostEvent  = "quota.admission.cost_reservation_overrun"
)

// quotaOverrunNow 让测试可以固定“现在”，跨天聚合边界才好验证。
var quotaOverrunNow = time.Now

func isQuotaOverrunEvent(eventType string) bool {
	return eventType == quotaOverrunTokenEvent || eventType == quotaOverrunCostEvent
}

func quotaOverrunUnit(eventType string) string {
	if eventType == quotaOverrunCostEvent {
		return "micros"
	}
	return "tokens"
}

// 额度默认时区与配额准入一致（Asia/Shanghai）。时区库缺失时退回固定 +8，避免精简镜像里聚合键失效。
func quotaOverrunLocation() *time.Location {
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return time.FixedZone("CST", 8*3600)
	}
	return location
}

func quotaOverrunDay(at time.Time) string {
	return at.In(quotaOverrunLocation()).Format("2006-01-02")
}

// quotaOverrunDayStart 是 at 所在本地日期的 0 点。同一聚合组的行都创建于当天 0 点之后，
// 查找时带上这个下界，才能走 (tenant_id, created_at) 索引，而不是每个事件都扫整个未读队列。
func quotaOverrunDayStart(at time.Time) time.Time {
	local := at.In(quotaOverrunLocation())
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, local.Location())
}

// quotaOverrunGroupKey 是聚合键：租户 + 类型 + 主体 + 模型 + 本地日期。
// 主体优先取用户（同一个人换 key 仍是同一个人），没有用户身份时退回按 key。
func quotaOverrunGroupKey(eventType string, env *modelrouter.RequestEnvelope, at time.Time) string {
	principal := ""
	switch {
	case env == nil:
	case strings.TrimSpace(env.UserID) != "":
		principal = "user:" + env.UserID
	case strings.TrimSpace(env.ClientID) != "":
		principal = "key:" + env.ClientID
	default:
		principal = "unknown"
	}
	tenant, model := "", ""
	if env != nil {
		tenant, model = env.TenantID, env.Model
	}
	return strings.Join([]string{"quota-overrun", eventType, tenant, principal, model, quotaOverrunDay(at)}, "|")
}

func bodyInt64(body map[string]any, key string) int64 {
	switch value := body[key].(type) {
	case float64:
		return int64(value)
	case int64:
		return value
	case int:
		return int64(value)
	case json.Number:
		parsed, _ := value.Int64()
		return parsed
	}
	return 0
}

func maxInt64Value(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

// quotaOverrunCreatedAtRefreshInterval 是合并更新时刷新 created_at 的最小间隔。
// created_at 是 alert_inbox 两个索引的键列，每次都刷新会让 UPDATE 失去 HOT（实测 HOT 96%→0%，
// WAL 约 2.7 倍），所以按窗口节流：窗口内只改 body_json（最近发生时间看 body.last_seen_at），
// 超过窗口再把 created_at 刷到最近发生时间，消息中心排序最多滞后这个间隔。
const quotaOverrunCreatedAtRefreshInterval = time.Minute

// 进程内按聚合键排队。必须在向连接池要连接之前排队：否则同键的并发写都先占住一条池连接，
// 再在数据库里等 advisory lock，磁盘慢时会排出秒级队列、占满连接池并让后续事件超时丢失。
type quotaOverrunKeyLock struct {
	slot chan struct{}
	refs int
}

var quotaOverrunKeyLocks = struct {
	sync.Mutex
	byKey map[string]*quotaOverrunKeyLock
}{byKey: map[string]*quotaOverrunKeyLock{}}

// lockQuotaOverrunKey 获取聚合键的进程内锁，等待期间不占用任何数据库连接，并响应 ctx 取消。
func lockQuotaOverrunKey(ctx context.Context, key string) (func(), error) {
	registry := &quotaOverrunKeyLocks
	registry.Lock()
	entry := registry.byKey[key]
	if entry == nil {
		entry = &quotaOverrunKeyLock{slot: make(chan struct{}, 1)}
		registry.byKey[key] = entry
	}
	entry.refs++
	registry.Unlock()

	drop := func() {
		registry.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(registry.byKey, key)
		}
		registry.Unlock()
	}
	select {
	case entry.slot <- struct{}{}:
		return func() {
			<-entry.slot
			drop()
		}, nil
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}
}

// recordQuotaOverrunAlert 写入或合并一条“预留超出”通知。先在进程内按聚合键排队，再开事务；
// 事务里仍保留按聚合键的 advisory lock，只作为多实例之间的兜底（此时同进程内已无同键竞争）。
// 事务内 SET LOCAL synchronous_commit = off：告警是只增的统计事实，宁可极端崩溃丢最后几毫秒，
// 也不让热路径等磁盘刷盘。失败只记日志，不影响请求。
func recordQuotaOverrunAlert(ctx context.Context, db *pgxpool.Pool, d governor.Decision, env *modelrouter.RequestEnvelope, eventType string) {
	if db == nil || env == nil {
		return
	}
	now := quotaOverrunNow()
	groupKey := quotaOverrunGroupKey(eventType, env, now)
	overrun := d.Actual - d.Estimated
	if overrun < 0 {
		overrun = 0
	}
	stamp := now.UTC().Format(time.RFC3339)

	lockKey := env.TenantID + "\x1f" + groupKey
	release, err := lockQuotaOverrunKey(ctx, lockKey)
	if err != nil {
		log.Printf("[quota.overrun_alert] queue failed: %v", err)
		return
	}
	defer release()

	tx, err := db.Begin(ctx)
	if err != nil {
		log.Printf("[quota.overrun_alert] begin failed: %v", err)
		return
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL synchronous_commit = off`); err != nil {
		log.Printf("[quota.overrun_alert] set synchronous_commit failed: %v", err)
		return
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		log.Printf("[quota.overrun_alert] lock failed: %v", err)
		return
	}

	var existingID string
	var existingRaw []byte
	var existingCreatedAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, body_json, created_at FROM alert_inbox
		WHERE tenant_id = $1 AND created_at >= $4 AND type = $2 AND read_at IS NULL AND body_json->>'group_key' = $3
		ORDER BY created_at DESC LIMIT 1
		FOR UPDATE`, env.TenantID, eventType, groupKey, quotaOverrunDayStart(now)).Scan(&existingID, &existingRaw, &existingCreatedAt)

	switch {
	case errors.Is(err, pgx.ErrNoRows):
		body := map[string]any{
			"triggered_scope": d.TriggeredScope, "triggered_metric": d.TriggeredMetric,
			"key_prefix": env.KeyPrefix, "project_id": env.ProjectID, "tenant_id": env.TenantID, "team_id": env.TeamID,
			"downgrade_to": d.DowngradeTo, "reason": d.Reason, "alert_only": d.AlertOnly,
			"user_id": env.UserID, "model": env.Model, "unit": quotaOverrunUnit(eventType), "day": quotaOverrunDay(now),
			"group_key": groupKey, "occurrence_count": 1, "first_seen_at": stamp, "last_seen_at": stamp,
			"sample_request_id": env.RequestID,
			"max_estimated":     d.Estimated, "max_actual": d.Actual, "max_overrun": overrun, "total_overrun": overrun,
		}
		encoded, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			log.Printf("[quota.overrun_alert] encode failed: %v", marshalErr)
			return
		}
		if _, err = tx.Exec(ctx, `
			INSERT INTO alert_inbox (id, tenant_id, severity, type, title, body_json, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			newAuditID("alert_"), env.TenantID, "warning", eventType, governorAlertTitle(eventType, d.Reason), encoded, now); err != nil {
			log.Printf("[quota.overrun_alert] insert failed: %v", err)
			return
		}
	case err != nil:
		log.Printf("[quota.overrun_alert] lookup failed: %v", err)
		return
	default:
		body := map[string]any{}
		if unmarshalErr := json.Unmarshal(existingRaw, &body); unmarshalErr != nil || body == nil {
			body = map[string]any{}
		}
		body["occurrence_count"] = bodyInt64(body, "occurrence_count") + 1
		body["last_seen_at"] = stamp
		body["sample_request_id"] = env.RequestID
		body["max_estimated"] = maxInt64Value(bodyInt64(body, "max_estimated"), d.Estimated)
		body["max_actual"] = maxInt64Value(bodyInt64(body, "max_actual"), d.Actual)
		body["max_overrun"] = maxInt64Value(bodyInt64(body, "max_overrun"), overrun)
		body["total_overrun"] = bodyInt64(body, "total_overrun") + overrun
		encoded, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			log.Printf("[quota.overrun_alert] encode failed: %v", marshalErr)
			return
		}
		// 默认只更新 body_json（不动索引列，UPDATE 可走 HOT）；距上次刷新超过节流窗口时，
		// 同时把 created_at 刷到最近发生时间，让消息中心按 created_at 排序能冒到前面。
		if now.Sub(existingCreatedAt) >= quotaOverrunCreatedAtRefreshInterval {
			_, err = tx.Exec(ctx, `UPDATE alert_inbox SET body_json = $2::jsonb, created_at = $3 WHERE id = $1`, existingID, encoded, now)
		} else {
			_, err = tx.Exec(ctx, `UPDATE alert_inbox SET body_json = $2::jsonb WHERE id = $1`, existingID, encoded)
		}
		if err != nil {
			log.Printf("[quota.overrun_alert] update failed: %v", err)
			return
		}
	}
	if err = tx.Commit(ctx); err != nil {
		log.Printf("[quota.overrun_alert] commit failed: %v", err)
	}
}
