package repository

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"

	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"github.com/yangjiyj/aiguard/packages/shared-go/logretention"
	"github.com/jackc/pgx/v5"
)

// CredentialHit 只包含可交给连接器的元数据，不携带正文、命中片段或凭据材料。
type CredentialHit struct {
	ID        string    `json:"id"`
	KeyID     string    `json:"key_id"`
	CreatedAt time.Time `json:"created_at"`
	Category  string    `json:"category"`
	PolicyID  string    `json:"policy_id,omitempty"`
	Action    string    `json:"action"`
	Model     string    `json:"model,omitempty"`
}

type CredentialHitsPage struct {
	Data       []CredentialHit `json:"data"`
	NextCursor string          `json:"next_cursor"`
	Since      time.Time       `json:"since"`
	Until      time.Time       `json:"until"`
}

type CredentialHitsQuery struct {
	KeyID        string
	Since, Until time.Time
	Cursor       string
	Limit        int
	afterAt      time.Time
	afterID      string
}

type credentialHitsCursor struct {
	Version int       `json:"v"`
	Tenant  string    `json:"tenant"`
	KeyID   string    `json:"key"`
	Since   time.Time `json:"since"`
	Until   time.Time `json:"until"`
	AfterAt time.Time `json:"after_at"`
	AfterID string    `json:"after_id"`
}

// NormalizeCredentialHitsQuery 固定分页窗口；窗口左闭右开，最多七天。
// 游标只是翻页位置，不能替代鉴权；每页仍按当前身份核验租户与专用凭据。
func NormalizeCredentialHitsQuery(tenant string, q CredentialHitsQuery, now time.Time) (CredentialHitsQuery, error) {
	if !ai.ValidID(tenant) || !ai.ValidID(q.KeyID) || q.Limit < 0 || q.Limit > 200 {
		return q, ai.ErrInvalid
	}
	if q.Limit == 0 {
		q.Limit = 100
	}
	if q.Cursor != "" {
		if len(q.Cursor) > 2048 {
			return q, ai.ErrInvalid
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(q.Cursor)
		if err != nil {
			return q, ai.ErrInvalid
		}
		var c credentialHitsCursor
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&c) != nil || decoder.Decode(&struct{}{}) != io.EOF || c.Version != 1 || c.Tenant != tenant || c.KeyID != q.KeyID || !ai.ValidID(c.AfterID) || c.AfterAt.IsZero() {
			return q, ai.ErrInvalid
		}
		if (!q.Since.IsZero() && !q.Since.Equal(c.Since)) || (!q.Until.IsZero() && !q.Until.Equal(c.Until)) {
			return q, ai.ErrInvalid
		}
		q.Since, q.Until, q.afterAt, q.afterID = c.Since, c.Until, c.AfterAt, c.AfterID
	}
	if q.Until.IsZero() {
		q.Until = now.UTC()
	}
	if q.Since.IsZero() {
		q.Since = q.Until.Add(-7 * 24 * time.Hour)
	}
	q.Since, q.Until = q.Since.UTC(), q.Until.UTC()
	if !q.Since.Before(q.Until) || q.Until.Sub(q.Since) > 7*24*time.Hour || (!q.afterAt.IsZero() && (q.afterAt.Before(q.Since) || !q.afterAt.Before(q.Until))) {
		return q, ai.ErrInvalid
	}
	return q, nil
}

func integrationMetadataReadTx(ctx context.Context, r *IntegrationRepository, tenant, key string) (pgx.Tx, error) {
	if !ai.ValidID(tenant) || !ai.ValidID(key) {
		return nil, ai.ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	var exists bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM internal_keys WHERE tenant_id=$1 AND id=$2 AND NULLIF(btrim(agent_instance_id),'') IS NOT NULL)`, tenant, key).Scan(&exists)
	if err != nil || !exists {
		_ = tx.Rollback(ctx)
		if err == nil {
			err = ai.ErrNotFound
		}
		return nil, err
	}
	return tx, nil
}

func (r *IntegrationRepository) CredentialHits(ctx context.Context, tenant string, query CredentialHitsQuery) (*CredentialHitsPage, error) {
	q, err := NormalizeCredentialHitsQuery(tenant, query, time.Now())
	if err != nil {
		return nil, err
	}
	tx, err := integrationMetadataReadTx(ctx, r, tenant, q.KeyID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// 只读事件本身的实际动作，不按当前策略配置倒推历史动作。
	// LATERAL 每个原生事件只选一个主命中，避免 findings 展开造成重复计数。
	// 不回传 matched_summary，只在数据库内提取固定的分类与策略编号。
	rows, err := tx.Query(ctx, `
	SELECT se.id,rl.client_id,se.created_at,hit.category,hit.policy_id,
	       CASE se.action_taken
	         WHEN 'block' THEN 'block' WHEN 'security_blocked' THEN 'block' WHEN 'stream_blocked' THEN 'block'
	         WHEN 'mask' THEN 'mask' WHEN 'security_masked' THEN 'mask'
	         ELSE 'audit' END,
	       CASE WHEN hit.category='key_model_outside_allowlist'
	         THEN COALESCE(rl.routing_decision_json #>> '{model_route_v2,requested_model}','') ELSE '' END
	FROM security_events se
	JOIN request_logs rl ON rl.tenant_id=se.tenant_id AND rl.request_id=se.request_id
	CROSS JOIN LATERAL (
	  SELECT CASE WHEN f.value->>'category'='key_model_outside_allowlist'
	           THEN 'key_model_outside_allowlist' ELSE 'dlp:'||(f.value->>'category') END AS category,
	         CASE WHEN f.value->>'category'='key_model_outside_allowlist' THEN '' ELSE f.value->>'rule_id' END AS policy_id
	  FROM jsonb_array_elements(CASE WHEN jsonb_typeof(se.matched_summary->'findings')='array'
	         THEN se.matched_summary->'findings' ELSE '[]'::jsonb END) WITH ORDINALITY AS f(value,ordinal)
	  WHERE COALESCE(f.value->'counts_as_security_finding','true'::jsonb)='true'::jsonb
	    AND (f.value->>'category'='key_model_outside_allowlist'
	      OR (f.value->>'policy_scene'='data_leak'
	        AND NULLIF(btrim(f.value->>'policy_code'),'') IS NOT NULL
	        AND f.value->>'rule_id' ~ '^[a-zA-Z0-9_-]{1,128}$'
	        AND f.value->>'category' ~ '^[a-z][a-z0-9_]{0,127}$'
	        AND jsonb_typeof(f.value->'matched_capabilities')='array'
	        AND (f.value->'matched_capabilities') ? (f.value->>'category')))
	  -- 主命中：2.9.22 起 primary_finding 只引用 findings 的下标（findings_index），先按序号对上；
	  -- 旧数据整条复制过，再按整条相等。
	  ORDER BY (f.ordinal-1 = CASE WHEN se.matched_summary#>>'{primary_finding,findings_index}' ~ '^[0-9]{1,9}$'
	             THEN (se.matched_summary#>>'{primary_finding,findings_index}')::int END) DESC NULLS LAST,
	           (f.value=se.matched_summary->'primary_finding') DESC NULLS LAST,f.ordinal
	  LIMIT 1
	) hit
	WHERE se.tenant_id=$1 AND rl.client_id=$2
	  AND se.created_at >= $3 AND se.created_at < $4
	  AND COALESCE(se.matched_summary->'counts_as_security_finding','true'::jsonb)='true'::jsonb
	  AND se.action_taken IN ('audit','log','security_audit','security_audit_only','block','security_blocked','stream_blocked','mask','security_masked')
	  AND ($5='' OR (se.created_at,se.id) < ($6::timestamptz,$5::text))
	ORDER BY se.created_at DESC,se.id DESC LIMIT $7`, tenant, q.KeyID, q.Since, q.Until, q.afterID, q.afterAt, q.Limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &CredentialHitsPage{Data: []CredentialHit{}, Since: q.Since, Until: q.Until}
	for rows.Next() {
		var hit CredentialHit
		if err = rows.Scan(&hit.ID, &hit.KeyID, &hit.CreatedAt, &hit.Category, &hit.PolicyID, &hit.Action, &hit.Model); err != nil {
			return nil, err
		}
		page.Data = append(page.Data, hit)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Data) > q.Limit {
		page.Data = page.Data[:q.Limit]
		last := page.Data[len(page.Data)-1]
		raw, err := json.Marshal(credentialHitsCursor{Version: 1, Tenant: tenant, KeyID: q.KeyID, Since: q.Since, Until: q.Until, AfterAt: last.CreatedAt, AfterID: last.ID})
		if err != nil {
			return nil, err
		}
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return page, nil
}

type CredentialRetentionStatus struct {
	KeyID             string     `json:"key_id"`
	LogRetentionDays  int        `json:"log_retention_days"`
	HasContentLogs24h bool       `json:"has_content_logs_24h"`
	LastContentLogAt  *time.Time `json:"last_content_log_at"`
}

func (r *IntegrationRepository) CredentialRetentionStatus(ctx context.Context, tenant, key string, now time.Time) (*CredentialRetentionStatus, error) {
	tx, err := integrationMetadataReadTx(ctx, r, tenant, key)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var raw string
	if err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT value FROM system_settings WHERE key=$1),'')`, logretention.SettingKey).Scan(&raw); err != nil {
		return nil, err
	}
	status := &CredentialRetentionStatus{KeyID: key, LogRetentionDays: logretention.Resolve(strings.TrimSpace(raw))}
	// 两套留存的关联键不同；所有表都复核租户。只读取时间，不读取任何内容列。
	err = tx.QueryRow(ctx, `SELECT max(created_at) FROM (
	  SELECT cl.created_at AT TIME ZONE 'UTC' AS created_at
	  FROM content_logs cl JOIN request_logs rl ON rl.id=cl.request_id AND rl.tenant_id=cl.tenant_id
	  WHERE cl.tenant_id=$1 AND rl.client_id=$2
	    AND cl.created_at >= ($3::timestamptz AT TIME ZONE 'UTC') AND cl.created_at <= ($4::timestamptz AT TIME ZONE 'UTC')
	  UNION ALL
	  SELECT acl.created_at FROM access_content_logs acl
	  JOIN request_logs rl ON rl.request_id=acl.request_id AND rl.tenant_id=acl.tenant_id
	  WHERE acl.tenant_id=$1 AND rl.client_id=$2 AND acl.created_at >= $3 AND acl.created_at <= $4
	) logs`, tenant, key, now.UTC().Add(-24*time.Hour), now.UTC()).Scan(&status.LastContentLogAt)
	if err != nil {
		return nil, err
	}
	status.HasContentLogs24h = status.LastContentLogAt != nil
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return status, nil
}
