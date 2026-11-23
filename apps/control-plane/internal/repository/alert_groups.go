package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/alertcounter"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("not found")

type AlertGroupStatus string

const (
	AlertGroupStatusOpen          AlertGroupStatus = "open"
	AlertGroupStatusAcknowledged  AlertGroupStatus = "acknowledged"
	AlertGroupStatusResolved      AlertGroupStatus = "resolved"
	AlertGroupStatusFalsePositive AlertGroupStatus = "false_positive"
)

type AlertGroup struct {
	ID                    string
	TenantID              string
	ProjectID             string
	GroupKey              string
	Status                AlertGroupStatus
	Severity              string
	AlertType             string
	Title                 string
	RepresentativeEventID string
	RequestID             string
	OccurrenceCount       int
	BodyJSON              map[string]any
	FirstSeenAt           time.Time
	LastSeenAt            time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
	// P0-A 生命周期重设计新增列（情境/分档/三闸），持久化在 alert_groups：
	EffectiveSeverity string // 情境计算严重度（区别于 authored severity）
	DispositionClass  string // action_required | informational | suppressed
	ClassKey          string // 比 group_key 粗一档的类签名（按类折叠用）
	PrincipalKey      string // 归一化主体键 <tenant>|<type>:<id>
	IsCanary          bool   // 命中蜜签（G1 一票否决，永不自动关/降级）
	Stage             string // input | output | tool（可靠 stage；空=未知，TTL fail-closed）
	// Domain 是风险域维度（迁移 941）：content | tool | skill | mcp | access | system。
	Domain string
	// SourceIP / AccessDirection 由代表请求关联 request_logs 得到（来源 IP 与流量方向），
	// 用于安全告警列表直接展示「方向/来源」，无对应请求时为空。
	SourceIP        string
	AccessDirection string
	// P1-D 主指标（迁移 108）：幂等重算结果。LastCalcAt 为 Unix 零值（to_timestamp(0) 哨兵）
	// 表示存量回算尚未覆盖——UI 显示 occurrence_count 兜底并标注"回算中"。
	DistinctOccurrences int
	AffectedUsers       int
	LastCalcAt          time.Time
}

type AlertGroupUpsertInput struct {
	TenantID              string
	ProjectID             string
	GroupKey              string
	Severity              string
	AlertType             string
	Title                 string
	RepresentativeEventID string
	RequestID             string
	OccurredAt            time.Time
	BodyJSON              map[string]any
	// P0-A 生命周期列（由 SecEventBridge 计算后填入；is_canary 在 UPDATE 走 sticky-OR）
	EffectiveSeverity string
	DispositionClass  string
	ClassKey          string
	PrincipalKey      string
	IsCanary          bool
	Stage             string
	// Domain 风险域（由 SecEventBridge/写入方按事件派生后传入；空值落 'content'）。
	Domain string
}

type AlertGroupListFilter struct {
	TenantID         string
	Status           AlertGroupStatus
	Severity         string
	DispositionClass string
	AccessDirection  string
	// ProjectIDs 非空时把结果收窄到这些 project（部门主管按本部门 project 集看告警）。
	ProjectIDs []string
	// IncludeDevTraffic explicitly includes development-scope semantic/runtime groups.
	IncludeDevTraffic bool
	// Domain 非空时按风险域过滤（content/tool/skill/mcp/access/system）。
	Domain string
	// AlertType 非空时按告警类型精确过滤（security_event/runtime_fault/access_governance/...）。
	AlertType string
	// Rule 非空时按规则过滤：规则名称包含匹配，或规则 id 精确匹配（取自 body_json）。
	Rule string
	// LastSeenFrom/LastSeenTo 按最近发生时间过滤，左闭右开；零值表示不限。
	LastSeenFrom time.Time
	LastSeenTo   time.Time
	Limit        int
	Offset       int
}

type AlertGroupPage struct {
	FoldedDevelopmentGroups int
	Items                   []*AlertGroup
	Total                   int
	HasAny                  bool
	Limit                   int
	Offset                  int
}

type AlertGroupRepository struct {
	db *pgxpool.Pool
}

func NewAlertGroupRepository(db *pgxpool.Pool) *AlertGroupRepository {
	return &AlertGroupRepository{db: db}
}

func (r *AlertGroupRepository) UpsertOpen(ctx context.Context, input AlertGroupUpsertInput) (*AlertGroup, bool, error) {
	if r == nil || r.db == nil {
		return nil, false, errors.New("alert group repository db is nil")
	}
	if err := input.validate(); err != nil {
		return nil, false, err
	}
	occurredAt := input.OccurredAt.UTC()
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	now := time.Now().UTC()
	bodyJSON, err := marshalAlertGroupBody(input.BodyJSON)
	if err != nil {
		return nil, false, err
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)

	existing, err := scanAlertGroupRow(tx.QueryRow(ctx, `
		SELECT id, tenant_id, COALESCE(project_id, ''), group_key, status, severity,
		       alert_type, title, COALESCE(representative_event_id, ''), COALESCE(request_id, ''),
		       occurrence_count, body_json, first_seen_at, last_seen_at, created_at, updated_at,
		       COALESCE(effective_severity, ''), COALESCE(disposition_class, ''), COALESCE(class_key, ''),
		       COALESCE(principal_key, ''), is_canary, COALESCE(stage, ''), COALESCE(domain, 'content'),
		       COALESCE(distinct_occurrences, 0), COALESCE(affected_users, 0), COALESCE(last_calc_at, to_timestamp(0)),
		       COALESCE((SELECT COALESCE(NULLIF(rl.proxy_source_ip, ''), rl.source_ip, '') FROM request_logs rl
		         WHERE rl.tenant_id = alert_groups.tenant_id AND NULLIF(alert_groups.request_id, '') IS NOT NULL
		           AND rl.request_id = alert_groups.request_id
		         ORDER BY rl.created_at DESC LIMIT 1), '') AS source_ip,
		       COALESCE((SELECT rl.proxy_mode FROM request_logs rl
		                 WHERE rl.tenant_id = alert_groups.tenant_id AND NULLIF(alert_groups.request_id, '') IS NOT NULL
		                   AND rl.request_id = alert_groups.request_id
		                 ORDER BY rl.created_at DESC LIMIT 1), '') AS access_direction
		FROM alert_groups
		WHERE tenant_id = $1 AND group_key = $2 AND status IN ('open', 'acknowledged')
		ORDER BY updated_at DESC
		LIMIT 1
		FOR UPDATE
	`, input.TenantID, input.GroupKey))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) && !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrNotFound) {
		id := "ag_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
		created, err := scanAlertGroupRow(tx.QueryRow(ctx, `
		INSERT INTO alert_groups (
			id, tenant_id, project_id, group_key, status, severity, alert_type,
			title, representative_event_id, request_id, occurrence_count, body_json,
			first_seen_at, last_seen_at, created_at, updated_at,
			effective_severity, disposition_class, class_key, principal_key, is_canary, stage, domain
		) VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,$7,$8,NULLIF($9,''),NULLIF($10,''),1,$11,$12,$12,$13,$13,
			NULLIF($14,''),NULLIF($15,''),NULLIF($16,''),NULLIF($17,''),$18,NULLIF($19,''),COALESCE(NULLIF($20,''),'content'))
			RETURNING id, tenant_id, COALESCE(project_id, ''), group_key, status, severity,
			          alert_type, title, COALESCE(representative_event_id, ''), COALESCE(request_id, ''),
			          occurrence_count, body_json, first_seen_at, last_seen_at, created_at, updated_at,
			          COALESCE(effective_severity, ''), COALESCE(disposition_class, ''), COALESCE(class_key, ''),
			          COALESCE(principal_key, ''), is_canary, COALESCE(stage, ''), COALESCE(domain, 'content'),
			          COALESCE(distinct_occurrences, 0), COALESCE(affected_users, 0), COALESCE(last_calc_at, to_timestamp(0)),
			          '' AS source_ip, '' AS access_direction
		`, id, input.TenantID, input.ProjectID, input.GroupKey, AlertGroupStatusOpen, input.Severity, input.AlertType, input.Title, input.RepresentativeEventID, input.RequestID, bodyJSON, occurredAt, now,
			input.EffectiveSeverity, input.DispositionClass, input.ClassKey, input.PrincipalKey, input.IsCanary, input.Stage, input.Domain))
		if err != nil {
			return nil, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, false, err
		}
		if input.RepresentativeEventID != "" {
			reconciled, reconcileErr := r.ReconcileOccurrences(ctx, input.TenantID, created.ID, input.RepresentativeEventID)
			if reconcileErr == nil {
				return reconciled, true, nil
			}
		}
		return created, true, nil
	}

	// severity is the representative-selection key. A lower-severity recurrence
	// must still count toward the group, but it must not replace the evidence
	// that explains why the group is actionable.
	replaceRepresentative := severityRank(input.Severity) >= severityRank(existing.Severity)
	representativeAlertType := input.AlertType
	representativeTitle := input.Title
	representativeEventID := input.RepresentativeEventID
	representativeRequestID := input.RequestID
	representativeBodyJSON := bodyJSON
	representativeEffectiveSeverity := input.EffectiveSeverity
	representativeDispositionClass := input.DispositionClass
	representativeClassKey := input.ClassKey
	representativePrincipalKey := input.PrincipalKey
	representativeStage := input.Stage
	representativeDomain := input.Domain
	if !replaceRepresentative {
		representativeAlertType = existing.AlertType
		representativeTitle = existing.Title
		representativeEventID = existing.RepresentativeEventID
		representativeRequestID = existing.RequestID
		representativeBodyJSON, err = marshalAlertGroupBody(existing.BodyJSON)
		if err != nil {
			return nil, false, err
		}
		representativeEffectiveSeverity = existing.EffectiveSeverity
		representativeDispositionClass = existing.DispositionClass
		representativeClassKey = existing.ClassKey
		representativePrincipalKey = existing.PrincipalKey
		representativeStage = existing.Stage
		representativeDomain = existing.Domain
	}
	updated, err := scanAlertGroupRow(tx.QueryRow(ctx, `
		UPDATE alert_groups
		SET severity = $1,
            alert_type = $16,
		    title = $2,
		    representative_event_id = NULLIF($3,''),
		    request_id = NULLIF($4,''),
		    occurrence_count = occurrence_count + 1,
		    body_json = $5,
		    last_seen_at = GREATEST(last_seen_at, $6),
		    updated_at = $7,
		    effective_severity = COALESCE(NULLIF($10,''), effective_severity),
		    disposition_class = COALESCE(NULLIF($11,''), disposition_class),
		    class_key = COALESCE(NULLIF($12,''), class_key),
		    principal_key = COALESCE(NULLIF($13,''), principal_key),
		    is_canary = alert_groups.is_canary OR $14,
		    stage = CASE WHEN alert_groups.stage = 'output' OR $15 = 'output' THEN 'output'
		                 ELSE COALESCE(NULLIF($15,''), alert_groups.stage) END,
		    domain = COALESCE(NULLIF($17,''), domain)
		WHERE id = $8 AND tenant_id = $9
		RETURNING id, tenant_id, COALESCE(project_id, ''), group_key, status, severity,
		          alert_type, title, COALESCE(representative_event_id, ''), COALESCE(request_id, ''),
		          occurrence_count, body_json, first_seen_at, last_seen_at, created_at, updated_at,
		          COALESCE(effective_severity, ''), COALESCE(disposition_class, ''), COALESCE(class_key, ''),
		          COALESCE(principal_key, ''), is_canary, COALESCE(stage, ''), COALESCE(domain, 'content'),
		          COALESCE(distinct_occurrences, 0), COALESCE(affected_users, 0), COALESCE(last_calc_at, to_timestamp(0)),
		          '' AS source_ip, '' AS access_direction
	`, maxSeverity(existing.Severity, input.Severity), representativeTitle, representativeEventID, representativeRequestID, representativeBodyJSON, occurredAt, now, existing.ID, input.TenantID,
		representativeEffectiveSeverity, representativeDispositionClass, representativeClassKey, representativePrincipalKey, input.IsCanary, representativeStage, representativeAlertType, representativeDomain))
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	if input.RepresentativeEventID != "" {
		reconciled, reconcileErr := r.ReconcileOccurrences(ctx, input.TenantID, updated.ID, input.RepresentativeEventID)
		if reconcileErr == nil {
			return reconciled, false, nil
		}
	}
	return updated, false, nil
}

// MarkFalsePositiveBySecurityEvent transitions only the alert group that is
// demonstrably linked to the supplied security event in the same tenant. It never
// changes security_events or audit evidence; it only gives a manual disposition the
// group-level lifecycle state consumed by the reversible inbox/notification silence.
func (r *AlertGroupRepository) MarkFalsePositiveBySecurityEvent(ctx context.Context, tenantID, eventID, actorID, note string) (*AlertGroup, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("alert group repository db is nil")
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(eventID) == "" {
		return nil, errors.New("tenant id and security event id are required")
	}
	now := time.Now().UTC()
	group, err := scanAlertGroupRow(r.db.QueryRow(ctx, `
		WITH target AS (
			SELECT ag.id
			FROM security_events se
			JOIN alert_groups ag ON ag.tenant_id = se.tenant_id
			 AND (ag.id = se.alert_group_id OR ag.representative_event_id = se.id)
			WHERE se.tenant_id = $1 AND se.id = $2
			ORDER BY CASE WHEN ag.id = se.alert_group_id THEN 0 ELSE 1 END, ag.updated_at DESC
			LIMIT 1
		)
		UPDATE alert_groups
		SET status = 'false_positive', false_positive_at = $3, closed_at = $3,
			disposition_by = NULLIF($4, ''), disposition_note = NULLIF($5, ''), updated_at = $3
		WHERE tenant_id = $1 AND id = (SELECT id FROM target)
		RETURNING id, tenant_id, COALESCE(project_id, ''), group_key, status, severity,
		          alert_type, title, COALESCE(representative_event_id, ''), COALESCE(request_id, ''),
		          occurrence_count, body_json, first_seen_at, last_seen_at, created_at, updated_at,
		          COALESCE(effective_severity, ''), COALESCE(disposition_class, ''), COALESCE(class_key, ''),
		          COALESCE(principal_key, ''), is_canary, COALESCE(stage, ''), COALESCE(domain, 'content'),
		          COALESCE(distinct_occurrences, 0), COALESCE(affected_users, 0), COALESCE(last_calc_at, to_timestamp(0)),
		          '' AS source_ip, '' AS access_direction
	`, tenantID, eventID, now, actorID, note))
	if err == nil && group != nil {
		syncAlertCaseRefs(ctx, r.db, tenantID, map[string][]string{"group": {group.ID}, "event": {eventID}})
	}
	return group, err
}

func (r *AlertGroupRepository) UpdateStatus(ctx context.Context, tenantID, id string, status AlertGroupStatus, actorID, note string) (*AlertGroup, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("alert group repository db is nil")
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" {
		return nil, errors.New("tenant id and alert group id are required")
	}
	if !validAlertGroupStatus(status) {
		return nil, fmt.Errorf("invalid alert group status: %s", status)
	}
	now := time.Now().UTC()
	group, err := scanAlertGroupRow(r.db.QueryRow(ctx, `
		UPDATE alert_groups
		SET status = $1::varchar,
		    acknowledged_at = CASE WHEN $1::varchar = 'acknowledged' THEN $2 ELSE acknowledged_at END,
		    resolved_at = CASE WHEN $1::varchar = 'resolved' THEN $2 ELSE resolved_at END,
		    false_positive_at = CASE WHEN $1::varchar = 'false_positive' THEN $2 ELSE false_positive_at END,
		    closed_at = CASE WHEN $1::varchar IN ('resolved', 'false_positive') THEN $2 WHEN $1::varchar = 'open' THEN NULL ELSE closed_at END,
		    reopened_at = CASE WHEN $1::varchar = 'open' THEN $2 ELSE reopened_at END,
		    disposition_by = NULLIF($3,''),
		    disposition_note = NULLIF($4,''),
		    updated_at = $2
		WHERE tenant_id = $5 AND id = $6
		RETURNING id, tenant_id, COALESCE(project_id, ''), group_key, status, severity,
		          alert_type, title, COALESCE(representative_event_id, ''), COALESCE(request_id, ''),
		          occurrence_count, body_json, first_seen_at, last_seen_at, created_at, updated_at,
		          COALESCE(effective_severity, ''), COALESCE(disposition_class, ''), COALESCE(class_key, ''),
		          COALESCE(principal_key, ''), is_canary, COALESCE(stage, ''), COALESCE(domain, 'content'),
		          COALESCE(distinct_occurrences, 0), COALESCE(affected_users, 0), COALESCE(last_calc_at, to_timestamp(0)),
		          '' AS source_ip, '' AS access_direction
	`, status, now, actorID, note, tenantID, id))
	if err == nil && group != nil {
		syncAlertCaseRefs(ctx, r.db, tenantID, map[string][]string{"group": {group.ID}})
	}
	return group, err
}

// FaultQuietTTL is how long a runtime-fault group must stay silent before the
// TTL sweep closes it. Faults are operational telemetry, so they are exempt from
// the stage guard that protects real leaks -- but the canary and high-value
// finding guards still apply, and faults are closed on a much shorter clock than
// the alert TTL, because a breaker that stopped flapping should leave the inbox
// the same day rather than sit for the full retention window.
const FaultQuietTTL = 6 * time.Hour

// AutoCloseStale 是 TTL 自动关闭（P0-A）：把陈旧（last_seen_at 早于 now-ttl）、且明确 input 侧、
// 无 canary、body_json 不含高价值 finding 的 open/acknowledged 组批量置为 resolved，
// 并以 disposition_by='system_ttl' 区分自动关 vs 人工关。
//
// 假阴性护栏（全部 fail-closed，宁可不关也不误关真泄露）：
//   - stage 必须精确等于 'input'：NULL（未回填/未知）、'output'、'tool' 一律保护；
//   - is_canary 为真的组永不关（G1 红线）；
//   - body_json.matched.findings 含 secret/data_leak 类型，或 illegal_system_command_instructions /
//     agent_canary* / classified* 类别的组永不关（可靠 stage 落地前，不信 stage 列的兜底）。
//
// 运行故障分支（alert_type='runtime_fault'）走独立的静默窗 faultTTL：它只豁免 stage 护栏
// （故障本来就没有可靠的 input/output stage 可言），canary 与高价值 finding 两条护栏照旧套用：
//
//   - 现实中的运行故障事件写入点逐个核对过，全都不带安全 finding（gateway-core 的
//     security_output_check_failed 一律传 nil；reverse_proxy_audit 那条要求
//     !hasSecurityFindings；proxy-server 的两条分别要求 securityFindingCount==0 与
//     len(findings)==0；文件上传路径 err != nil 时 findings 必为 nil）。也就是说今天
//     is_canary 不可能为真，这一条不是在修一个已存在的漏关。
//   - 但那个结论要三个服务五个文件同时成立才成立，任何一处改动都能让它静默失效。所以这里
//     仍然显式护栏：把"跨服务巧合"变成"本地强制"，代价只是一条 SQL 谓词，而被自动关掉的
//     金丝雀组（G1 红线）恰恰是护栏要防的那类假阴性。
//   - disposition_note 用独立取值，便于事后区分"故障静默自动关"与"低危留观 TTL 关"。
//
// 注意：本方法是全局 cron 语义（跨租户），不加 tenant 过滤；batchLimit>0 时单次最多关这么多行以绑定持锁时长。
// redlineFindingGuardSQL 判定 body_json 里不含高价值 finding。两个分支共用同一份文本，
// 是因为这份护栏一旦被复制成两份、又在某次修改里只删掉一处，误关就是静默的：组会安静地
// 变成 resolved，没有任何一条日志会说"这里本不该关"。
const redlineFindingGuardSQL = `NOT EXISTS (
						SELECT 1 FROM jsonb_array_elements(
							COALESCE(body_json->'matched'->'findings', '[]'::jsonb)) AS f
						WHERE f->>'type' IN ('secret', 'data_leak')
						   OR f->>'category' = 'illegal_system_command_instructions'
						   OR f->>'category' LIKE 'agent_canary%'
						   OR f->>'category' LIKE 'classified%'
					)`

func (r *AlertGroupRepository) AutoCloseStale(ctx context.Context, now time.Time, ttl time.Duration, faultTTL time.Duration, batchLimit int) (int64, error) {
	if r == nil || r.db == nil {
		return 0, errors.New("alert group repository db is nil")
	}
	if ttl <= 0 {
		return 0, errors.New("ttl must be positive")
	}
	if faultTTL <= 0 {
		faultTTL = FaultQuietTTL
	}
	nowUTC := now.UTC()
	cutoff := nowUTC.Add(-ttl)
	faultCutoff := nowUTC.Add(-faultTTL)
	limit := batchLimit
	if limit <= 0 {
		limit = 1000
	}
	tag, err := r.db.Exec(ctx, `
		UPDATE alert_groups SET
			status = 'resolved',
			resolved_at = $1,
			closed_at = $1,
			disposition_by = 'system_ttl',
			disposition_note = CASE WHEN alert_type = 'runtime_fault'
			                        THEN 'auto_closed_fault_quiet'
			                        ELSE 'auto_closed_ttl' END,
			updated_at = $1
		WHERE id IN (
			SELECT id FROM alert_groups
			WHERE status IN ('open', 'acknowledged')
			  AND (
				(
					last_seen_at < $2
					AND stage = 'input'
					AND NOT is_canary
					AND `+redlineFindingGuardSQL+`
				)
				OR (
					alert_type = 'runtime_fault'
					AND last_seen_at < $4
					AND NOT is_canary
					AND `+redlineFindingGuardSQL+`
				)
			  )
			LIMIT $3
		)
	`, nowUTC, cutoff, limit, faultCutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *AlertGroupRepository) GetByID(ctx context.Context, tenantID, id string) (*AlertGroup, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("alert group repository db is nil")
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" {
		return nil, errors.New("tenant id and alert group id are required")
	}
	group, err := scanAlertGroupRow(r.db.QueryRow(ctx, `
		SELECT id, tenant_id, COALESCE(project_id, ''), group_key, status, severity,
		       alert_type, title, COALESCE(representative_event_id, ''), COALESCE(request_id, ''),
		       occurrence_count, body_json, first_seen_at, last_seen_at, created_at, updated_at,
		       COALESCE(effective_severity, ''), COALESCE(disposition_class, ''), COALESCE(class_key, ''),
		       COALESCE(principal_key, ''), is_canary, COALESCE(stage, ''), COALESCE(domain, 'content'),
		       COALESCE(distinct_occurrences, 0), COALESCE(affected_users, 0), COALESCE(last_calc_at, to_timestamp(0)),
		       COALESCE((SELECT COALESCE(NULLIF(rl.proxy_source_ip, ''), rl.source_ip, '') FROM request_logs rl
		         WHERE rl.tenant_id = alert_groups.tenant_id AND NULLIF(alert_groups.request_id, '') IS NOT NULL
		           AND rl.request_id = alert_groups.request_id
		         ORDER BY rl.created_at DESC LIMIT 1), '') AS source_ip,
		       COALESCE((SELECT rl.proxy_mode FROM request_logs rl
		                 WHERE rl.tenant_id = alert_groups.tenant_id AND NULLIF(alert_groups.request_id, '') IS NOT NULL
		                   AND rl.request_id = alert_groups.request_id
		                 ORDER BY rl.created_at DESC LIMIT 1), '') AS access_direction
		FROM alert_groups
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	return group, err
}

func buildAlertGroupPageWhere(filter AlertGroupListFilter) ([]string, []any, error) {
	if strings.TrimSpace(filter.TenantID) == "" {
		return nil, nil, errors.New("tenant id is required")
	}
	args := []any{filter.TenantID}
	where := []string{"ag.tenant_id = $1"}
	if filter.Status != "" {
		if !validAlertGroupStatus(filter.Status) {
			return nil, nil, fmt.Errorf("invalid alert group status: %s", filter.Status)
		}
		args = append(args, filter.Status)
		where = append(where, fmt.Sprintf("ag.status = $%d", len(args)))
	}
	if strings.TrimSpace(filter.Severity) != "" {
		args = append(args, strings.TrimSpace(filter.Severity))
		where = append(where, fmt.Sprintf("COALESCE(NULLIF(ag.effective_severity, ''), ag.severity) = $%d", len(args)))
	}
	if strings.TrimSpace(filter.DispositionClass) != "" {
		switch strings.TrimSpace(filter.DispositionClass) {
		case "action_required", "informational", "suppressed":
		default:
			return nil, nil, fmt.Errorf("invalid alert group disposition class: %s", filter.DispositionClass)
		}
		args = append(args, strings.TrimSpace(filter.DispositionClass))
		where = append(where, fmt.Sprintf("COALESCE(NULLIF(ag.disposition_class, ''), 'action_required') = $%d", len(args)))
	}
	if strings.TrimSpace(filter.AccessDirection) != "" {
		args = append(args, strings.TrimSpace(filter.AccessDirection))
		where = append(where, fmt.Sprintf("EXISTS (SELECT 1 FROM request_logs rl_filter WHERE rl_filter.tenant_id = ag.tenant_id AND NULLIF(ag.request_id, '') IS NOT NULL AND rl_filter.request_id = ag.request_id AND rl_filter.proxy_mode = $%d)", len(args)))
	}
	// 风险域过滤（迁移 941）：未知取值直接拒绝，避免静默空结果被当成"该域无告警"。
	if strings.TrimSpace(filter.Domain) != "" {
		switch filter.Domain {
		case "content", "tool", "skill", "mcp", "access", "system":
		default:
			return nil, nil, fmt.Errorf("invalid alert group domain: %s", filter.Domain)
		}
		args = append(args, filter.Domain)
		where = append(where, fmt.Sprintf("COALESCE(ag.domain, 'content') = $%d", len(args)))
	}
	if t := strings.TrimSpace(filter.AlertType); t != "" {
		args = append(args, t)
		where = append(where, fmt.Sprintf("ag.alert_type = $%d", len(args)))
	}
	if rule := strings.TrimSpace(filter.Rule); rule != "" {
		args = append(args, rule, "%"+escapeLikePattern(rule)+"%")
		where = append(where, fmt.Sprintf("(ag.body_json->>'rule_id' = $%d OR ag.body_json->>'rule_name' ILIKE $%d ESCAPE '\\')", len(args)-1, len(args)))
	}
	if !filter.LastSeenFrom.IsZero() {
		args = append(args, filter.LastSeenFrom.UTC())
		where = append(where, fmt.Sprintf("ag.last_seen_at >= $%d", len(args)))
	}
	if !filter.LastSeenTo.IsZero() {
		args = append(args, filter.LastSeenTo.UTC())
		where = append(where, fmt.Sprintf("ag.last_seen_at < $%d", len(args)))
	}
	// 部门收窄：project_id ∈ 本部门 project 集。空集合（部门无 project）→ 零行（fail-closed）。
	// 必须放在最后：ListPage 的 has_any 子查询按 len(args) 引用这个参数。
	if filter.ProjectIDs != nil {
		args = append(args, filter.ProjectIDs)
		where = append(where, fmt.Sprintf("ag.project_id = ANY($%d)", len(args)))
	}
	if !filter.IncludeDevTraffic {
		where = append(where, "NOT ("+developmentAlertGroupFoldExpr("ag")+")")
	}
	return where, args, nil
}

func (r *AlertGroupRepository) ListPage(ctx context.Context, filter AlertGroupListFilter) (AlertGroupPage, error) {
	if r == nil || r.db == nil {
		return AlertGroupPage{}, errors.New("alert group repository db is nil")
	}
	where, args, err := buildAlertGroupPageWhere(filter)
	if err != nil {
		return AlertGroupPage{}, err
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset := maxInt(filter.Offset, 0)

	// COUNT 与列表查询分离，列表不再把 body_json 大字段拉到数据库驱动/浏览器链路。
	var page AlertGroupPage
	page.Limit, page.Offset = limit, offset
	projectScope := ""
	if filter.ProjectIDs != nil {
		projectScope = fmt.Sprintf(" AND ag2.project_id = ANY($%d)", len(args))
	}
	countQuery := fmt.Sprintf(
		"SELECT COUNT(*)::int, EXISTS (SELECT 1 FROM alert_groups ag2 WHERE ag2.tenant_id = $1%s) AS has_any FROM alert_groups ag WHERE %s",
		projectScope,
		strings.Join(where, " AND "),
	)
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&page.Total, &page.HasAny); err != nil {
		return AlertGroupPage{}, err
	}

	foldedFilter := filter
	foldedFilter.IncludeDevTraffic = true
	foldedWhere, foldedArgs, err := buildAlertGroupPageWhere(foldedFilter)
	if err != nil {
		return AlertGroupPage{}, err
	}
	foldedWhere = append(foldedWhere, developmentAlertGroupFoldExpr("ag"))
	if err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM alert_groups ag WHERE "+strings.Join(foldedWhere, " AND "), foldedArgs...).Scan(&page.FoldedDevelopmentGroups); err != nil {
		return AlertGroupPage{}, err
	}

	listArgs := append(append([]any{}, args...), limit, offset)
	limitArg, offsetArg := len(listArgs)-1, len(listArgs)
	listQuery := fmt.Sprintf(
		"SELECT ag.id, ag.tenant_id, COALESCE(ag.project_id, ''), ag.group_key, ag.status, ag.severity, "+
			"ag.alert_type, ag.title, COALESCE(ag.representative_event_id, ''), COALESCE(ag.request_id, ''), "+
			"ag.occurrence_count, jsonb_strip_nulls(jsonb_build_object('rule_name', ag.body_json->>'rule_name')), ag.first_seen_at, ag.last_seen_at, ag.created_at, ag.updated_at, "+
			"COALESCE(ag.effective_severity, ''), COALESCE(ag.disposition_class, ''), COALESCE(ag.class_key, ''), "+
			"COALESCE(ag.principal_key, ''), ag.is_canary, COALESCE(ag.stage, ''), COALESCE(ag.domain, 'content'), "+
			"COALESCE(ag.distinct_occurrences, 0), COALESCE(ag.affected_users, 0), COALESCE(ag.last_calc_at, to_timestamp(0)), "+
			"COALESCE(request_meta.source_ip, ''), COALESCE(request_meta.access_direction, '') "+
			"FROM alert_groups ag "+
			"LEFT JOIN LATERAL ( "+
			"SELECT COALESCE(NULLIF(rl.proxy_source_ip, ''), rl.source_ip, '') AS source_ip, COALESCE(rl.proxy_mode, '') AS access_direction "+
			"FROM request_logs rl WHERE rl.tenant_id = ag.tenant_id AND NULLIF(ag.request_id, '') IS NOT NULL "+
			"AND rl.request_id = ag.request_id ORDER BY rl.created_at DESC LIMIT 1 "+
			") request_meta ON TRUE WHERE %s ORDER BY ag.last_seen_at DESC, ag.updated_at DESC LIMIT $%d OFFSET $%d",
		strings.Join(where, " AND "),
		limitArg,
		offsetArg,
	)
	rows, err := r.db.Query(ctx, listQuery, listArgs...)
	if err != nil {
		return AlertGroupPage{}, err
	}
	defer rows.Close()
	page.Items = make([]*AlertGroup, 0, limit)
	for rows.Next() {
		group, err := scanAlertGroupRow(rows)
		if err != nil {
			return AlertGroupPage{}, err
		}
		page.Items = append(page.Items, group)
	}
	if err := rows.Err(); err != nil {
		return AlertGroupPage{}, err
	}
	return page, nil
}

func (r *AlertGroupRepository) List(ctx context.Context, filter AlertGroupListFilter) ([]*AlertGroup, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("alert group repository db is nil")
	}
	if strings.TrimSpace(filter.TenantID) == "" {
		return nil, errors.New("tenant id is required")
	}
	limit := normalizeAlertGroupListLimit(filter.Limit)
	args := []any{filter.TenantID}
	where := []string{"tenant_id = $1"}
	if filter.Status != "" {
		if !validAlertGroupStatus(filter.Status) {
			return nil, fmt.Errorf("invalid alert group status: %s", filter.Status)
		}
		args = append(args, filter.Status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	if strings.TrimSpace(filter.Severity) != "" {
		args = append(args, strings.TrimSpace(filter.Severity))
		where = append(where, fmt.Sprintf("severity = $%d", len(args)))
	}
	// 部门收窄：project_id ∈ 本部门 project 集。空集合（部门无 project）→ 零行（fail-closed）。
	if filter.ProjectIDs != nil {
		args = append(args, filter.ProjectIDs)
		where = append(where, fmt.Sprintf("project_id = ANY($%d)", len(args)))
	}
	if strings.TrimSpace(filter.Domain) != "" {
		switch filter.Domain {
		case "content", "tool", "skill", "mcp", "access", "system":
		default:
			return nil, fmt.Errorf("invalid alert group domain: %s", filter.Domain)
		}
		args = append(args, filter.Domain)
		where = append(where, fmt.Sprintf("COALESCE(domain, 'content') = $%d", len(args)))
	}
	args = append(args, limit, maxInt(filter.Offset, 0))
	query := fmt.Sprintf(`
		SELECT id, tenant_id, COALESCE(project_id, ''), group_key, status, severity,
		       alert_type, title, COALESCE(representative_event_id, ''), COALESCE(request_id, ''),
		       occurrence_count, body_json, first_seen_at, last_seen_at, created_at, updated_at,
		       COALESCE(effective_severity, ''), COALESCE(disposition_class, ''), COALESCE(class_key, ''),
		       COALESCE(principal_key, ''), is_canary, COALESCE(stage, ''), COALESCE(domain, 'content'),
		       COALESCE(distinct_occurrences, 0), COALESCE(affected_users, 0), COALESCE(last_calc_at, to_timestamp(0)),
		       COALESCE((SELECT COALESCE(NULLIF(rl.proxy_source_ip, ''), rl.source_ip, '') FROM request_logs rl
		         WHERE rl.tenant_id = alert_groups.tenant_id AND NULLIF(alert_groups.request_id, '') IS NOT NULL
		           AND rl.request_id = alert_groups.request_id
		         ORDER BY rl.created_at DESC LIMIT 1), '') AS source_ip,
		       COALESCE((SELECT rl.proxy_mode FROM request_logs rl
		                 WHERE rl.tenant_id = alert_groups.tenant_id AND NULLIF(alert_groups.request_id, '') IS NOT NULL
		                   AND rl.request_id = alert_groups.request_id
		                 ORDER BY rl.created_at DESC LIMIT 1), '') AS access_direction
		FROM alert_groups
		WHERE %s
		ORDER BY last_seen_at DESC, updated_at DESC
		LIMIT $%d OFFSET $%d
	`, strings.Join(where, " AND "), len(args)-1, len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []*AlertGroup{}
	for rows.Next() {
		group, err := scanAlertGroupRow(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

// normalizeAlertGroupListLimit 归一化列表页大小：未传/非法回落默认 50，
// 超过 200 的请求 cap 到 200（此前 >200 会静默回落 50，越翻越少）。
// escapeLikePattern 转义 LIKE 通配符，让用户输入的规则名按字面包含匹配。
func escapeLikePattern(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func normalizeAlertGroupListLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	// 上限放到 2000：告警列表需一次性载入以支持前端「按类折叠/概览」的准确计数，
	// 单租户开放组量级在千级以内，2000 足够且客户端可承受。
	if limit > 2000 {
		return 2000
	}
	return limit
}

// ListFalsePositiveGroupKeys 返回给定租户集合内、处置时间（false_positive_at）在 since
// 之后的误报组 group_key 集合（按租户分组）。按 group_key 查且不限组状态：
// 组被处置关闭后，同 key 的后续事件会新建 open 组（开放组唯一索引只约束 open/acknowledged），
// 静默判定必须仍能命中旧的 false_positive 组，与新开放组共存。
func (r *AlertGroupRepository) ListFalsePositiveGroupKeys(ctx context.Context, tenantIDs []string, since time.Time) (map[string]map[string]bool, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("alert group repository db is nil")
	}
	out := map[string]map[string]bool{}
	if len(tenantIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT tenant_id, group_key, COALESCE(project_id, ''), COALESCE(stage, '')
		FROM alert_groups
		WHERE tenant_id = ANY($1)
		  AND status = 'false_positive'
		  AND false_positive_at >= $2
	`, tenantIDs, since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var tenantID, groupKey, projectID, stage string
		if err := rows.Scan(&tenantID, &groupKey, &projectID, &stage); err != nil {
			return nil, err
		}
		if out[tenantID] == nil {
			out[tenantID] = map[string]bool{}
		}
		out[tenantID][ScopedAlertGroupKey(groupKey, projectID, stage)] = true
	}
	return out, rows.Err()
}

func (input AlertGroupUpsertInput) validate() error {
	if strings.TrimSpace(input.TenantID) == "" {
		return errors.New("tenant id is required")
	}
	if strings.TrimSpace(input.GroupKey) == "" {
		return errors.New("group key is required")
	}
	if strings.TrimSpace(input.Severity) == "" {
		return errors.New("severity is required")
	}
	if strings.TrimSpace(input.AlertType) == "" {
		return errors.New("alert type is required")
	}
	if strings.TrimSpace(input.Title) == "" {
		return errors.New("title is required")
	}
	return nil
}

func validAlertGroupStatus(status AlertGroupStatus) bool {
	switch status {
	case AlertGroupStatusOpen, AlertGroupStatusAcknowledged, AlertGroupStatusResolved, AlertGroupStatusFalsePositive:
		return true
	}
	return false
}

func marshalAlertGroupBody(body map[string]any) (string, error) {
	if body == nil {
		body = map[string]any{}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

type alertGroupScanner interface {
	Scan(dest ...any) error
}

func scanAlertGroupRow(row alertGroupScanner) (*AlertGroup, error) {
	var group AlertGroup
	var status string
	var bodyRaw []byte
	if err := row.Scan(
		&group.ID,
		&group.TenantID,
		&group.ProjectID,
		&group.GroupKey,
		&status,
		&group.Severity,
		&group.AlertType,
		&group.Title,
		&group.RepresentativeEventID,
		&group.RequestID,
		&group.OccurrenceCount,
		&bodyRaw,
		&group.FirstSeenAt,
		&group.LastSeenAt,
		&group.CreatedAt,
		&group.UpdatedAt,
		&group.EffectiveSeverity,
		&group.DispositionClass,
		&group.ClassKey,
		&group.PrincipalKey,
		&group.IsCanary,
		&group.Stage,
		&group.Domain,
		&group.DistinctOccurrences,
		&group.AffectedUsers,
		&group.LastCalcAt,
		&group.SourceIP,
		&group.AccessDirection,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	group.Status = AlertGroupStatus(status)
	group.BodyJSON = map[string]any{}
	if len(bodyRaw) > 0 {
		_ = json.Unmarshal(bodyRaw, &group.BodyJSON)
	}
	return &group, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// AttachEvent 把安全事件回填到告警组（桥 UpsertOpen 成功后调用；契约第 6 条）。
// 幂等：重复执行同值覆盖；WHERE 同时锁 tenant_id 防跨租户串写。
func (r *AlertGroupRepository) AttachEvent(ctx context.Context, tenantID, eventID, groupID string) error {
	if r == nil || r.db == nil {
		return errors.New("alert group repository db is nil")
	}
	_, err := r.db.Exec(ctx, `
		UPDATE security_events SET alert_group_id = $1
		WHERE tenant_id = $2 AND id = $3
	`, groupID, tenantID, eventID)
	if err != nil {
		return err
	}
	_, _ = r.ReconcileOccurrences(ctx, tenantID, groupID, eventID)
	return nil
}

// ReconcileOccurrences claims pending lightweight occurrences for one representative
// security event. Claiming and occurrence_count bump are idempotent: only rows whose
// alert_group_id was still NULL contribute to the increment.
func (r *AlertGroupRepository) ReconcileOccurrences(ctx context.Context, tenantID, groupID, representativeEventID string) (*AlertGroup, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("alert group repository db is nil")
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(groupID) == "" || strings.TrimSpace(representativeEventID) == "" {
		return nil, errors.New("tenant id, group id and representative event id are required")
	}
	_, err := r.db.Exec(ctx, `
		WITH claimed AS (
			UPDATE security_event_occurrences
			   SET alert_group_id = $2
			 WHERE tenant_id = $1
			   AND representative_event_id = $3
			   AND alert_group_id IS NULL
			RETURNING occurred_at
		),
		claimed_stats AS (
			SELECT COUNT(*)::int AS count, MAX(occurred_at) AS last_seen_at
			  FROM claimed
		)
		UPDATE alert_groups ag
		   SET occurrence_count = ag.occurrence_count + claimed_stats.count,
		       last_seen_at = GREATEST(ag.last_seen_at, COALESCE(claimed_stats.last_seen_at, ag.last_seen_at)),
		       updated_at = CASE WHEN claimed_stats.count > 0 THEN NOW() ELSE ag.updated_at END
		  FROM claimed_stats
		 WHERE ag.tenant_id = $1
		   AND ag.id = $2
	`, tenantID, groupID, representativeEventID)
	if err != nil {
		return nil, err
	}
	if _, _, err := r.RecalcCounters(ctx, tenantID, groupID); err != nil {
		return nil, err
	}
	return r.GetByID(ctx, tenantID, groupID)
}

// RecalcCounters 幂等重算组主指标（桥 at-least-once 语义下绝不做增量 +1）：
//
//	distinct_occurrences = COUNT(DISTINCT COALESCE(NULLIF(conversation_key,''), request_id))（会话口径）
//	affected_users       = COUNT(DISTINCT principal_key)（空值不计）
//
// 并写 last_calc_at 记录口径时间。返回重算后的两个计数，供收件箱/通知文案使用。
func (r *AlertGroupRepository) RecalcCounters(ctx context.Context, tenantID, groupID string) (int, int, error) {
	if r == nil || r.db == nil {
		return 0, 0, errors.New("alert group repository db is nil")
	}
	return alertcounter.RecalculateGroup(ctx, r.db, tenantID, groupID)
}

type AlertGroupEventView string

const (
	AlertGroupEventViewEvents        AlertGroupEventView = "events"
	AlertGroupEventViewConversations AlertGroupEventView = "conversations"
)

type AlertGroupEventListFilter struct {
	View            AlertGroupEventView
	ConversationKey string
	Limit           int
	Offset          int
}

// AlertGroupEvent 是告警组事件视图的一行；conversations 视图按有效会话键聚合。
type AlertGroupEvent struct {
	RowKey          string    `json:"row_key"`
	EventID         string    `json:"event_id"`
	RequestID       string    `json:"request_id"`
	PrincipalKey    string    `json:"principal_key"`
	ConversationKey string    `json:"conversation_key"`
	EventType       string    `json:"event_type"`
	Severity        string    `json:"severity"`
	ActionTaken     string    `json:"action_taken"`
	CreatedAt       time.Time `json:"created_at"`
	EventCount      int       `json:"event_count"`
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
}

func buildAlertGroupEventsQueries(tenantID, groupID string, filter AlertGroupEventListFilter) (string, string, []any, []any) {
	limit, offset := filter.Limit, filter.Offset
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	if filter.View == AlertGroupEventViewConversations {
		countSQL := `
			SELECT COUNT(DISTINCT COALESCE(NULLIF(conversation_key, ''), request_id))
			FROM security_events
			WHERE tenant_id = $1 AND alert_group_id = $2
		`
		listSQL := `
			WITH ranked AS (
				SELECT
					COALESCE(NULLIF(conversation_key, ''), request_id) AS row_key,
					id, request_id, COALESCE(principal_key, '') AS principal_key,
					COALESCE(conversation_key, '') AS conversation_key,
					event_type, action_taken, created_at,
					ROW_NUMBER() OVER (
						PARTITION BY COALESCE(NULLIF(conversation_key, ''), request_id)
						ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, created_at DESC, id DESC
                    ) AS row_number,
					COUNT(*) OVER (
						PARTITION BY COALESCE(NULLIF(conversation_key, ''), request_id)
					) AS event_count,
					MIN(created_at) OVER (
						PARTITION BY COALESCE(NULLIF(conversation_key, ''), request_id)
					) AS first_seen_at,
					MAX(created_at) OVER (
						PARTITION BY COALESCE(NULLIF(conversation_key, ''), request_id)
					) AS last_seen_at,
					FIRST_VALUE(action_taken) OVER (
						PARTITION BY COALESCE(NULLIF(conversation_key, ''), request_id)
						ORDER BY CASE action_taken
							WHEN 'security_blocked' THEN 4
							WHEN 'blocked' THEN 4
							WHEN 'block' THEN 4
							WHEN 'deny' THEN 4
							WHEN 'security_replied' THEN 3
							WHEN 'security_masked' THEN 3
							WHEN 'reply' THEN 3
							WHEN 'mask' THEN 3
							WHEN 'redact' THEN 3
							WHEN 'rewrite' THEN 3
							WHEN 'security_audit' THEN 2
							WHEN 'security_audit_only' THEN 2
							WHEN 'tool_audited' THEN 2
							WHEN 'tool_audit_only' THEN 2
							WHEN 'audit' THEN 2
							WHEN 'allow' THEN 1
							ELSE 0
						END DESC, created_at DESC, id DESC
					) AS strictest_action,
					FIRST_VALUE(severity) OVER (
						PARTITION BY COALESCE(NULLIF(conversation_key, ''), request_id)
						ORDER BY CASE severity
							WHEN 'critical' THEN 4
							WHEN 'high' THEN 3
							WHEN 'medium' THEN 2
							WHEN 'low' THEN 1
							ELSE 0
						END DESC, created_at DESC, id DESC
					) AS highest_severity
				FROM security_events
				WHERE tenant_id = $1 AND alert_group_id = $2
			)
			SELECT row_key, id, request_id, principal_key, conversation_key,
			       -- Conversation action = strongest disposition across the whole conversation,
			       -- not the representative row's own action.
			       -- Spec: docs/superpowers/specs/2026-07-28-alert-occurrence-conversation-collapse-design.md
			       event_type, highest_severity, strictest_action, created_at,
			       event_count, first_seen_at, last_seen_at
			FROM ranked
			WHERE row_number = 1
			ORDER BY last_seen_at DESC, row_key
			LIMIT $3 OFFSET $4
		`
		return countSQL, listSQL, []any{tenantID, groupID}, []any{tenantID, groupID, limit, offset}
	}

	where := "tenant_id = $1 AND alert_group_id = $2"
	countArgs := []any{tenantID, groupID}
	listArgs := []any{tenantID, groupID}
	limitPosition, offsetPosition := 3, 4
	if filter.ConversationKey != "" {
		where += " AND conversation_key = $3"
		countArgs = append(countArgs, filter.ConversationKey)
		listArgs = append(listArgs, filter.ConversationKey)
		limitPosition, offsetPosition = 4, 5
	}
	countSQL := "SELECT COUNT(*) FROM security_events WHERE " + where
	listSQL := fmt.Sprintf(`
		SELECT id AS row_key, id, request_id, COALESCE(principal_key, ''),
		       COALESCE(conversation_key, ''), event_type, severity, action_taken,
		       created_at, 1 AS event_count, created_at AS first_seen_at, created_at AS last_seen_at
		FROM security_events
		WHERE %s
		ORDER BY created_at DESC, id DESC
		LIMIT $%d OFFSET $%d
	`, where, limitPosition, offsetPosition)
	listArgs = append(listArgs, limit, offset)
	return countSQL, listSQL, countArgs, listArgs
}

// ListGroupEvents 分页列出组内会话摘要或物理事件（时间倒序）。
// 注意口径：被抑制/FP 静默的事件没有 alert_group_id，不在此列（UI 需注明）。
func (r *AlertGroupRepository) ListGroupEvents(ctx context.Context, tenantID, groupID string, filter AlertGroupEventListFilter) ([]*AlertGroupEvent, int, error) {
	if r == nil || r.db == nil {
		return nil, 0, errors.New("alert group repository db is nil")
	}
	countSQL, listSQL, countArgs, listArgs := buildAlertGroupEventsQueries(tenantID, groupID, filter)
	var total int
	if err := r.db.QueryRow(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(ctx, listSQL, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	events := []*AlertGroupEvent{}
	for rows.Next() {
		var e AlertGroupEvent
		if err := rows.Scan(
			&e.RowKey, &e.EventID, &e.RequestID, &e.PrincipalKey, &e.ConversationKey,
			&e.EventType, &e.Severity, &e.ActionTaken, &e.CreatedAt,
			&e.EventCount, &e.FirstSeenAt, &e.LastSeenAt,
		); err != nil {
			return nil, 0, err
		}
		events = append(events, &e)
	}
	return events, total, rows.Err()
}
