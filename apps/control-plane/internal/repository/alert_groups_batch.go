package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AlertGroupBatchMaxIDs 是单次批量处置的条数上限。批量只接受前端勾选出的显式 id 列表，
// 不提供"按条件一键全关"：积压是否整体关闭由人决定，且每一批都要能在审计里逐条追溯。
const AlertGroupBatchMaxIDs = 500

const (
	// AlertGroupBatchReasonNotFound 覆盖不存在、跨租户与不在本人部门范围内三种情况——
	// 对调用方刻意不区分，避免借批量接口探测别的租户/部门是否存在某个告警组。
	AlertGroupBatchReasonNotFound = "not_found"
	// AlertGroupBatchReasonNotOpen 表示组已不处于该动作允许的待处置状态（已关闭/已误报，或重复确认）。
	AlertGroupBatchReasonNotOpen = "not_open"
)

type AlertGroupBatchStatusInput struct {
	TenantID string
	IDs      []string
	Status   AlertGroupStatus
	ActorID  string
	Note     string
	// ProjectIDs 非 nil 时只允许处置这些 project 下的组（部门主管口径，与列表收窄一致）；
	// 空切片 = 一个都不允许（fail-closed）。
	ProjectIDs []string
}

type AlertGroupBatchFailure struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type AlertGroupBatchStatusResult struct {
	UpdatedIDs []string
	Failed     []AlertGroupBatchFailure
}

// batchFromStatuses 给出每个批量动作允许的起始状态，语义与单条 UpdateStatus 的列迁移一致，
// 但只做"待处置 → 已处置"方向：确认只从 open 出发；关闭/误报从 open 或 acknowledged 出发。
// 批量不支持重新打开（open），重开仍走单条接口逐个判断。
func batchFromStatuses(status AlertGroupStatus) ([]string, bool) {
	switch status {
	case AlertGroupStatusAcknowledged:
		return []string{string(AlertGroupStatusOpen)}, true
	case AlertGroupStatusResolved, AlertGroupStatusFalsePositive:
		return []string{string(AlertGroupStatusOpen), string(AlertGroupStatusAcknowledged)}, true
	}
	return nil, false
}

// BatchUpdateStatus 在一个事务里把显式 id 列表中、属于本租户（及可选部门范围）且处于可迁移
// 状态的告警组迁到目标状态；其余 id 以明细返回失败原因。只写 alert_groups，不触碰
// security_events 及任何审计证据。
func (r *AlertGroupRepository) BatchUpdateStatus(ctx context.Context, in AlertGroupBatchStatusInput) (AlertGroupBatchStatusResult, error) {
	var res AlertGroupBatchStatusResult
	if r == nil || r.db == nil {
		return res, errors.New("alert group repository db is nil")
	}
	if strings.TrimSpace(in.TenantID) == "" {
		return res, errors.New("tenant id is required")
	}
	if len(in.IDs) == 0 {
		return res, errors.New("alert group ids are required")
	}
	if len(in.IDs) > AlertGroupBatchMaxIDs {
		return res, fmt.Errorf("at most %d alert groups per batch", AlertGroupBatchMaxIDs)
	}
	from, ok := batchFromStatuses(in.Status)
	if !ok {
		return res, fmt.Errorf("invalid batch alert group status: %s", in.Status)
	}

	scopeSQL := ""
	args := []any{in.Status, time.Now().UTC(), in.ActorID, in.Note, in.TenantID, in.IDs, from}
	if in.ProjectIDs != nil {
		args = append(args, in.ProjectIDs)
		scopeSQL = fmt.Sprintf(" AND project_id = ANY($%d::text[])", len(args))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		UPDATE alert_groups
		SET status = $1::varchar,
		    acknowledged_at = CASE WHEN $1::varchar = 'acknowledged' THEN $2 ELSE acknowledged_at END,
		    resolved_at = CASE WHEN $1::varchar = 'resolved' THEN $2 ELSE resolved_at END,
		    false_positive_at = CASE WHEN $1::varchar = 'false_positive' THEN $2 ELSE false_positive_at END,
		    closed_at = CASE WHEN $1::varchar IN ('resolved', 'false_positive') THEN $2 ELSE closed_at END,
		    disposition_by = NULLIF($3,''),
		    disposition_note = NULLIF($4,''),
		    updated_at = $2
		WHERE tenant_id = $5 AND id = ANY($6::text[]) AND status = ANY($7::text[])`+scopeSQL+`
		RETURNING id
	`, args...)
	if err != nil {
		return res, err
	}
	updated := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return res, err
		}
		updated[id] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}
	if len(updated) > 0 {
		changed := make([]string, 0, len(updated))
		for id := range updated {
			changed = append(changed, id)
		}
		syncAlertCaseRefs(ctx, r.db, in.TenantID, map[string][]string{"group": changed})
	}

	// 未迁移的 id 区分"看得见但状态不对"与"看不见"：可见性判定与上面的 UPDATE 用同一租户/部门谓词。
	visible := map[string]bool{}
	remaining := make([]string, 0, len(in.IDs))
	for _, id := range in.IDs {
		if !updated[id] {
			remaining = append(remaining, id)
		}
	}
	if len(remaining) > 0 {
		visArgs := []any{in.TenantID, remaining}
		visScope := ""
		if in.ProjectIDs != nil {
			visArgs = append(visArgs, in.ProjectIDs)
			visScope = " AND project_id = ANY($3::text[])"
		}
		vrows, err := tx.Query(ctx, `SELECT id FROM alert_groups WHERE tenant_id = $1 AND id = ANY($2::text[])`+visScope, visArgs...)
		if err != nil {
			return res, err
		}
		for vrows.Next() {
			var id string
			if err := vrows.Scan(&id); err != nil {
				vrows.Close()
				return res, err
			}
			visible[id] = true
		}
		vrows.Close()
		if err := vrows.Err(); err != nil {
			return res, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return res, err
	}

	// 按入参顺序输出，便于前端逐条对照。
	for _, id := range in.IDs {
		switch {
		case updated[id]:
			res.UpdatedIDs = append(res.UpdatedIDs, id)
		case visible[id]:
			res.Failed = append(res.Failed, AlertGroupBatchFailure{ID: id, Reason: AlertGroupBatchReasonNotOpen})
		default:
			res.Failed = append(res.Failed, AlertGroupBatchFailure{ID: id, Reason: AlertGroupBatchReasonNotFound})
		}
	}
	return res, nil
}
