package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

const (
	maxAlertGroupBatchBodyBytes = 128 << 10
	maxAlertGroupIDLength       = 128
	maxAlertGroupBatchNoteRunes = 500
	alertGroupBatchAuditSample  = 20
)

// alertGroupBatchFilters 只是前端勾选时所处的筛选上下文，原样写进审计便于事后复盘；
// 它不参与选择——服务端只处置 ids 里显式列出的组，绝不按条件扩展。
type alertGroupBatchFilters struct {
	Type   string `json:"type,omitempty"`
	Rule   string `json:"rule,omitempty"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Status string `json:"status,omitempty"`
}

// BatchUpdateAlertGroupStatus serves POST /admin/v1/alert-groups/batch-status.
// 批量确认 / 关闭 / 标记误报：沿用单条 PATCH 的鉴权链（RBAC alert_groups:write + SoD alert_handle）
// 与租户隔离；部门主管只能处置本部门 project 下的组。整批写一条审计。
func BatchUpdateAlertGroupStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		// 处置告警需要管理员类角色：RBAC 中间件默认只记录不拦截（UAG_RBAC_ENFORCE=false），
		// 这里按角色硬性校验，普通用户、部门主管、审计员不能改告警状态。
		if !roles.CanHandleAlerts(user.Role) && !roles.IsSystemAdmin(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "当前角色无权处置告警")
			return
		}
		batchRepo, ok := deps.AlertGroupRepo.(AlertGroupBatchRepo)
		if deps.AlertGroupRepo == nil || !ok {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert groups not configured")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAlertGroupBatchBodyBytes)
		var body struct {
			IDs     []string                    `json:"ids"`
			Status  repository.AlertGroupStatus `json:"status"`
			Note    string                      `json:"note"`
			Filters alertGroupBatchFilters      `json:"filters"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "request_too_large", "batch request is too large")
				return
			}
			writeError(w, "invalid_request", "invalid json body")
			return
		}
		switch body.Status {
		case repository.AlertGroupStatusAcknowledged, repository.AlertGroupStatusResolved, repository.AlertGroupStatusFalsePositive:
		default:
			writeError(w, "invalid_request", "status must be acknowledged, resolved or false_positive")
			return
		}
		ids := make([]string, 0, len(body.IDs))
		seen := make(map[string]bool, len(body.IDs))
		for _, raw := range body.IDs {
			id := strings.TrimSpace(raw)
			if id == "" || len(id) > maxAlertGroupIDLength {
				writeError(w, "invalid_request", "alert group ids must be non-empty and at most 128 characters")
				return
			}
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			writeError(w, "invalid_request", "select at least one alert group")
			return
		}
		if len(ids) > repository.AlertGroupBatchMaxIDs {
			writeError(w, "invalid_request", "at most 500 alert groups per batch")
			return
		}
		note := strings.TrimSpace(body.Note)
		if len([]rune(note)) > maxAlertGroupBatchNoteRunes {
			writeError(w, "invalid_request", "note must be at most 500 characters")
			return
		}

		var result repository.AlertGroupBatchStatusResult
		in := repository.AlertGroupBatchStatusInput{TenantID: user.TenantID, IDs: ids, Status: body.Status, ActorID: user.ID, Note: note}
		// 与单条详情/列表同口径：非全租户角色只能动本部门 project 的组；无 project → 全部按不存在处理。
		scopeEmpty := false
		if scope, ok := resolveUsageScope(r, deps); ok && !scope.FullTenant {
			if len(scope.ProjectIDs) == 0 {
				scopeEmpty = true
			} else {
				in.ProjectIDs = scope.ProjectIDs
			}
		}
		if scopeEmpty {
			for _, id := range ids {
				result.Failed = append(result.Failed, repository.AlertGroupBatchFailure{ID: id, Reason: repository.AlertGroupBatchReasonNotFound})
			}
		} else {
			res, err := batchRepo.BatchUpdateStatus(r.Context(), in)
			if err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to update alert groups")
				return
			}
			result = res
		}

		digest := sha256.Sum256([]byte(strings.Join(ids, "\n")))
		sample := ids
		if len(sample) > alertGroupBatchAuditSample {
			sample = sample[:alertGroupBatchAuditSample]
		}
		failedIDs := make([]string, 0, len(result.Failed))
		for _, f := range result.Failed {
			failedIDs = append(failedIDs, f.ID)
		}
		if len(failedIDs) > alertGroupBatchAuditSample {
			failedIDs = failedIDs[:alertGroupBatchAuditSample]
		}
		logAudit(r, deps, "alert_group.batch_status", map[string]any{
			"status":            string(body.Status),
			"requested":         len(ids),
			"updated":           len(result.UpdatedIDs),
			"failed":            len(result.Failed),
			"filters":           map[string]any{"type": body.Filters.Type, "rule": body.Filters.Rule, "from": body.Filters.From, "to": body.Filters.To, "status": body.Filters.Status},
			"ids_sha256":        hex.EncodeToString(digest[:]),
			"ids_sample":        sample,
			"failed_ids_sample": failedIDs,
			"note":              note,
		}, "alert_group", "batch")

		failed := result.Failed
		if failed == nil {
			failed = []repository.AlertGroupBatchFailure{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"requested":   len(ids),
			"updated":     len(result.UpdatedIDs),
			"updated_ids": result.UpdatedIDs,
			"failed":      failed,
		})
	}
}
