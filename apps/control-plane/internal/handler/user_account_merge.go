package handler

import (
	"encoding/json"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"strings"
)

func AccountMerge(deps *Dependencies, dryRun bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = withOperationAudit(r, deps)
		actor := auth.GetUser(r.Context())
		if actor == nil || (actor.Role != "platform_admin" && actor.Role != "tenant_admin") {
			writeErrorWithStatus(w, 403, "forbidden", "没有合并账号的权限")
			return
		}
		if deps == nil || deps.UserAccountMergeRepo == nil {
			writeErrorWithStatus(w, 503, "account_merge_unavailable", "账号合并服务暂不可用")
			return
		}
		var req struct {
			SourceUserID string `json:"source_user_id"`
			repository.AccountMergeInput
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768))
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil || dec.Decode(&struct{}{}) != io.EOF || strings.TrimSpace(req.SourceUserID) == "" {
			writeError(w, "invalid_request", "请选择源账号并填写有效预览与冲突选择")
			return
		}
		target := chi.URLParam(r, "id")
		var result *repository.AccountMergePreview
		var err error
		if dryRun {
			result, err = deps.UserAccountMergeRepo.Preview(r.Context(), actor.TenantID, req.SourceUserID, target, actor.ID)
		} else {
			result, err = deps.UserAccountMergeRepo.Merge(r.Context(), actor.TenantID, req.SourceUserID, target, actor.ID, req.AccountMergeInput)
		}
		switch {
		case errors.Is(err, repository.ErrAccountMergeWalletNotEmpty):
			writeErrorWithStatus(w, 409, "account_merge_wallet_not_empty", "账号钱包余额或预留金额非零，暂不能合并，请先处理余额")
		case errors.Is(err, repository.ErrAccountMergeInactive):
			writeErrorWithStatus(w, 409, "account_merge_user_inactive", "源账号或目标账号已停用，请检查账号状态")
		case errors.Is(err, repository.ErrAccountMergeProjectMissing):
			writeErrorWithStatus(w, 409, "account_merge_project_unavailable", "所选部门尚未配置默认应用，无法迁入 Key")
		case errors.Is(err, repository.ErrAccountMergeForbidden):
			writeErrorWithStatus(w, 403, "account_merge_forbidden", "不得合并自身账号，租户管理员仅可操作普通员工账号")
		case errors.Is(err, repository.ErrAccountMergeUnavailable), errors.Is(err, pgx.ErrNoRows):
			writeErrorWithStatus(w, 404, "account_merge_unavailable", "账号不存在或不在当前租户")
		case errors.Is(err, repository.ErrAccountMergeChoices):
			writeErrorWithStatus(w, 409, "account_merge_choices_required", "请逐项选择冲突处理规则，未选择不能合并")
		case errors.Is(err, repository.ErrAccountMergeConflict):
			writeErrorWithStatus(w, 409, "account_merge_conflict", "账号资料已变化，请重新预览")
		case err != nil:
			writeErrorWithStatus(w, 503, "account_merge_unavailable", "账号合并失败，事务已回滚")
		default:
			writeJSON(w, map[string]any{"data": result, "dry_run": dryRun})
		}
	}
}

func RebindUserIdentity(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = withOperationAudit(r, deps)
		actor := auth.GetUser(r.Context())
		if actor == nil || (actor.Role != "platform_admin" && actor.Role != "tenant_admin") {
			writeErrorWithStatus(w, 403, "forbidden", "没有换绑身份的权限")
			return
		}
		if deps == nil || deps.UserAccountMergeRepo == nil {
			writeErrorWithStatus(w, 503, "account_merge_unavailable", "身份换绑服务暂不可用")
			return
		}
		var req struct {
			TargetUserID   string `json:"target_user_id"`
			PreviewVersion string `json:"preview_version"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil || dec.Decode(&struct{}{}) != io.EOF || req.TargetUserID == "" {
			writeError(w, "invalid_request", "请选择有效目标账号")
			return
		}
		err := deps.UserAccountMergeRepo.RebindIdentity(r.Context(), actor.TenantID, chi.URLParam(r, "id"), req.TargetUserID, actor.ID, chi.URLParam(r, "link_id"), req.PreviewVersion)
		if errors.Is(err, repository.ErrAccountMergeForbidden) {
			writeErrorWithStatus(w, 403, "account_merge_forbidden", "不得换绑自身账号，租户管理员仅可操作普通员工账号")
			return
		}
		if errors.Is(err, repository.ErrAccountMergeInactive) {
			writeErrorWithStatus(w, 409, "account_merge_user_inactive", "源账号或目标账号已停用")
			return
		}
		if errors.Is(err, repository.ErrAccountMergeConflict) {
			writeErrorWithStatus(w, 409, "account_merge_conflict", "身份资料已变化或缺少有效预览，请重新预览")
			return
		}
		if errors.Is(err, repository.ErrAccountMergeUnavailable) || errors.Is(err, pgx.ErrNoRows) {
			writeErrorWithStatus(w, 404, "not_found", "账号或身份不存在于本租户")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, 503, "account_merge_unavailable", "身份换绑失败，事务已回滚")
			return
		}
		writeJSON(w, map[string]any{"data": map[string]bool{"rebound": true}})
	}
}
