package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// identityRuntimeObserver 是可选能力：只读反推运行态选项。未实现时采纳接口返回「运行服务不可用」。
type identityRuntimeObserver interface {
	Observe(context.Context, identityruntime.DesiredIdentitySource) (identityruntime.ObservedSettings, error)
}

const adoptNotAdoptableMessage = "仅启用中或已停用的身份源可采纳（当前处于编辑中，请先发布或放弃草稿）"

type adoptRuntimeReq struct {
	// SourceID 必填：同一 alias 可能有多条记录，只采纳明确指定的这一条。
	SourceID string `json:"source_id"`
}

type adoptSameAliasDTO struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	Version       int    `json:"version"`
	PublishStatus string `json:"publish_status"`
}

// AdoptIdentityRuntime POST /admin/v1/identity/sources/adopt-runtime
//
// 管理员触发：只读读取运行态，反推 signature_mode / username_claim / skip_profile_review 写回数据库，
// 并按新选项重算期望摘要。全程不写运行态，不会把验签重新打开。
// 运行态里保存的发布摘要仍是旧值，所以采纳后通常仍显示「配置不一致」，需再执行一次「按当前配置修复」才会收敛为已启用。
func AdoptIdentityRuntime(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !isIdentityAdmin(user) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		var req adoptRuntimeReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.SourceID) == "" {
			writeError(w, "invalid_request", "请指定要采纳运行配置的身份源")
			return
		}
		src, err := deps.IdentitySourceRepo.GetByID(r.Context(), user.TenantID, strings.TrimSpace(req.SourceID))
		if err != nil {
			writeError(w, "internal_error", "获取身份源失败")
			return
		}
		if src == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "身份源不存在")
			return
		}
		// 编辑中的身份源（草稿/已测试）不能采纳：在读取运行态之前先拦截。
		if src.Status != "active" && src.Status != "disabled" {
			writeErrorWithStatus(w, http.StatusConflict, "adopt_target_not_adoptable", adoptNotAdoptableMessage)
			return
		}
		observer, ok := deps.IdentityRuntime.(identityRuntimeObserver)
		if deps.IdentityRuntime == nil || !ok {
			writeIdentityRuntimeError(w, identityruntime.ErrRuntimeUnavailable)
			return
		}
		alias := sourceAlias(src)
		observeCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		observed, err := observer.Observe(observeCtx, identityruntime.DesiredIdentitySource{
			Realm: identityruntime.RealmName, Alias: alias,
		})
		cancel()
		if err != nil {
			writeIdentityRuntimeError(w, err)
			return
		}
		if !observed.Exists {
			writeErrorWithStatus(w, http.StatusNotFound, "runtime_not_found", "运行环境中没有该身份源的配置，无可采纳内容")
			return
		}

		adopted := *src
		adopted.SignatureMode = observed.SignatureMode
		adopted.SkipProfileReview = observed.SkipProfileReview
		if observed.UsernameClaim != "" {
			adopted.UsernameClaim = observed.UsernameClaim
		}
		desired, err := desiredIdentitySource(r.Context(), deps, &adopted)
		if err != nil {
			writeIdentityRuntimeError(w, err)
			return
		}
		result, err := deps.IdentitySourceRepo.AdoptRuntimeSettings(r.Context(), repository.AdoptRuntimeInput{
			TenantID: user.TenantID, SourceID: src.ID, Version: src.Version,
			SignatureMode: observed.SignatureMode, UsernameClaim: observed.UsernameClaim,
			SkipProfileReview: observed.SkipProfileReview, ConfigDigest: desired.Digest,
		})
		switch {
		case errors.Is(err, repository.ErrAdoptTargetNotActive):
			writeErrorWithStatus(w, http.StatusConflict, "adopt_target_not_active",
				"同一登录入口下已有启用中的身份源，运行配置属于启用中的那一条，请改为采纳它")
			return
		case errors.Is(err, repository.ErrAdoptTargetNotAdoptable):
			writeErrorWithStatus(w, http.StatusConflict, "adopt_target_not_adoptable", adoptNotAdoptableMessage)
			return
		case errors.Is(err, repository.ErrIdentitySourceChanged):
			// 读取运行态期间配置被他人修改（或身份源已不存在）：不写库，请刷新后重试。
			writeErrorWithStatus(w, http.StatusConflict, "identity_publish_conflict", "配置已被他人修改，请刷新后重试")
			return
		case err != nil:
			writeError(w, "internal_error", "写入采纳结果失败")
			return
		}

		drift := true
		publishStatus := "drifted"
		checkCtx, checkCancel := context.WithTimeout(r.Context(), identityStatusTimeout)
		status, statusErr := deps.IdentityRuntime.Status(checkCtx, identityruntime.DesiredIdentitySource{
			Realm: identityruntime.RealmName, Alias: alias, Digest: desired.Digest,
		})
		checkCancel()
		if statusErr == nil && !status.Drifted {
			drift, publishStatus = false, "active"
		}
		if src.Status == "active" && statusErr == nil {
			_ = deps.IdentitySourceRepo.MarkRuntimeStatus(r.Context(), user.TenantID, src.ID, publishStatus)
		}

		same := make([]adoptSameAliasDTO, 0, len(result.SameAliasSources))
		for _, other := range result.SameAliasSources {
			same = append(same, adoptSameAliasDTO{ID: other.ID, Status: other.Status, Version: other.Version, PublishStatus: other.PublishStatus})
		}
		unresolved := []string{}
		if observed.UsernameClaim == "" {
			unresolved = append(unresolved, "username_claim")
		}
		message := "已采纳运行环境的现有配置"
		if drift {
			message += "；运行环境记录的发布摘要尚未更新，请再执行一次「按当前配置修复」，修复将按已采纳的选项发布，不会改回默认值"
		}
		if len(same) > 0 {
			message += "；同一登录入口下还有其他身份源记录，未被改动，请确认是否需要清理"
		}
		logAudit(r, deps, "identity.source.runtime_adopted", map[string]interface{}{
			"display_name": src.DisplayName, "source_version": src.Version,
			"signature_mode": observed.SignatureMode, "username_claim": observed.UsernameClaim,
			"skip_profile_review": observed.SkipProfileReview, "same_alias_sources": len(same),
		}, "identity_source", src.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true, "message": message,
			"adopted": map[string]any{
				"signature_mode": observed.SignatureMode, "username_claim": adopted.UsernameClaim,
				"skip_profile_review": observed.SkipProfileReview,
			},
			"unresolved":         unresolved,
			"same_alias_sources": same,
			"publish_status":     publishStatus, "drift": drift,
		})
	}
}
