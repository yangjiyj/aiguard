// TODO(I-3 backlog): 本文件 661+ 行职责过重，建议把 IncrementalDirectorySync/
// activatePreviewEntries/claimAndCreateRun/finalizeActivationTx 等服务层逻辑
// 抽到 internal/directorysync/service.go，handler 只留 HTTP 编解码。当前不修
// 避免范围蔓延，供后续可维护性 backlog 跟进。
package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryldap"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// previewTTL 控制预览过期窗口；激活路径据此校验未过期。
const previewTTL = 24 * time.Hour

// previewEntryMaxScan 单次预览扫描的条目上限，防止超大目录拖垮控制面。
const previewEntryMaxScan = 10000

// directoryPreviewResponse 是预览响应体；只暴露计数 + ID，绝不暴露脱敏字段以外的内容。
type directoryPreviewResponse struct {
	PreviewID  string `json:"preview_id"`
	SourceID   string `json:"source_id"`
	Status     string `json:"status"`
	Scanned    int    `json:"scanned"`
	Created    int    `json:"created"`
	Updated    int    `json:"updated"`
	Disabled   int    `json:"disabled"`
	Conflict   int    `json:"conflict"`
	Unassigned int    `json:"unassigned"`
	ErrorCode  string `json:"error_code,omitempty"`
	ExpiresAt  string `json:"expires_at"`
}

// directoryActivationResponse 是激活响应体；幂等返回同一 run_id。
type directoryActivationResponse struct {
	RunID      string `json:"run_id"`
	PreviewID  string `json:"preview_id"`
	Scanned    int    `json:"scanned"`
	Created    int    `json:"created"`
	Updated    int    `json:"updated"`
	Disabled   int    `json:"disabled"`
	Conflict   int    `json:"conflict"`
	Unassigned int    `json:"unassigned"`
	Restored   int    `json:"restored"`
}

// PreviewDirectorySource POST /admin/v1/directory/sources/preview
//
// 行为：读取已通过连接测试的目录草稿 → 解密 Bind Password 仅用于本进程拉取账号
// → 把每个账号的脱敏字段 + content_digest 写入 preview 表 → 不写 users /
// user_identity_links / team_members / directory_user_links。
//
// 安全：Bind Password 绝不落 preview 表或日志；响应只暴露计数。
func PreviewDirectorySource(deps *Dependencies) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		user := auth.GetUser(request.Context())
		if user == nil {
			writeUnauthorized(writer, "no user")
			return
		}
		if !isIdentityAdmin(user) {
			writeErrorWithStatus(writer, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		if deps.DirectorySourceRepo == nil || deps.DirectorySyncPreviewRepo == nil || deps.DirectoryTester == nil {
			writeError(writer, "service_unavailable", "目录同步服务未配置")
			return
		}
		draft, err := deps.DirectorySourceRepo.GetDraft(request.Context(), user.TenantID)
		if err != nil {
			writeError(writer, "internal_error", "获取目录草稿失败")
			return
		}
		if draft == nil {
			writeErrorWithStatus(writer, http.StatusNotFound, "not_found", "请先保存并测试目录配置")
			return
		}
		if draft.Status != "tested" {
			writeErrorWithStatus(writer, http.StatusConflict, "not_tested", "请先通过目录连接测试")
			return
		}
		if err := validateDirectoryDraftSyncPreflight(request.Context(), DirectoryTargetPolicyFor(request.Context(), deps), draft); err != nil {
			writeError(writer, "invalid_request", "目录连接地址不符合当前安全策略")
			return
		}

		password, err := secrets.DecryptProviderSecret(draft.BindPasswordEnc)
		if err != nil {
			writeError(writer, "internal_error", "解密绑定密码失败")
			return
		}
		// 建预览头并立即落 running 状态，便于审计与历史追溯。
		// ComputeDigest 仅对 Kind/ConnectionURL/BindDN/UsersDN 做哈希；BindPassword
		// 占位符只用于通过 config 校验，绝不进入 digest 输出或落库。
		digest, err := directoryruntime.ComputeDigest(directoryruntime.DirectoryConfig{
			Kind: directoryruntime.DirectoryKind(draft.Kind), ConnectionURL: draft.ConnectionURL,
			BindDN: draft.BindDN, BindPassword: "[redacted]", UsersDN: draft.UsersDN,
		})
		if err != nil {
			writeError(writer, "internal_error", "计算目录配置指纹失败")
			return
		}
		preview := &repository.DirectorySyncPreview{
			TenantID: user.TenantID, DirectorySourceID: draft.ID,
			SourceVersion: draft.Version, ConfigDigest: digest,
			ActorUserID: user.ID, ExpiresAt: time.Now().Add(previewTTL),
		}
		if err := deps.DirectorySyncPreviewRepo.CreatePreview(request.Context(), preview); err != nil {
			writeError(writer, "internal_error", "创建目录预览失败")
			return
		}

		entries, err := deps.DirectoryTester.ListUsers(request.Context(), directoryldap.SyncRequest{
			TestRequest: directoryldap.TestRequest{ConnectionURL: draft.ConnectionURL, BindDN: draft.BindDN, BindPassword: password, CACertPEM: draft.CACertPEM},
			UsersDN:     draft.UsersDN, UserFilter: draft.UserFilter, StableIDAttribute: draft.StableIDAttribute,
			UsernameAttribute: draft.UsernameAttribute, EmailAttribute: draft.EmailAttribute, NameAttribute: draft.NameAttribute,
		})
		if err != nil {
			_ = deps.DirectorySyncPreviewRepo.FinalizePreview(request.Context(), user.TenantID, preview.ID, repository.PreviewStatusFailed, repository.PreviewCounts{}, "directory_list_failed")
			writeErrorWithStatus(writer, http.StatusBadGateway, "directory_list_failed", "目录读取失败，请检查连接、证书和账号权限")
			return
		}
		if len(entries) > previewEntryMaxScan {
			_ = deps.DirectorySyncPreviewRepo.FinalizePreview(request.Context(), user.TenantID, preview.ID, repository.PreviewStatusFailed, repository.PreviewCounts{}, "preview_too_large")
			writeError(writer, "invalid_request", "目录账号数量超过预览上限，请收窄同步范围")
			return
		}

		counts := repository.PreviewCounts{Scanned: len(entries)}
		// 预先取已绑定集合用于判断 create / update / restore（仅基于稳定 ID，不写库）
		bound, err := deps.DirectorySyncPreviewRepo.ListBoundDirectoryUserIDs(request.Context(), user.TenantID, draft.ID)
		if err != nil {
			writeError(writer, "internal_error", "读取目录账号绑定失败")
			return
		}
		for _, entry := range entries {
			action := repository.PreviewActionCreate
			if _, ok := bound[entry.ObjectID]; ok {
				action = repository.PreviewActionUpdate
			}
			previewEntry := &repository.DirectorySyncPreviewEntry{
				TenantID: user.TenantID, PreviewID: preview.ID,
				ExternalSubject: entry.ObjectID,
				ContentDigest:   directoryContentDigest(entry),
				Action:          action,
				Username:        entry.Username, DisplayName: entry.Name,
				ResolutionStatus: "pending",
			}
			if err := deps.DirectorySyncPreviewRepo.AppendPreviewEntry(request.Context(), previewEntry); err != nil {
				writeError(writer, "internal_error", "写入目录预览条目失败")
				return
			}
		}
		if err := deps.DirectorySyncPreviewRepo.FinalizePreview(request.Context(), user.TenantID, preview.ID, repository.PreviewStatusSucceeded, counts, ""); err != nil {
			writeError(writer, "internal_error", "完成目录预览失败")
			return
		}
		logAudit(request, deps, "directory.source.previewed", map[string]any{
			"scanned": counts.Scanned, "config_version": draft.Version,
		}, "directory_source", draft.ID)
		writePreviewResponse(writer, preview, counts)
	}
}

// directoryContentDigest 计算 (objectID + username + email + dn) 的 SHA-256，
// 作为内容指纹用于变更检测；绝不包含密码或敏感凭据。
//
// digest 在 LDAP 拉取时计算（含 email 用于检测目录侧账号变化），落库只存
// digest 不存 email 明文——directory_sync_preview_entries 表无 email 列，
// 激活路径也不依赖 email（部门归属靠 match_type/match_value）。
func directoryContentDigest(entry directoryldap.DirectoryUser) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(entry.ObjectID))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(entry.Username))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(entry.Email))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(entry.DN))
	return hex.EncodeToString(hash.Sum(nil))
}

func writePreviewResponse(writer http.ResponseWriter, preview *repository.DirectorySyncPreview, counts repository.PreviewCounts) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{"data": directoryPreviewResponse{
		PreviewID: preview.ID, SourceID: preview.DirectorySourceID, Status: preview.Status,
		Scanned: counts.Scanned, Created: counts.Created, Updated: counts.Updated,
		Disabled: counts.Disabled, Conflict: counts.Conflict, Unassigned: counts.Unassigned,
		ErrorCode: preview.ErrorCode, ExpiresAt: preview.ExpiresAt.Format(time.RFC3339),
	}})
}

// GetDirectoryPreview GET /admin/v1/directory/sources/previews/{id}
//
// 返回预览头 + 条目计数；条目级详情只暴露脱敏字段（不含 email 明文）。
func GetDirectoryPreview(deps *Dependencies) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		user := auth.GetUser(request.Context())
		if user == nil {
			writeUnauthorized(writer, "no user")
			return
		}
		if deps.DirectorySyncPreviewRepo == nil {
			writeError(writer, "service_unavailable", "目录同步服务未配置")
			return
		}
		previewID := strings.TrimSpace(chi.URLParam(request, "id"))
		if previewID == "" {
			writeError(writer, "invalid_request", "缺少预览 ID")
			return
		}
		preview, err := deps.DirectorySyncPreviewRepo.GetPreview(request.Context(), user.TenantID, previewID)
		if err != nil {
			writeError(writer, "internal_error", "读取目录预览失败")
			return
		}
		if preview == nil {
			writeErrorWithStatus(writer, http.StatusNotFound, "not_found", "预览不存在或已过期")
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": directoryPreviewResponse{
			PreviewID: preview.ID, SourceID: preview.DirectorySourceID, Status: preview.Status,
			Scanned: preview.ScannedCount, Created: preview.CreatedCount, Updated: preview.UpdatedCount,
			Disabled: preview.DisabledCount, Conflict: preview.ConflictCount, Unassigned: preview.UnassignedCount,
			ErrorCode: preview.ErrorCode, ExpiresAt: preview.ExpiresAt.Format(time.RFC3339),
		}})
	}
}

// ActivateDirectoryPreview POST /admin/v1/directory/sources/previews/{id}/activate
func activateDirectoryPreviewByID(deps *Dependencies, writer http.ResponseWriter, request *http.Request, user *repository.User, previewID string) {
	activateDirectoryPreview(deps, writer, request, user, previewID)
}

// 行为：
//  1. 校验 preview 同租户、未过期、source_version 未漂移、status=succeeded 或 activated
//  2. 若已激活：返回原 run_id（幂等）
//  3. 否则：建 sync_run(full) → 逐条 BindAndResolve → 更新 directory_user_links
//     → 禁用已消失账号（不删审计历史）→ FinalizeSyncRun → MarkPreviewActivated
//
// 安全：单条 BindAndResolve 失败记 sync entry error_code，连接级失败终止 run；
// 目录用户绝不覆盖 local/oidic 用户的 stable identity link（由 BindAndResolve 内部保证）。
func ActivateDirectoryPreview(deps *Dependencies) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		user := auth.GetUser(request.Context())
		if user == nil {
			writeUnauthorized(writer, "no user")
			return
		}
		if !isIdentityAdmin(user) {
			writeErrorWithStatus(writer, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		if !decodeDirectoryConfirmation(writer, request) {
			return
		}
		previewID := strings.TrimSpace(chi.URLParam(request, "id"))
		if previewID == "" {
			writeError(writer, "invalid_request", "缺少预览 ID")
			return
		}
		activateDirectoryPreview(deps, writer, request, user, previewID)
	}
}

type directoryRuntimeReconciliationResult struct {
	restoreFailed          bool
	compensationSyncFailed bool
	persistenceFailed      bool
}

func reconcileDirectoryRuntimeAfterFullSync(
	request *http.Request,
	deps *Dependencies,
	runtime DirectoryLifecycleRuntime,
	source *repository.DirectorySource,
	snapshot directoryruntime.RuntimeSnapshot,
	reason string,
) directoryRuntimeReconciliationResult {
	result := directoryRuntimeReconciliationResult{}
	restoreCtx, cancelRestore := context.WithTimeout(
		context.WithoutCancel(request.Context()),
		directoryRestoreTimeout,
	)
	restoreErr := runtime.Restore(restoreCtx, snapshot)
	if restoreErr != nil {
		result.restoreFailed = true
	} else if snapshot.Exists {
		if err := runtime.FullSync(restoreCtx); err != nil {
			result.compensationSyncFailed = true
		}
	}
	cancelRestore()

	persistCtx, cancelPersist := context.WithTimeout(
		context.WithoutCancel(request.Context()),
		directoryRestoreTimeout,
	)
	if err := deps.DirectorySourceRepo.MarkRuntimeReconciliationRequired(
		persistCtx,
		source.TenantID,
		source.ID,
		reason,
	); err != nil {
		result.persistenceFailed = true
	}
	cancelPersist()

	auditCtx, cancelAudit := context.WithTimeout(
		context.WithoutCancel(request.Context()),
		directoryRestoreTimeout,
	)
	logAudit(request.Clone(auditCtx), deps, "directory.source.reconciliation_required", map[string]any{
		"reason":                         reason,
		"restore_succeeded":              !result.restoreFailed,
		"compensation_sync_attempted":    snapshot.Exists && !result.restoreFailed,
		"compensation_sync_succeeded":    !result.compensationSyncFailed,
		"reconciliation_state_persisted": !result.persistenceFailed,
	}, "directory_source", source.ID)
	cancelAudit()
	return result
}

func writeDirectoryReconciliationFailure(w http.ResponseWriter, result directoryRuntimeReconciliationResult) bool {
	if result.persistenceFailed {
		writeDirectoryLifecycleError(w, "directory_reconciliation_persistence_failed", "目录运行状态对账标记失败")
		return true
	}
	if result.restoreFailed || result.compensationSyncFailed {
		writeDirectoryLifecycleError(w, "directory_rollback_failed", "目录配置恢复失败")
		return true
	}
	return false
}

func activateDirectoryPreview(
	deps *Dependencies,
	writer http.ResponseWriter,
	request *http.Request,
	user *repository.User,
	previewID string,
) {
	if deps == nil || deps.DirectorySourceRepo == nil || deps.DirectorySyncPreviewRepo == nil || deps.IdentityBindingService == nil {
		writeError(writer, "service_unavailable", "目录同步服务未配置")
		return
	}
	preview, err := deps.DirectorySyncPreviewRepo.GetPreview(request.Context(), user.TenantID, previewID)
	if err != nil {
		writeError(writer, "internal_error", "读取目录预览失败")
		return
	}
	if preview == nil {
		writeErrorWithStatus(writer, http.StatusNotFound, "not_found", "预览不存在或已过期")
		return
	}
	if preview.Status != repository.PreviewStatusSucceeded && preview.Status != repository.PreviewStatusActivated {
		writeErrorWithStatus(writer, http.StatusConflict, "preview_not_ready", "预览不可激活，请重新预览")
		return
	}
	if preview.Status == repository.PreviewStatusSucceeded && !preview.ExpiresAt.IsZero() && preview.ExpiresAt.Before(time.Now()) {
		writeErrorWithStatus(writer, http.StatusConflict, "preview_expired", "预览已过期，请重新预览")
		return
	}
	claim, err := deps.DirectorySourceRepo.ClaimActivation(request.Context(), user.TenantID)
	if err != nil {
		if errors.Is(err, repository.ErrDirectorySourceActivating) {
			writeErrorWithStatus(writer, http.StatusConflict, "directory_activation_in_progress", "目录源正在激活")
			return
		}
		writeError(writer, "internal_error", "获取目录激活锁失败")
		return
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(
			context.WithoutCancel(request.Context()),
			directoryRestoreTimeout,
		)
		defer cancel()
		_ = claim.Release(releaseCtx)
	}()

	// 配置版本漂移校验：取当前 draft 的 version/digest 对比
	draft, err := deps.DirectorySourceRepo.GetDraft(request.Context(), user.TenantID)
	if err != nil {
		writeError(writer, "internal_error", "获取目录草稿失败")
		return
	}
	if draft == nil || draft.ID != preview.DirectorySourceID || draft.Version != preview.SourceVersion {
		writeErrorWithStatus(writer, http.StatusConflict, "config_drifted", "目录配置已变化，请重新预览")
		return
	}
	runtime, ok := directoryLifecycleRuntime(deps)
	if !ok {
		writeDirectoryLifecycleError(writer, "directory_runtime_unavailable", "\u76ee\u5f55\u8eab\u4efd\u670d\u52a1\u6682\u4e0d\u53ef\u7528")
		return
	}
	bindPassword, err := secrets.DecryptProviderSecret(draft.BindPasswordEnc)
	if err != nil || bindPassword == "" {
		writeDirectoryLifecycleError(writer, "directory_publish_failed", "\u76ee\u5f55\u914d\u7f6e\u53d1\u5e03\u5931\u8d25")
		return
	}
	publication, err := runtime.Publish(request.Context(), directoryruntime.DirectoryConfig{
		Kind: directoryruntime.DirectoryKind(draft.Kind), ConnectionURL: draft.ConnectionURL,
		BindDN: draft.BindDN, BindPassword: bindPassword, UsersDN: draft.UsersDN,
	})
	if err != nil {
		writeDirectoryLifecycleError(writer, "directory_publish_failed", "\u76ee\u5f55\u914d\u7f6e\u53d1\u5e03\u5931\u8d25")
		return
	}
	failAfterFullSync := func(reason string, writeOriginal func()) {
		result := reconcileDirectoryRuntimeAfterFullSync(
			request,
			deps,
			runtime,
			draft,
			publication.Previous,
			reason,
		)
		if !writeDirectoryReconciliationFailure(writer, result) {
			writeOriginal()
		}
	}
	clearAfterFullSync := func() bool {
		if err := deps.DirectorySourceRepo.ClearRuntimeReconciliation(
			request.Context(),
			user.TenantID,
			draft.ID,
		); err == nil {
			return true
		}
		failAfterFullSync(repository.DirectoryReconciliationReasonClearFailed, func() {
			writeDirectoryLifecycleError(writer, "directory_reconciliation_persistence_failed", "目录运行状态对账标记失败")
		})
		return false
	}
	if err := runtime.FullSync(request.Context()); err != nil {
		failAfterFullSync(repository.DirectoryReconciliationReasonFullSyncFailed, func() {
			writeDirectoryLifecycleError(writer, "directory_sync_failed", "\u76ee\u5f55\u540c\u6b65\u5931\u8d25\uff0c\u539f\u914d\u7f6e\u5df2\u6062\u590d")
		})
		return
	}
	if preview.Status == repository.PreviewStatusActivated && preview.ActivatedRunID != "" {
		run, err := deps.DirectorySyncPreviewRepo.GetSyncRun(request.Context(), user.TenantID, preview.ActivatedRunID)
		if err != nil || run == nil {
			failAfterFullSync(repository.DirectoryReconciliationReasonPostSyncFailed, func() {
				writeError(writer, "internal_error", "\u8bfb\u53d6\u540c\u6b65\u8fd0\u884c\u5931\u8d25")
			})
			return
		}
		if draft.Status != "active" {
			if err := deps.DirectorySourceRepo.Activate(request.Context(), user.TenantID, draft.ID, draft.Version); err != nil {
				failAfterFullSync(repository.DirectoryReconciliationReasonPostSyncFailed, func() {
					writeErrorWithStatus(writer, http.StatusConflict, "directory_source_changed", "\u76ee\u5f55\u914d\u7f6e\u5df2\u53d8\u5316")
				})
				return
			}
		}
		if !clearAfterFullSync() {
			return
		}
		writeActivationResponse(writer, run.ID, preview.ID, repository.PreviewCounts{
			Scanned: run.ScannedCount, Created: run.CreatedCount, Updated: run.UpdatedCount,
			Disabled: run.DisabledCount, Conflict: run.ConflictCount, Restored: run.RestoredCount,
			Unassigned: preview.UnassignedCount,
		})
		return
	}
	// I-2 并发安全 + I-1 原子性：先在事务里 CreateSyncRun + ClaimPreviewForActivation
	// CAS 抢占 activated_run_id，只有第一个并发请求能赢。抢不到的走幂等分支。
	run := &repository.DirectorySyncRun{
		TenantID: user.TenantID, DirectorySourceID: preview.DirectorySourceID,
		SourceVersion: preview.SourceVersion, RunKind: "full", ActorUserID: user.ID,
	}
	claimedRunID, claimed, err := claimAndCreateRun(request.Context(), deps, user.TenantID, preview.ID, run)
	if err != nil {
		failAfterFullSync(repository.DirectoryReconciliationReasonPostSyncFailed, func() {
			writeError(writer, "internal_error", "创建同步运行失败")
		})
		return
	}
	if !claimed {
		// 并发请求已抢占：走幂等分支返回赢家 run
		existingRunID := claimedRunID
		if existingRunID == "" {
			// 极端情况：claim 失败但 activated_run_id 仍空（状态已变），重新读 preview 兜底
			reload, reloadErr := deps.DirectorySyncPreviewRepo.GetPreview(request.Context(), user.TenantID, preview.ID)
			if reloadErr != nil || reload == nil {
				failAfterFullSync(repository.DirectoryReconciliationReasonPostSyncFailed, func() {
					writeError(writer, "internal_error", "读取目录预览失败")
				})
				return
			}
			existingRunID = reload.ActivatedRunID
		}
		if existingRunID == "" {
			failAfterFullSync(repository.DirectoryReconciliationReasonPostSyncFailed, func() {
				writeErrorWithStatus(writer, http.StatusConflict, "preview_not_ready", "预览不可激活，请重新预览")
			})
			return
		}
		existingRun, getErr := deps.DirectorySyncPreviewRepo.GetSyncRun(request.Context(), user.TenantID, existingRunID)
		if getErr != nil || existingRun == nil {
			failAfterFullSync(repository.DirectoryReconciliationReasonPostSyncFailed, func() {
				writeError(writer, "internal_error", "读取同步运行失败")
			})
			return
		}
		if !clearAfterFullSync() {
			return
		}
		writeActivationResponse(writer, existingRun.ID, preview.ID, repository.PreviewCounts{
			Scanned: existingRun.ScannedCount, Created: existingRun.CreatedCount, Updated: existingRun.UpdatedCount,
			Disabled: existingRun.DisabledCount, Conflict: existingRun.ConflictCount, Restored: existingRun.RestoredCount,
		})
		return
	}

	// 本请求赢得抢占：执行逐条激活（BindAndResolve 各自开事务，不嵌套）
	interim, err := activatePreviewEntries(request.Context(), deps, user.TenantID, preview, draft, run)
	if err != nil {
		// 连接级失败：同一事务把 run 标 failed 并释放 preview claim，允许安全重试。
		_ = deps.DirectorySyncPreviewRepo.RunInTx(request.Context(), func(tx pgx.Tx) error {
			if err := deps.DirectorySyncPreviewRepo.FinalizeSyncRunTx(request.Context(), tx, user.TenantID, run.ID, "failed", interim.counts, "activation_link_failed"); err != nil {
				return err
			}
			return clearPreviewActivationTx(request.Context(), deps, tx, user.TenantID, preview.ID)
		})
		failAfterFullSync(repository.DirectoryReconciliationReasonPostSyncFailed, func() {
			writeError(writer, "internal_error", "目录激活失败")
		})
		return
	}
	// I-1 汇总写原子：禁用消失账号 + 刷新 last_seen + FinalizeSyncRun + MarkPreviewActivated
	// 任一步失败整体回滚——users.status 不会停在半状态（disabled 但 sync_run 仍 running）。
	counts, disabledUserIDs, err := finalizeActivationTx(request.Context(), deps, user.TenantID, preview.ID, run, interim)
	if err != nil {
		// 汇总写失败：finalizeActivationTx 事务已回滚（users.status/sync_run 计数/preview.status
		// 均未被改），但 claimAndCreateRun 阶段建的 running run 和 activated_run_id 已 commit。
		// 补偿清理：把 run 标 failed、清空 preview.activated_run_id（回到 succeeded 可重试）。
		// 补偿用 raw SQL（不经 wrapper 方法），避免同样的注入故障再次卡住清理。
		_ = deps.DirectorySyncPreviewRepo.RunInTx(request.Context(), func(tx pgx.Tx) error {
			const compensateSQL = `UPDATE directory_sync_runs SET status='failed', finished_at=now(), error_code='finalize_activation_failed' WHERE tenant_id=$1 AND id=$2 AND status='running'`
			if _, ferr := tx.Exec(request.Context(), compensateSQL, user.TenantID, run.ID); ferr != nil {
				return ferr
			}
			return clearPreviewActivationTx(request.Context(), deps, tx, user.TenantID, preview.ID)
		})
		failAfterFullSync(repository.DirectoryReconciliationReasonPostSyncFailed, func() {
			writeError(writer, "internal_error", "完成同步运行失败")
		})
		return
	}
	// W2.5：停用已提交，立即吊销这些用户的控制台会话。失败不回滚停用（停用与
	// key 吊销已生效），只写审计供运维跟进。
	if failed := revokeDirectoryDisabledSessions(request.Context(), deps, disabledUserIDs); len(failed) > 0 {
		logAudit(request, deps, "directory.users.session_revoke_failed", map[string]any{
			"run_id": run.ID, "user_ids": failed,
		}, "directory_source", preview.DirectorySourceID)
	}
	if draft.Status != "active" {
		if err := deps.DirectorySourceRepo.Activate(request.Context(), user.TenantID, draft.ID, draft.Version); err != nil {
			failAfterFullSync(repository.DirectoryReconciliationReasonPostSyncFailed, func() {
				writeErrorWithStatus(writer, http.StatusConflict, "directory_source_changed", "\u76ee\u5f55\u914d\u7f6e\u5df2\u53d8\u5316")
			})
			return
		}
	}
	if !clearAfterFullSync() {
		return
	}
	logAudit(request, deps, "directory.source.activated", map[string]any{
		"run_id": run.ID, "preview_id": preview.ID,
		"created": counts.Created, "updated": counts.Updated, "disabled": counts.Disabled,
		"conflict": counts.Conflict, "unassigned": counts.Unassigned,
	}, "directory_source", preview.DirectorySourceID)
	writeActivationResponse(writer, run.ID, preview.ID, counts)
}

// activatePreviewEntries 逐条激活预览条目：
//   - 调 IdentityBindingService.BindAndResolve（统一部门解析）
//   - 按 Resolution 结果累计 create/update/conflict/unassigned
//   - 用 Resolution.UserID 建立/刷新 directory_user_links（external_object_id 稳定 ID）
//   - 对比已绑定集合，禁用本次未出现的账号（保留审计历史）
//
// 返回的 counts 用于 SyncRun 写回。连接级错误（DB 不可用）返 error 终止 run；
// 单条无效身份或绑定冲突计 conflict 不终止；未分类错误终止 run。
func activatePreviewEntries(ctx context.Context, deps *Dependencies, tenantID string, preview *repository.DirectorySyncPreview, draft *repository.DirectorySource, run *repository.DirectorySyncRun) (interimActivation, error) {
	entries, err := deps.DirectorySyncPreviewRepo.ListPreviewEntries(ctx, tenantID, preview.ID)
	if err != nil {
		return interimActivation{}, err
	}
	boundBefore, err := deps.DirectorySyncPreviewRepo.ListBoundDirectoryUserIDs(ctx, tenantID, preview.DirectorySourceID)
	if err != nil {
		return interimActivation{}, err
	}
	seenExternalIDs := make([]string, 0, len(entries))
	counts := repository.PreviewCounts{Scanned: len(entries)}
	sourceType := directorySourceType(draft.Kind)
	for _, entry := range entries {
		identity := identitybinding.ExternalIdentity{
			TenantID:        tenantID,
			SourceType:      sourceType,
			SourceID:        preview.DirectorySourceID,
			Issuer:          preview.DirectorySourceID,
			ExternalSubject: entry.ExternalSubject,
			Username:        entry.Username,
			Email:           "",
			Departments:     departmentMatchValues(entry, "department"),
			OUs:             departmentMatchValues(entry, "ou"),
			MemberOf:        departmentMatchValues(entry, "member_of"),
			Groups:          departmentMatchValues(entry, "groups"),
		}
		seenExternalIDs = append(seenExternalIDs, entry.ExternalSubject)
		resolution, err := deps.IdentityBindingService.BindAndResolve(ctx, identity)
		if err != nil {
			if errors.Is(err, identitybinding.ErrInvalidIdentity) ||
				errors.Is(err, identitybinding.ErrConflict) {
				counts.Conflict++
				continue
			}
			return interimActivation{
				counts: counts, seenExternalIDs: seenExternalIDs, boundBefore: boundBefore,
			}, err
		}
		_, wasBound := boundBefore[entry.ExternalSubject]
		switch {
		case resolution.Mode == identitybinding.ModeConflict:
			counts.Conflict++
			counts.Unassigned++
		case resolution.Mode == identitybinding.ModeUnassigned:
			counts.Unassigned++
		}
		if resolution.Changed && !wasBound {
			counts.Created++
		} else {
			counts.Updated++
		}
		if resolution.UserID != "" {
			if err := deps.DirectorySourceRepo.BindDirectoryUser(ctx, repository.DirectoryUserLink{
				TenantID: tenantID, DirectorySourceID: preview.DirectorySourceID,
				ExternalObjectID: entry.ExternalSubject, UserID: resolution.UserID,
			}); err != nil {
				return interimActivation{}, err
			}
		}
	}
	// 禁用 + snapshot + finalize 推迟到 finalizeActivationTx 统一在事务里做（I-1）
	return interimActivation{counts: counts, seenExternalIDs: seenExternalIDs, boundBefore: boundBefore}, nil
}

// directorySourceType 按 directory_sources.kind 返回对应的 stable identity source_type。
// 迁移 137 的 user_identity_links.source_type CHECK 允许 ('local','oidc','ldap','ad')；
// DirectoryKindLDAP/DirectoryKindActiveDirectory 的字符串值正好是 'ldap'/'ad'。
func directorySourceType(kind repository.DirectoryKind) string {
	switch kind {
	case repository.DirectoryKindActiveDirectory:
		return "ad"
	case repository.DirectoryKindLDAP:
		return "ldap"
	default:
		return "ldap"
	}
}

// departmentMatchValues 当 entry 的 match_type 与请求的 type 一致且 value 非空时，
// 返回拆分后的值列表；否则返回 nil。value 支持逗号分隔的多值（例如账号归属
// 多个外部组 "cn=g1,cn=g2"），拆分后逐个参与部门匹配。预览阶段若目录 LDAP
// 没拉组，这里返回 nil，BindAndResolve 会落到未分配部门（不会误触发冲突）。
func departmentMatchValues(entry repository.DirectorySyncPreviewEntry, matchType string) []string {
	if entry.DepartmentMatchType != matchType || strings.TrimSpace(entry.DepartmentMatchValue) == "" {
		return nil
	}
	raw := strings.TrimSpace(entry.DepartmentMatchValue)
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func containsString(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

func writeActivationResponse(writer http.ResponseWriter, runID, previewID string, counts repository.PreviewCounts) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{"data": directoryActivationResponse{
		RunID: runID, PreviewID: previewID,
		Scanned: counts.Scanned, Created: counts.Created, Updated: counts.Updated,
		Disabled: counts.Disabled, Conflict: counts.Conflict, Unassigned: counts.Unassigned,
		Restored: counts.Restored,
	}})
}

// ListDirectorySyncRuns GET /admin/v1/directory/sync-runs
func ListDirectorySyncRuns(deps *Dependencies) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		user := auth.GetUser(request.Context())
		if user == nil {
			writeUnauthorized(writer, "no user")
			return
		}
		if deps.DirectorySyncPreviewRepo == nil {
			writeError(writer, "service_unavailable", "目录同步服务未配置")
			return
		}
		runs, err := deps.DirectorySyncPreviewRepo.ListSyncRuns(request.Context(), user.TenantID, 50)
		if err != nil {
			writeError(writer, "internal_error", "读取同步历史失败")
			return
		}
		out := make([]map[string]any, 0, len(runs))
		for _, run := range runs {
			out = append(out, directorySyncRunDTO(run))
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": out})
	}
}

// GetDirectorySyncRun GET /admin/v1/directory/sync-runs/{id}
func GetDirectorySyncRun(deps *Dependencies) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		user := auth.GetUser(request.Context())
		if user == nil {
			writeUnauthorized(writer, "no user")
			return
		}
		if deps.DirectorySyncPreviewRepo == nil {
			writeError(writer, "service_unavailable", "目录同步服务未配置")
			return
		}
		runID := strings.TrimSpace(chi.URLParam(request, "id"))
		if runID == "" {
			writeError(writer, "invalid_request", "缺少运行 ID")
			return
		}
		run, err := deps.DirectorySyncPreviewRepo.GetSyncRun(request.Context(), user.TenantID, runID)
		if err != nil {
			writeError(writer, "internal_error", "读取同步运行失败")
			return
		}
		if run == nil {
			writeErrorWithStatus(writer, http.StatusNotFound, "not_found", "同步运行不存在")
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": directorySyncRunDTO(*run)})
	}
}

func directorySyncRunDTO(run repository.DirectorySyncRun) map[string]any {
	dto := map[string]any{
		"id": run.ID, "source_id": run.DirectorySourceID,
		"source_version": run.SourceVersion, "kind": run.RunKind, "status": run.Status,
		"started_at": run.StartedAt.Format(time.RFC3339),
		"scanned":    run.ScannedCount, "created": run.CreatedCount, "updated": run.UpdatedCount,
		"restored": run.RestoredCount, "disabled": run.DisabledCount, "conflict": run.ConflictCount,
		"skipped": run.SkippedCount, "actor_user_id": run.ActorUserID,
	}
	if run.FinishedAt != nil {
		dto["finished_at"] = run.FinishedAt.Format(time.RFC3339)
	}
	if run.ErrorCode != "" {
		dto["error_code"] = run.ErrorCode
	}
	return dto
}

// interimActivation 承载逐条 BindAndResolve 的中间结果，供 finalizeActivationTx
// 在汇总事务里统一处理禁用/快照/定稿。
type interimActivation struct {
	counts          repository.PreviewCounts
	seenExternalIDs []string
	boundBefore     map[string]string
}

// clearPreviewActivationTx 把 preview 的 activated_run_id 清空（回到 succeeded 可重试）。
// 仅在 finalizeActivationTx 失败时做补偿清理；status 未推进到 activated 所以不需要回退 status。
func clearPreviewActivationTx(ctx context.Context, deps *Dependencies, tx pgx.Tx, tenantID, previewID string) error {
	_, err := tx.Exec(ctx, `
		UPDATE directory_sync_previews
		SET activated_run_id = NULL, updated_at = now()
		WHERE tenant_id=$1 AND id=$2 AND status='succeeded'`, tenantID, previewID)
	if err != nil {
		return fmt.Errorf("clear preview activation: %w", err)
	}
	return nil
}

// claimAndCreateRun 在单事务里建 running run + CAS 抢占 preview.activated_run_id（I-2）。
// 返回 (winningRunID, claimed, error)：claimed=true 表示本请求赢得抢占。
func claimAndCreateRun(ctx context.Context, deps *Dependencies, tenantID, previewID string, run *repository.DirectorySyncRun) (string, bool, error) {
	var winningRunID string
	var claimed bool
	err := deps.DirectorySyncPreviewRepo.RunInTx(ctx, func(tx pgx.Tx) error {
		if err := deps.DirectorySyncPreviewRepo.CreateSyncRunTx(ctx, tx, run); err != nil {
			return err
		}
		winner, did, claimErr := deps.DirectorySyncPreviewRepo.ClaimPreviewForActivation(ctx, tx, tenantID, previewID, run.ID)
		if claimErr != nil {
			return claimErr
		}
		winningRunID = winner
		claimed = did
		return nil
	})
	return winningRunID, claimed, err
}

// finalizeActivationTx 在单事务里原子完成汇总写（I-1）：
// 禁用已消失账号 → 刷新已见集合 last_seen → FinalizeSyncRun(succeeded) → MarkPreviewActivated。
// 任一步失败整体回滚，避免 users.status=disabled 但 sync_run 仍 running 的半状态。
// 返回值额外带出本次被停用的 user_id，供调用方在提交后吊销会话（W2.5）；
// key 吊销由 users.status 触发器（迁移 870）在同一事务内完成。
func finalizeActivationTx(ctx context.Context, deps *Dependencies, tenantID, previewID string, run *repository.DirectorySyncRun, interim interimActivation) (repository.PreviewCounts, []string, error) {
	counts := interim.counts
	var disabledUserIDs []string
	err := deps.DirectorySyncPreviewRepo.RunInTx(ctx, func(tx pgx.Tx) error {
		disabledUserIDs = nil
		var restoredUserIDs []string
		for extID, userID := range interim.boundBefore {
			if !containsString(interim.seenExternalIDs, extID) {
				disabledUserIDs = append(disabledUserIDs, userID)
			} else {
				restoredUserIDs = append(restoredUserIDs, userID)
			}
		}
		restored, err := deps.DirectorySyncPreviewRepo.MarkDirectoryUserRestoredTx(ctx, tx, tenantID, restoredUserIDs)
		if err != nil {
			return err
		}
		counts.Restored = restored
		n, err := deps.DirectorySyncPreviewRepo.MarkDirectoryUserDisabledTx(ctx, tx, tenantID, disabledUserIDs)
		if err != nil {
			return err
		}
		counts.Disabled = n
		if err := deps.DirectorySyncPreviewRepo.SnapshotDirectoryUserLinksTx(ctx, tx, tenantID, run.DirectorySourceID, run.ID, interim.seenExternalIDs); err != nil {
			return err
		}
		if err := deps.DirectorySyncPreviewRepo.FinalizeSyncRunTx(ctx, tx, tenantID, run.ID, "succeeded", counts, ""); err != nil {
			return err
		}
		if _, err := deps.DirectorySyncPreviewRepo.MarkPreviewActivatedTx(ctx, tx, tenantID, previewID, run.ID); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return counts, nil, err
	}
	return counts, disabledUserIDs, nil
}

// revokeDirectoryDisabledSessions deletes console sessions of users that a
// full directory sync deactivated (W2.5). It runs only after the deactivation
// committed. Portal JWT sessions are invalidated separately: the portal
// re-checks the control-plane authorization context on every BFF request and
// on session refresh. Returns the user ids whose session revocation failed.
func revokeDirectoryDisabledSessions(ctx context.Context, deps *Dependencies, userIDs []string) []string {
	if deps == nil || deps.SessionRepo == nil {
		return nil
	}
	var failed []string
	for _, userID := range userIDs {
		if err := deps.SessionRepo.DeleteByUser(ctx, userID); err != nil {
			failed = append(failed, userID)
		}
	}
	return failed
}

// IncrementalDirectorySync 基于游标按稳定 ID 增量同步目录账号。
//
// 与全量激活的区别：
//   - 当前 cursor 仅审计追溯（PreviousRunID），增量对比基于全量已绑定集合；
//     未来若 LDAP 支持 dirSync/modifyTimestamp 可改为真增量（只拉变化的账号）。

//   - run_kind='changed'（迁移 135 CHECK 允许 'preview'/'full'/'changed'）
//   - 只处理新增/变化的账号（按 external_object_id 稳定 ID 对比已绑定集合）
//   - 不禁用已消失的账号（禁用是全量激活的责任；增量只增量）
//   - cursor 推进到本次 run_id，作为下一次增量的起点
//
// cursor 语义：上一次成功 sync_run 的 ID（无论 full 还是 changed）。空 cursor
// 表示从当前已绑定集合开始增量（首次增量场景）。
//
// 返回的 IncrementalResult 含新 run_id（即新 cursor）。连接级错误返 error。
func IncrementalDirectorySync(ctx context.Context, deps *Dependencies, tenantID, sourceID, actorID, cursor string) (IncrementalResult, error) {
	if deps == nil || deps.DirectorySourceRepo == nil || deps.DirectorySyncPreviewRepo == nil || deps.DirectoryTester == nil || deps.IdentityBindingService == nil {
		return IncrementalResult{}, errors.New("incremental sync dependencies not configured")
	}
	draft, err := deps.DirectorySourceRepo.GetDraft(ctx, tenantID)
	if err != nil {
		return IncrementalResult{}, err
	}
	if draft == nil || draft.ID != sourceID || (draft.Status != "tested" && draft.Status != "active") {
		return IncrementalResult{}, errors.New("directory source not ready for incremental sync")
	}
	if err := validateDirectoryDraftSyncPreflight(ctx, DirectoryTargetPolicyFor(ctx, deps), draft); err != nil {
		return IncrementalResult{}, err
	}

	password, err := secrets.DecryptProviderSecret(draft.BindPasswordEnc)
	if err != nil {
		return IncrementalResult{}, err
	}
	entries, err := deps.DirectoryTester.ListUsers(ctx, directoryldap.SyncRequest{
		TestRequest: directoryldap.TestRequest{ConnectionURL: draft.ConnectionURL, BindDN: draft.BindDN, BindPassword: password, CACertPEM: draft.CACertPEM},
		UsersDN:     draft.UsersDN, UserFilter: draft.UserFilter, StableIDAttribute: draft.StableIDAttribute,
		UsernameAttribute: draft.UsernameAttribute, EmailAttribute: draft.EmailAttribute, NameAttribute: draft.NameAttribute,
	})
	if err != nil {
		return IncrementalResult{}, err
	}
	// 建 changed run
	run := &repository.DirectorySyncRun{
		TenantID: tenantID, DirectorySourceID: sourceID,
		SourceVersion: draft.Version, RunKind: directoryRunKindChanged, ActorUserID: actorID,
	}
	if err := deps.DirectorySyncPreviewRepo.CreateSyncRun(ctx, run); err != nil {
		return IncrementalResult{}, err
	}
	result := IncrementalResult{RunID: run.ID, PreviousRunID: cursor}
	// 预先取已绑定集合（用于判定 create vs update）
	boundBefore, err := deps.DirectorySyncPreviewRepo.ListBoundDirectoryUserIDs(ctx, tenantID, sourceID)
	if err != nil {
		_ = deps.DirectorySyncPreviewRepo.FinalizeSyncRun(ctx, tenantID, run.ID, "failed", repository.PreviewCounts{Scanned: len(entries)}, "incremental_bind_lookup_failed")
		return result, err
	}
	counts := repository.PreviewCounts{Scanned: len(entries)}
	sourceType := directorySourceType(draft.Kind)
	seenExternalIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		identity := identitybinding.ExternalIdentity{
			TenantID:        tenantID,
			SourceType:      sourceType,
			SourceID:        sourceID,
			Issuer:          sourceID,
			ExternalSubject: entry.ObjectID,
			Username:        entry.Username,
			Email:           "",
		}
		resolution, err := deps.IdentityBindingService.BindAndResolve(ctx, identity)
		if err != nil {
			counts.Conflict++
			continue
		}
		_, wasBound := boundBefore[entry.ObjectID]
		switch {
		case resolution.Mode == identitybinding.ModeConflict:
			counts.Conflict++
			counts.Unassigned++
		case resolution.Mode == identitybinding.ModeUnassigned:
			counts.Unassigned++
		}
		if resolution.Changed && !wasBound {
			counts.Created++
		} else if resolution.Changed {
			counts.Updated++
		} else {
			counts.Skipped++
		}
		if resolution.UserID != "" {
			if err := deps.DirectorySourceRepo.BindDirectoryUser(ctx, repository.DirectoryUserLink{
				TenantID: tenantID, DirectorySourceID: sourceID,
				ExternalObjectID: entry.ObjectID, UserID: resolution.UserID,
			}); err != nil {
				_ = deps.DirectorySyncPreviewRepo.FinalizeSyncRun(ctx, tenantID, run.ID, "failed", counts, "incremental_bind_failed")
				return result, err
			}
		}
		seenExternalIDs = append(seenExternalIDs, entry.ObjectID)
	}
	// 刷新已见集合的 last_seen_run_id（推进 cursor）
	if err := deps.DirectorySyncPreviewRepo.SnapshotDirectoryUserLinks(ctx, tenantID, sourceID, run.ID, seenExternalIDs); err != nil {
		_ = deps.DirectorySyncPreviewRepo.FinalizeSyncRun(ctx, tenantID, run.ID, "failed", counts, "incremental_snapshot_failed")
		return result, err
	}
	if err := deps.DirectorySyncPreviewRepo.FinalizeSyncRun(ctx, tenantID, run.ID, "succeeded", counts, ""); err != nil {
		return result, err
	}
	result.Counts = counts
	return result, nil
}

// IncrementalResult 承载增量同步结果。
type IncrementalResult struct {
	RunID         string
	PreviousRunID string
	Counts        repository.PreviewCounts
}

// directoryRunKindChanged 标记增量同步运行类型（迁移 135 CHECK 允许）。
const directoryRunKindChanged = "changed"
