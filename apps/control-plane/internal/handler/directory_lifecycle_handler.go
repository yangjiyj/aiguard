package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const directoryRestoreTimeout = 5 * time.Second

type DirectoryLifecycleRuntime interface {
	DirectoryRuntime
	Disable(context.Context) (directoryruntime.RuntimeSnapshot, error)
	Restore(context.Context, directoryruntime.RuntimeSnapshot) error
}

func restoreDirectoryRuntime(ctx context.Context, runtime DirectoryLifecycleRuntime, snapshot directoryruntime.RuntimeSnapshot) error {
	restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), directoryRestoreTimeout)
	defer cancel()
	return runtime.Restore(restoreCtx, snapshot)
}

func directoryLifecycleRuntime(deps *Dependencies) (DirectoryLifecycleRuntime, bool) {
	if deps == nil || deps.DirectoryRuntime == nil {
		return nil, false
	}
	runtime, ok := deps.DirectoryRuntime.(DirectoryLifecycleRuntime)
	return runtime, ok
}

func decodeDirectoryConfirmation(w http.ResponseWriter, r *http.Request) bool {
	var request disableReq
	// 空 body 会让 Decode 直接返回 io.EOF。语义上「没有 body」等于
	// 「没有确认」，报 confirmation_required 才指向真实原因；报
	// invalid_request 会把排查引到请求格式上（现场就是这么被误导的）。
	// 只放宽 io.EOF：io.ErrUnexpectedEOF（截断的 JSON）仍是格式错误。
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "请求格式错误")
		return false
	}
	if !request.Confirm {
		writeErrorWithStatus(w, http.StatusBadRequest, "confirmation_required", "请确认操作")
		return false
	}
	return true
}

type activateDirectoryRequest struct {
	PreviewID string `json:"preview_id"`
	Confirm   bool   `json:"confirm"`
}

func decodeDirectoryActivation(w http.ResponseWriter, r *http.Request) (activateDirectoryRequest, bool) {
	var request activateDirectoryRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "\u8bf7\u6c42\u683c\u5f0f\u9519\u8bef")
		return activateDirectoryRequest{}, false
	}
	request.PreviewID = strings.TrimSpace(request.PreviewID)
	if request.PreviewID == "" {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "\u7f3a\u5c11\u9884\u89c8 ID")
		return activateDirectoryRequest{}, false
	}
	if !request.Confirm {
		writeErrorWithStatus(w, http.StatusBadRequest, "confirmation_required", "\u8bf7\u786e\u8ba4\u64cd\u4f5c")
		return activateDirectoryRequest{}, false
	}
	return request, true
}

func writeDirectoryLifecycleError(w http.ResponseWriter, code, message string) {
	writeErrorWithStatus(w, http.StatusServiceUnavailable, code, message)
}

func ActivateDirectorySource(deps *Dependencies) http.HandlerFunc {
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
		activation, ok := decodeDirectoryActivation(w, r)
		if !ok {
			return
		}
		activateDirectoryPreviewByID(deps, w, r, user, activation.PreviewID)
	}
}

func DisableDirectorySource(deps *Dependencies) http.HandlerFunc {
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
		if !decodeDirectoryConfirmation(w, r) {
			return
		}
		if deps == nil || deps.DirectorySourceRepo == nil {
			writeDirectoryLifecycleError(w, "directory_runtime_unavailable", "目录身份服务暂不可用")
			return
		}
		runtime, ok := directoryLifecycleRuntime(deps)
		if !ok {
			writeDirectoryLifecycleError(w, "directory_runtime_unavailable", "目录身份服务暂不可用")
			return
		}
		claim, err := deps.DirectorySourceRepo.ClaimActivation(r.Context(), user.TenantID)
		if err != nil {
			if errors.Is(err, repository.ErrDirectorySourceActivating) {
				writeErrorWithStatus(w, http.StatusConflict, "directory_activation_in_progress", "目录源正在激活")
				return
			}
			writeError(w, "internal_error", "获取目录激活锁失败")
			return
		}
		defer func() {
			releaseCtx, cancel := context.WithTimeout(
				context.WithoutCancel(r.Context()),
				directoryRestoreTimeout,
			)
			defer cancel()
			_ = claim.Release(releaseCtx)
		}()
		source, err := deps.DirectorySourceRepo.GetActive(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", "获取目录配置失败")
			return
		}
		if source == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "没有已启用的目录源")
			return
		}
		snapshot, err := runtime.Disable(r.Context())
		if err != nil {
			writeDirectoryLifecycleError(w, "directory_disable_failed", "目录源停用失败")
			return
		}
		if err := deps.DirectorySourceRepo.Disable(r.Context(), user.TenantID, source.ID, source.Version); err != nil {
			if restoreErr := restoreDirectoryRuntime(r.Context(), runtime, snapshot); restoreErr != nil {
				writeError(w, "directory_rollback_failed", "目录配置恢复失败")
				return
			}
			writeErrorWithStatus(w, http.StatusConflict, "directory_source_changed", "目录配置已变化，运行配置已恢复")
			return
		}
		logAudit(r, deps, "directory.source.disabled", map[string]any{
			"display_name": source.DisplayName, "source_version": source.Version,
		}, "directory_source", source.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "目录源已停用"})
	}
}
