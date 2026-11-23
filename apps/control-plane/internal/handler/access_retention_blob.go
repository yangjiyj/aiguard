package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// GetAccessRetentionBlob 按 object_key 从留存后端流式回放已存字节(图片/文件)。
// 治 P4:此前前端只能经 image-proxy 取已过期外链→破图;现优先读盘上已留存的 blob。
// 安全:仅当 key 确属该 request 的留证元数据时放行,防越权读任意租户 blob(GetObject 自身也按 tenant 隔离)。
// 内容寻址:ETag=sha256 + immutable 强缓存(留存期内字节不变),支持 If-None-Match→304。
// GetAccessRetentionBlob is a compatibility alias. It accepts artifact_id only;
// object keys are no longer customer-facing.

// GetAccessRetentionBlob 返回带证据读取审计的 handler（Low-2）：读取成功后写 evidence.read，见 AuditEvidenceRead。
func GetAccessRetentionBlob(deps *Dependencies) http.HandlerFunc {
	return auditedEvidenceHandler(deps, "blob", getAccessRetentionBlobInner(deps))
}

// getAccessRetentionBlobInner 复用附件下载的内部实现（不再套一层审计）：blob 是 artifact original 的兼容别名，
// 外层 GetAccessRetentionBlob 已按 blob 记一次读取，内层再记会让一次读取留下两条审计。
func getAccessRetentionBlobInner(deps *Dependencies) http.HandlerFunc {
	return getAccessRetentionArtifactInner(false, deps)
}

func getAccessRetentionBlobLegacy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		requestID := strings.TrimSpace(chi.URLParam(r, "request_id"))
		key := strings.TrimSpace(r.URL.Query().Get("key"))
		if requestID == "" || key == "" {
			writeError(w, "invalid_request", "request id and object key are required")
			return
		}
		scope, start, end, windowErr := retentionScopeAndWindow(r)
		if windowErr != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid UTC retention window")
			return
		}
		if deps.RetentionStore == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "unavailable", "retention blob store is not configured")
			return
		}
		repo := deps.AccessContentRepo
		if repo == nil && deps.RequestLogRepo != nil {
			repo = deps.RequestLogRepo
		}
		if repo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "access content repository is not configured")
			return
		}
		item, err := getAccessContentLog(r.Context(), repo, user.TenantID, requestID, scope, start, end)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get access content")
			return
		}
		// SP4 turn 合并：合并展示时 blob 可能属于 turn 内其它成员。带 members 参数时把鉴权范围
		// 扩到同 turn 全部成员的留证元数据——只要该 object_key 属任一成员即放行，与 /content 合并
		// 口径一致；不带 members 仍只按单条 request_id 鉴权（行为不变）。
		if members := parseTurnMemberIDs(r.URL.Query().Get("members"), requestID); len(members) > 1 {
			logs, merr := getAccessContentLogs(r.Context(), repo, user.TenantID, members, scope, start, end)
			if merr != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get turn member content")
				return
			}
			if merged := mergeTurnAccessContentLogs(requestID, members, logs); merged != nil {
				item = merged
			}
		}
		if item == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "access content not found")
			return
		}
		if !accessRetentionContentContainsObjectKey(item, key) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "object key is not retained for this request")
			return
		}
		obj, err := deps.RetentionStore.GetObject(r.Context(), user.TenantID, key)
		if err != nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "retained object not found")
			return
		}
		defer obj.Body.Close()

		contentType := strings.TrimSpace(obj.Metadata.ContentType)
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		if sum := strings.TrimSpace(obj.Metadata.SHA256); sum != "" {
			etag := "\"" + sum + "\""
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "private, max-age=604800, immutable")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = io.Copy(w, io.LimitReader(obj.Body, 64<<20))
	}
}

// accessRetentionContentContainsObjectKey 校验 object_key 是否属于该 request 的留证元数据,
// 防止凭任意 key 越权读 blob。
func accessRetentionContentContainsObjectKey(item *repository.AccessContentLog, key string) bool {
	if item == nil || len(item.FileMetadataJSON) == 0 || key == "" {
		return false
	}
	var meta []map[string]interface{}
	if err := json.Unmarshal(item.FileMetadataJSON, &meta); err != nil {
		return false
	}
	for _, entry := range meta {
		if v, _ := entry["object_key"].(string); strings.TrimSpace(v) == key {
			return true
		}
	}
	return false
}
