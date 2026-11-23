package handler

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// RevealPortalCustomerKey 只向 Portal 机器通道返回当前员工自己的完整 Key。
// 浏览器不能指定租户，BFF 也必须用已签名会话解析出的 user_id；跨用户查询统一返回 404。
func RevealPortalCustomerKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = withOperationAudit(r, deps)
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
		if userID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "user_required", "user_id is required")
			return
		}
		if deps == nil || deps.KeyRepo == nil {
			portalNotConfigured(w, "key repository")
			return
		}

		keyID := strings.TrimSpace(chi.URLParam(r, "id"))
		key, err := deps.KeyRepo.GetByID(r.Context(), tenantID, keyID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load key")
			return
		}
		if key == nil || key.UserID != userID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "key not found")
			return
		}
		// 个人 Key 与自建 Key 一样，本人可随时复制完整内容；仍只限本人、需在线，并写审计。
		if !portalSensitiveAction(w, r, deps, tenantID, userID, "reveal") {
			return
		}
		if key.Status != "active" {
			writeErrorWithStatus(w, http.StatusConflict, "key_not_active", "key is not active")
			return
		}

		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Pragma", "no-cache")
		if key.KeyCiphertext == "" {
			writeJSON(w, map[string]any{"full_key": nil, "reason": "created_before_encryption"})
			return
		}
		fullKey, err := secrets.DecryptProviderSecret(key.KeyCiphertext)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to decrypt key")
			return
		}

		recorded, auditErr := deps.KeyRepo.AuditOwnedKeyReveal(r.Context(), tenantID, key.ID, userID, key.KeyCiphertext, requestClientIP(r))
		if auditErr != nil {
			writeErrorWithStatus(w, 503, "key_audit_unavailable", "credential audit unavailable")
			return
		}
		if !recorded {
			writeErrorWithStatus(w, 404, "not_found", "key not found")
			return
		}
		writeJSON(w, map[string]any{"full_key": fullKey})
	}
}
