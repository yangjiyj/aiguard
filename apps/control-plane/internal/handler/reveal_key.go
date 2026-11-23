package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// revealKeyResponse 后台"复制完整密钥"响应。
// full_key 为 null 且带 reason 表示无法复原（改造前的老 key，原文已丢）。
type revealKeyResponse struct {
	FullKey *string `json:"full_key"`
	Reason  string  `json:"reason,omitempty"`
}

// RevealKey 后台受保护端点：解密返回某内部 key 的完整明文，供管理员一键复制。
//
// 铁律：
//   - 必须挂在 session 受保护组（auth.Middleware + RBAC api_keys:read），绝非 portal 机器通道；
//   - 每次真正揭示都写 audit_operations（action_type=reveal_key，target=key_id）——安全审计要求
//     可追"谁在何时看了哪把完整密钥"；
//   - 租户隔离由 KeyRepo.GetByID(tenantID, id) 保证，防越权查看他人密钥。
//
// 完整密钥现以 AES-GCM 密文（enc:v1:）随 key_ciphertext 落库；改造前的老 key 无密文，
// 如实返 {full_key:null, reason:created_before_encryption} 提示重置，而非误导复制前缀。
func RevealKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		keyID := chi.URLParam(r, "id")

		key, err := deps.KeyRepo.GetByID(r.Context(), user.TenantID, keyID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load key")
			return
		}
		if key == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "key not found")
			return
		}

		// 改造前老 key 无密文，原文已丢不可复原：如实告知，引导重置而非误导。
		if key.KeyCiphertext == "" {
			writeJSON(w, revealKeyResponse{FullKey: nil, Reason: "created_before_encryption"})
			return
		}

		fullKey, err := secrets.DecryptProviderSecret(key.KeyCiphertext)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to decrypt key（检查 JJD_PROVIDER_SECRET_KEY/JJD_MASTER_KEY）")
			return
		}

		// 审计：完整密钥被揭示，记录谁在何时看了哪把 key。
		logAudit(r, deps, "reveal_key", map[string]interface{}{"key_id": keyID}, "key", keyID)

		writeJSON(w, revealKeyResponse{FullKey: &fullKey})
	}
}
