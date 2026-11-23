package handler

import (
	"errors"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
)

// writeLocalIdentityError 把 Keycloak 客户端错误映射到稳定的 HTTP 状态码与
// error.code，让客户端能区分不同失败语义，而非全部坍缩成 502 sync_failed。
//
// 映射表：
//   - ErrConflict      -> 409 username_conflict（用户名冲突）
//   - ErrUnauthorized  -> 502 local_identity_unauthorized（KC 凭据/权限问题）
//   - ErrUnavailable   -> 502 local_identity_unavailable（KC 不可达/超时）
//   - ErrNotFound      -> 502 local_identity_not_found（subject 不存在）
//   - 其他             -> 502 + fallbackCode（调用方提供的默认 code）
//
// fallbackMessage 仅在非 sentinel 错误时使用；sentinel 错误一律用稳定的中性
// 文案，不泄露原始错误体、subject、DSN 或 secret。
func writeLocalIdentityError(w http.ResponseWriter, err error, fallbackCode, fallbackMessage string) {
	switch {
	case errors.Is(err, localidentity.ErrConflict):
		writeErrorWithStatus(w, http.StatusConflict, "username_conflict", "用户名已被占用")
	case errors.Is(err, localidentity.ErrUnauthorized):
		writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_unauthorized", "本地身份服务未授权")
	case errors.Is(err, localidentity.ErrUnavailable):
		writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_unavailable", "本地身份服务不可达")
	case errors.Is(err, localidentity.ErrNotFound):
		writeErrorWithStatus(w, http.StatusBadGateway, "local_identity_not_found", "本地身份对象不存在")
	default:
		writeErrorWithStatus(w, http.StatusBadGateway, fallbackCode, fallbackMessage)
	}
}
