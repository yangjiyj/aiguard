package auth

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"

	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
)

type modelAccessContextKey struct{}
type ModelAccessLoader func(context.Context, string, string) (*modelaccess.Access, error)

// UserModelAuthorization refreshes personal grants for every authenticated
// request. There is no quota-mode switch or grant cache that can retain a
// revoked model. Service keys without an owner keep their existing contract.
func UserModelAuthorization(load ModelAccessLoader) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := GetAuthInfo(r)
			if info.UserID == "" {
				next.ServeHTTP(w, r)
				return
			}
			access, err := load(r.Context(), info.TenantID, info.UserID)
			if errors.Is(err, pgx.ErrNoRows) {
				writeModelAccessError(w, http.StatusForbidden, "forbidden_model", "该账号没有模型使用权限")
				return
			}
			if err != nil || access == nil {
				writeModelAccessError(w, http.StatusServiceUnavailable, "model_access_unavailable", "暂时无法核实模型使用权限，请稍后重试")
				return
			}
			if !access.ChatAllowed {
				writeModelAccessError(w, http.StatusForbidden, "forbidden_model", "该账号没有模型使用权限")
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), modelAccessContextKey{}, access))
			next.ServeHTTP(w, r)
		})
	}
}

func writeModelAccessError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func UserModelAllowed(ctx context.Context, name string) bool {
	access, ok := ctx.Value(modelAccessContextKey{}).(*modelaccess.Access)
	return keyModelAdmission(ctx, name, true) && (!ok || access.Allows(name))
}

func UserFinalModelAllowed(ctx context.Context, ref string) bool {
	access, ok := ctx.Value(modelAccessContextKey{}).(*modelaccess.Access)
	name := ref
	if ok && !access.Allows(ref) {
		for _, known := range access.KnownModelNames {
			if known == ref {
				return false
			}
		}
		if mapped, exists := access.ModelReferences[ref]; exists {
			name = mapped
		}
	}
	return keyModelAdmission(ctx, name, true) && (!ok || access.AllowsReference(ref))
}

// UserModelAccessEnforced identifies a request whose model admission was resolved
// by the mandatory user gate. Quota, budget, security and audit still apply.
func UserModelAccessEnforced(ctx context.Context) bool {
	access, ok := ctx.Value(modelAccessContextKey{}).(*modelaccess.Access)
	return ok && access != nil
}

// KeyModelAllowed only consumes the whitelist loaded by database-backed key auth.
func KeyModelAllowed(ctx context.Context, name string) bool {
	names, _ := ctx.Value(KeyModelAllowlistKey).([]string)
	if len(names) == 0 {
		return true
	}
	for _, allowed := range names {
		if name == allowed {
			return true
		}
	}
	return false
}
func ModelDenialCode(ctx context.Context, name string) string {
	if !keyModelAdmission(ctx, name, false) {
		return "key_model_not_allowed"
	}
	return "forbidden_model"
}
