package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"net/http"
)

func OperationAuditContext(ctx context.Context, deps *Dependencies, ip string) context.Context {
	return repository.WithOperationAudit(ctx, ip, func(event repository.CommittedOperationAudit) {
		detail := map[string]any{}
		for k, v := range event.ActionDetail {
			detail[k] = v
		}
		detail["action_type"] = event.ActionType
		detail["actor_user_id"] = event.UserID
		detail["ip_address"] = event.IPAddress
		appendAuditChain(context.WithoutCancel(ctx), deps, event.TenantID, event.ActionType, event.ID, detail)
	})
}
func withOperationAudit(r *http.Request, deps *Dependencies) *http.Request {
	return r.WithContext(OperationAuditContext(r.Context(), deps, requestClientIP(r)))
}
