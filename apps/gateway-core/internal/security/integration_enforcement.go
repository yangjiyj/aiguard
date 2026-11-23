package security

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
)

func withCredentialContext(ctx context.Context, request *CheckInputRequest) *CheckInputRequest {
	copy := *request
	values := make(map[string]interface{}, len(request.Context)+4)
	for k, v := range request.Context {
		values[k] = v
	}
	// 这些字段只由鉴权结果决定，客户端内容和重放缓存均不能授予权限。
	delete(values, "key_id")
	delete(values, "effective_dlp_enforcement")
	delete(values, "integration_credential")
	delete(values, "integration_dlp_block_key_ids")
	if key, ok := ctx.Value(auth.KeyIDKey).(string); ok && key != "" {
		values["key_id"] = key
		values["effective_dlp_enforcement"] = auth.EffectiveDLPEnforcement(ctx)
		agent, _ := ctx.Value(auth.AgentInstanceIDKey).(string)
		values["integration_credential"] = agent != ""
		ids, _ := ctx.Value(auth.IntegrationDLPBlockKeysKey).([]string)
		values["integration_dlp_block_key_ids"] = append([]string{}, ids...)
		if tenant, ok := ctx.Value(auth.TenantKey).(string); ok {
			values["tenant_id"] = tenant
		}
	}
	if len(values) > 0 {
		copy.Context = values
	} else {
		copy.Context = nil
	}
	return &copy
}
