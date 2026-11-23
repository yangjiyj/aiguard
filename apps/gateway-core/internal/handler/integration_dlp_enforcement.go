package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
)

// 有效拦截档先完成整包输出检查，客户端流式格式仍由既有缓冲路径生成。
func integrationDLPNeedsBufferedOutput(ctx context.Context) bool {
	return ctx != nil && auth.EffectiveDLPEnforcement(ctx) == "block"
}
