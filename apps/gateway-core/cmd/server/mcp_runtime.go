package main

import (
	"context"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/handler"
)

type mcpRuntimeGuardTarget interface {
	SetToolResultChecker(handler.MCPToolResultChecker)
	StartServerCacheInvalidator(context.Context)
}

func configureMCPRuntimeGuards(ctx context.Context, target mcpRuntimeGuardTarget, checker handler.MCPToolResultChecker, enabled bool) {
	if enabled {
		target.SetToolResultChecker(checker)
	} else {
		target.SetToolResultChecker(nil)
	}
	target.StartServerCacheInvalidator(ctx)
}
