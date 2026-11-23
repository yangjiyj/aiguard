package main

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/handler"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type mcpRuntimeGuardSpy struct {
	checker handler.MCPToolResultChecker
	ctx     context.Context
}

func (s *mcpRuntimeGuardSpy) SetToolResultChecker(checker handler.MCPToolResultChecker) {
	s.checker = checker
}
func (s *mcpRuntimeGuardSpy) StartServerCacheInvalidator(ctx context.Context) { s.ctx = ctx }

type startupInjectionChecker struct{}

func (*startupInjectionChecker) CheckInput(context.Context, *modelrouter.RequestEnvelope, string, int, string, string) (string, string, []handler.SecurityFinding, error) {
	return "block", "", []handler.SecurityFinding{{Type: "prompt_injection", Action: "block"}}, nil
}

func TestMCPRuntimeStartupWiresCheckerAndCancelableInvalidator(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{{"", true}, {"true", true}, {"false", false}} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("MCP_TOOL_RESULT_GUARD_ENABLED", tc.value)
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			spy := &mcpRuntimeGuardSpy{}
			checker := &startupInjectionChecker{}
			configureMCPRuntimeGuards(ctx, spy, checker, cfg.MCPToolResultGuardEnabled)
			if (spy.checker != nil) != tc.want {
				t.Fatalf("startup checker enabled=%v want=%v", spy.checker != nil, tc.want)
			}
			if spy.ctx != ctx {
				t.Fatal("cache invalidator not bound to process context")
			}
			cancel()
			select {
			case <-spy.ctx.Done():
			default:
				t.Fatal("cache invalidator context survives shutdown")
			}
		})
	}
}
