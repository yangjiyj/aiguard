package main

// 复审 M-1：main.go 里真实注册的 /health 必须只用最小载荷，运行姿态只能经需要内部密钥的 runtime-status 暴露。
// 这是对源码的契约检查（main() 依赖数据库与 Redis，无法直接起路由）。

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestHealthRouteUsesMinimalPayloadAndRuntimeStatusIsSecretGuarded(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	health := regexp.MustCompile(`(?s)r\.Get\("/health",.*?\n\t\}\)\n`).FindString(src)
	if health == "" {
		t.Fatal("找不到 /health 路由")
	}
	if !strings.Contains(health, "handler.GatewayHealthPayload(") {
		t.Fatalf("/health 必须使用最小载荷 GatewayHealthPayload")
	}
	for _, forbidden := range []string{"GatewayRuntimeStatus", "RedlineFetchStatus", "EffectiveExecutionModeReport", "execution_mode", "last_error"} {
		if strings.Contains(health, forbidden) {
			t.Fatalf("未鉴权的 /health 不得包含 %q", forbidden)
		}
	}
	if !strings.Contains(src, `r.Get("/admin/v1/internal/runtime-status", handler.RuntimeStatusHandler(cfg.InternalAPISecret,`) {
		t.Fatal("runtime-status 必须用内部密钥保护并注册在路由表里")
	}
}
