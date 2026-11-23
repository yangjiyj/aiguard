package handler

import (
	"strings"
	"testing"
)

// D4：容器 env SECURITY_AUDIT_ONLY=false 而数据库设置为 record 时，运维看 env 会以为是 protect。
// 网关必须在启动与模式变化时打一行明确的「生效执行模式」日志，并能经 /health 暴露。

func TestD4_EffectiveModeReportNamesSourceAndEnvFallback(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	c := NewToolRiskClient("http://127.0.0.1:1", "x")
	c.runtimeCache.setSemanticConfig(semanticRuntimeConfig{Revision: gatewaySemanticRevision, SecurityAuditOnly: true, SecurityExecutionModeManaged: true})
	r := c.EffectiveExecutionModeReport()
	if r.Mode != "record" || r.Source != "signed" || r.EnvFallback != false {
		t.Fatalf("report=%+v", r)
	}
	if got := r.Message(); got != "生效执行模式=record（来源：数据库设置；env 兜底值=false）" {
		t.Fatalf("日志文案不符合约定: %q", got)
	}
}

func TestD4_EnvLockIsReportedAsDeployment(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	c := NewToolRiskClient("http://127.0.0.1:1", "x")
	r := c.EffectiveExecutionModeReport()
	if r.Mode != "record" || r.Source != "deployment" || !strings.Contains(r.Message(), "来源：部署环境变量") {
		t.Fatalf("report=%+v msg=%q", r, r.Message())
	}
}

func TestD4_ProtectModeAndStartupSourceWording(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	c := NewToolRiskClient("http://127.0.0.1:1", "x")
	c.runtimeCache.setSemanticConfig(semanticRuntimeConfig{Revision: gatewaySemanticRevision, SecurityAuditOnly: false, SecurityExecutionModeManaged: true})
	if r := c.EffectiveExecutionModeReport(); r.Mode != "protect" {
		t.Fatalf("report=%+v", r)
	}
	fresh := NewToolRiskClient("http://127.0.0.1:1", "x")
	if r := fresh.EffectiveExecutionModeReport(); r.Source != "startup" || !strings.Contains(r.Message(), "尚未取得数据库设置") {
		t.Fatalf("启动期应说明尚未取得数据库设置: %+v %q", r, r.Message())
	}
}

func TestD4_LogsOnFirstObservationAndOnChangeOnly(t *testing.T) {
	buf := captureLog(t)
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	c := NewToolRiskClient("http://127.0.0.1:1", "x")
	c.runtimeCache.setSemanticConfig(semanticRuntimeConfig{Revision: gatewaySemanticRevision, SecurityAuditOnly: true, SecurityExecutionModeManaged: true})

	c.logEffectiveExecutionModeIfChanged()
	c.logEffectiveExecutionModeIfChanged() // 无变化：不重复
	if n := strings.Count(buf.String(), "生效执行模式=record（来源：数据库设置；env 兜底值=false）"); n != 1 {
		t.Fatalf("首次观测应恰好打一行，实际 %d: %s", n, buf.String())
	}
	c.runtimeCache.setSemanticConfig(semanticRuntimeConfig{Revision: gatewaySemanticRevision, SecurityAuditOnly: false, SecurityExecutionModeManaged: true})
	c.logEffectiveExecutionModeIfChanged()
	out := buf.String()
	if !strings.Contains(out, "生效执行模式=protect") || !strings.Contains(out, "执行模式已变更：record → protect") {
		t.Fatalf("模式变化应有变更日志: %s", out)
	}
}

func TestD4_RuntimeStatusExposesModeAndRedlineStatus(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	c := NewToolRiskClient("http://127.0.0.1:1", "x")
	c.runtimeCache.setSemanticConfig(semanticRuntimeConfig{Revision: gatewaySemanticRevision, SecurityAuditOnly: true, SecurityExecutionModeManaged: true})
	h := NewMCPProxyHandler(nil, c, false)
	payload := GatewayRuntimeStatus(c, h)
	if payload["execution_mode"] != "record" || payload["execution_mode_source"] != "signed" || payload["env_security_audit_only"] != false {
		t.Fatalf("payload=%v", payload)
	}
	red, ok := payload["mcp_redline"].(map[string]any)
	if !ok || red["fetch_failures"] != int64(0) {
		t.Fatalf("应暴露红线配置拉取状态: %v", payload["mcp_redline"])
	}
}
