package handler

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
)

// 验收缺陷 D4：容器 env SECURITY_AUDIT_ONLY=false 与数据库设置 security_execution_mode=record 同时存在时，
// 运维只看 env 会误以为网关在 protect。这里把「实际生效的执行模式及其来源」说清楚：
// 启动与模式变化时各打一行日志，并经 /health 暴露。只做可观测，不改变模式本身。

// ExecutionModeReport 描述网关当前实际生效的执行模式。
type ExecutionModeReport struct {
	Mode        string // record | protect
	Source      string // deployment | signed | legacy | startup（沿用 securityExecutionModeSnapshot 的取值）
	EnvFallback bool   // 环境变量 SECURITY_AUDIT_ONLY 的值（仅在数据库设置不可用时才起兜底作用）
}

func executionModeName(auditOnly bool) string {
	if auditOnly {
		return "record"
	}
	return "protect"
}

func executionModeSourceLabel(source string) string {
	switch source {
	case "deployment":
		return "部署环境变量"
	case "signed", "legacy":
		return "数据库设置"
	default:
		return "启动默认值，尚未取得数据库设置"
	}
}

// Message 是写入日志的固定文案。
func (r ExecutionModeReport) Message() string {
	return fmt.Sprintf("生效执行模式=%s（来源：%s；env 兜底值=%t）", r.Mode, executionModeSourceLabel(r.Source), r.EnvFallback)
}

// EffectiveExecutionModeReport 返回当前生效的执行模式、来源与 env 兜底值。
func (c *ToolRiskClient) EffectiveExecutionModeReport() ExecutionModeReport {
	auditOnly, source := c.securityExecutionModeSnapshot()
	return ExecutionModeReport{Mode: executionModeName(auditOnly), Source: source, EnvFallback: securityAuditOnlyForcedByEnvironment()}
}

type executionModeLogState struct {
	mu   sync.Mutex
	seen bool
	last ExecutionModeReport
}

// logEffectiveExecutionModeIfChanged 在首次观测与模式/来源变化时各打一行；无变化不重复。
func (c *ToolRiskClient) logEffectiveExecutionModeIfChanged() {
	if c == nil {
		return
	}
	cur := c.EffectiveExecutionModeReport()
	c.modeLog.mu.Lock()
	defer c.modeLog.mu.Unlock()
	if c.modeLog.seen && c.modeLog.last == cur {
		return
	}
	prev, hadPrev := c.modeLog.last, c.modeLog.seen
	c.modeLog.last, c.modeLog.seen = cur, true
	log.Printf("[INFO] %s", cur.Message())
	if hadPrev && prev.Mode != cur.Mode {
		log.Printf("[INFO] 执行模式已变更：%s → %s（%s）", prev.Mode, cur.Mode, cur.Message())
	}
}

// GatewayHealthPayload 是未鉴权 /health 的响应：只保留最小存活信息（复审 M-1）。
// 不含执行模式、红线拉取状态、任何内部主机名/端口/路径；compose healthcheck 只看 HTTP 状态码。
func GatewayHealthPayload(dbStatus, redisStatus string, status int) map[string]any {
	return map[string]any{
		"status":   map[bool]string{true: "healthy", false: "degraded"}[status == http.StatusOK],
		"service":  "gateway-core",
		"database": dbStatus,
		"redis":    redisStatus,
	}
}

// GatewayRuntimeStatus 组装运行姿态（生效执行模式及来源、env 兜底值、红线拉取失败次数与类别）。
// 仅经需要内部密钥的 /admin/v1/internal/runtime-status 暴露。红线错误原文不在其中，只写日志。
func GatewayRuntimeStatus(c *ToolRiskClient, mcp *MCPProxyHandler) map[string]any {
	report := c.EffectiveExecutionModeReport()
	out := map[string]any{
		"execution_mode":          report.Mode,
		"execution_mode_source":   report.Source,
		"env_security_audit_only": report.EnvFallback,
	}
	if mcp != nil {
		failures, category := mcp.RedlineFetchStatus()
		out["mcp_redline"] = map[string]any{"fetch_failures": failures, "last_error_category": category}
	}
	return out
}

// RuntimeStatusHandler 返回内部运行状态端点。内部密钥未配置时一律拒绝（fail-closed）；比较用常量时间。
func RuntimeStatusHandler(internalSecret string, c *ToolRiskClient, mcp *MCPProxyHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("X-JJDGuard-Internal-Secret")
		if internalSecret == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(internalSecret)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(GatewayRuntimeStatus(c, mcp))
	}
}
