package handler

// 故障处理与检测执行里由网关执行的几项（2.9.22 契约 2.2 节、任务 4.5）。
//
// 控制面把库里存了的键随签名投影下发；网关按请求读取最新快照，不在启动时固定。
// 某个键没下发（库里没存、旧控制面、快照未加载）时才用网关自己的环境变量作初值：
// SECURITY_CAPACITY_FAIL_CLOSED、MCP_POLICY_FAIL_MODE、RETENTION_FAILURE_MODE、
// GATEWAY_OUTPUT_SECURITY_MODE、GATEWAY_OUTPUT_STRICT_MAX_BYTES。

import (
	"strconv"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/runtimeoptions"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// runtimeSecurityOptions 中空值表示控制面没有下发该键。
type runtimeSecurityOptions struct {
	CapacityFailMode              string // open | closed
	MCPPolicyFailMode             string // open | closed
	RetentionFailureMode          string // open | closed
	OutputSecurityMode            string // stream_enforce | strict_buffered | stream_audit
	OutputStrictMaxBytes          int    // 0 = 未下发
	UploadInspectionFailureAction string // forward_alert | block
}

// apply 记下一个已签名覆盖的键；取值按共享包 runtimeoptions 校验与规范化，
// 不认识的取值返回错误，由调用方把该键当未下发处理。
func (o *runtimeSecurityOptions) apply(key, value string) error {
	normalized, err := runtimeoptions.Normalize(key, value)
	if err != nil {
		return err
	}
	switch key {
	case runtimeoptions.SecurityCapacityFailMode:
		o.CapacityFailMode = normalized
	case runtimeoptions.MCPPolicyFailMode:
		o.MCPPolicyFailMode = normalized
	case runtimeoptions.RetentionFailureMode:
		o.RetentionFailureMode = normalized
	case runtimeoptions.OutputSecurityMode:
		o.OutputSecurityMode = normalized
	case runtimeoptions.OutputStrictMaxBytes:
		o.OutputStrictMaxBytes, _ = strconv.Atoi(normalized)
	case runtimeoptions.UploadInspectionFailureAction:
		o.UploadInspectionFailureAction = normalized
	}
	return nil
}

func (c *ToolRiskClient) runtimeSecurityOptions() runtimeSecurityOptions {
	if c == nil || c.runtimeCache == nil {
		return runtimeSecurityOptions{}
	}
	if config, ok := c.runtimeCache.getSemanticConfig(); ok {
		return config.RuntimeOptions
	}
	return runtimeSecurityOptions{}
}

// CapacityFailClosed：检测排队满时是否拒绝（只在防护模式生效）。
func (c *ToolRiskClient) CapacityFailClosed() bool {
	if mode := c.runtimeSecurityOptions().CapacityFailMode; mode != "" {
		return mode == "closed"
	}
	return securityexit.CapacityPolicy().FailClosedOnCapacity
}

// currentMCPPolicyFailMode：MCP 策略不可用时的取向（open / closed）。
func (c *ToolRiskClient) currentMCPPolicyFailMode() string {
	if mode := c.runtimeSecurityOptions().MCPPolicyFailMode; mode != "" {
		return mode
	}
	if c == nil {
		return normalizeMCPPolicyFailMode("")
	}
	return c.mcpPolicyFailMode
}

// RetentionFailureMode 返回网关配置口径（open / close）；fallback 是启动配置。
func (c *ToolRiskClient) RetentionFailureMode(fallback string) string {
	switch c.runtimeSecurityOptions().RetentionFailureMode {
	case "closed":
		return "close"
	case "open":
		return "open"
	}
	return fallback
}

// UploadInspectionFailureBlocks：上传时检测失败是否拦截（缺省转发并另记告警）。
func (c *ToolRiskClient) UploadInspectionFailureBlocks() bool {
	return c.runtimeSecurityOptions().UploadInspectionFailureAction == "block"
}

// effectiveOutputSecurityMode 按请求取输出检测方式：签名下发值优先，其次启动配置。
func effectiveOutputSecurityMode(client *ToolRiskClient, cfg *config.Config) relay.OutputSecurityMode {
	if mode := client.runtimeSecurityOptions().OutputSecurityMode; mode != "" {
		return relay.NormalizeOutputSecurityMode(mode)
	}
	if cfg != nil {
		return relay.NormalizeOutputSecurityMode(cfg.OutputSecurityMode)
	}
	return relay.NormalizeOutputSecurityMode("")
}

// effectiveOutputStrictMaxBytes 按请求取缓冲严格模式的上限：签名下发值优先，其次启动配置。
func effectiveOutputStrictMaxBytes(client *ToolRiskClient, cfg *config.Config) int {
	if limit := client.runtimeSecurityOptions().OutputStrictMaxBytes; limit > 0 {
		return limit
	}
	if cfg != nil {
		return cfg.OutputStrictMaxBytes
	}
	return 0
}
