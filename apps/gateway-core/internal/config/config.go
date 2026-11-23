package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/buildinfo"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

type Config struct {
	ProductProfile                string
	ProductName                   string
	ProductVersion                string
	ListenAddr                    string
	DatabaseURL                   string
	RedisURL                      string
	RedisAddr                     string
	SecurityEngineURL             string
	InputSecurityRequestTimeout   time.Duration
	ControlPlaneURL               string
	InternalAPISecret             string
	SemanticGatewayAttestationKey string
	LogLevel                      string
	MCPConfirmationScopeSecret    string
	ShutdownTimeout               time.Duration
	SecurityAuditOnly             bool
	OutputSecurityMode            string
	OutputStreamHoldbackBytes     int
	OutputStreamScanBatchBytes    int
	OutputStreamPendingBytes      int
	OutputStrictMaxBytes          int
	SecurityActionHeader          bool
	SecurityActionHeaderDefaulted bool
	GuardrailFailureMode          string
	RetentionFailureMode          string
	AuditAsyncEnabled             bool
	APIRequestBodyLimitBytes      int64
	// BillingMode separates non-blocking showback metering from prepaid admission.
	BillingEnabled bool
	BillingMode    string
	BillingGroup   string

	// MCP 安全网关（/mcp/{serverID} JSON-RPC 代理 + tools/call 权限管控）总开关。
	// 默认 false —— 不注册路由、行为与改造前完全一致；true 才启用。
	// 注意：开启后仍受 SECURITY_AUDIT_ONLY 钳制，audit-only 下任何决策只审计不阻断。
	MCPGatewayEnabled         bool
	MCPToolResultGuardEnabled bool
	MCPAllowedOrigins         []string
	AgentEndpointEnabled      bool

	// MCPPolicyFailMode 控制 control-plane 策略拉取失败时的兜底取向：
	//   "open"（默认）——fail-open 到 audit（只审计放行），守住"绝不断流"可用性铁律；
	//   "closed"——fail-close 到 block（拉取失败按阻断处理），供 enforce 模式政企客户可选。
	// 无论哪种，SECURITY_AUDIT_ONLY=true 时仍被 CallerMode 钳回 audit（audit-only 铁律不破）。
	MCPPolicyFailMode string

	// Upstream streaming (Stage 2): 给上游的调用是否走流式 SSE + 网关内部累积。
	// 默认 false —— 行为与改造前完全一致(走非流式 Call), 零风险; true 才走 CallStreaming。
	UpstreamStreaming         bool
	UpstreamStreamIdleTimeout time.Duration
	// StreamKeepaliveInterval: chat / messages / responses / Gemini 四条流式路径走"先攒后发"时，攒满一个间隔
	// 仍未完成就先回 200 + text/event-stream 头，之后每个间隔写一次保活字节（chat、messages、responses 为
	// SSE 注释 ": keepalive"，Gemini 为空行），防 Dify 等客户端/中间层按读超时断开。默认 15s（开箱支持
	// Dify）；显式设 0 关闭。慢请求的拦截与错误由各协议的流内错误帧告知（状态码已是 200）。
	StreamKeepaliveInterval time.Duration

	// Proxy model settings
	ProxyEnabled            bool
	ProxyDefaultTenantID    string
	GatewayForwardProxyMode string
	ProxyWhitelistFailMode  string
	ProxyDefaultProjectID   string
	ProxyDefaultUserID      string
	ProxyListenAddr         string
	RetentionStorePath      string
	EnvironmentScope        string
}

const (
	BillingModeOff      = "off"
	BillingModeMetering = "metering"
	BillingModePrepaid  = "prepaid"
)

func Load() (*Config, error) {
	productProfile, err := resolveProductProfile(os.Getenv("PRODUCT_PROFILE"))
	if err != nil {
		return nil, err
	}
	productName := "JJDGuard"
	productVersion := buildinfo.Current().Version
	if productProfile == "agent-platform" {
		productName = getEnv("PRODUCT_NAME", "JJDGuard Agent Platform")
		productVersion = getEnv("PRODUCT_VERSION", "1.0.0")
	}
	redisURL := getEnv("REDIS_URL", "redis://redis:6379/0")
	redisAddr := extractRedisAddr(redisURL)

	mcpAllowedOrigins, err := parseMCPAllowedOrigins(getEnv("MCP_ALLOWED_ORIGINS", ""))
	if err != nil {
		return nil, err
	}
	billingMode, err := resolveBillingMode(getEnv("BILLING_MODE", ""), getEnvBool("BILLING_ENABLED", false))
	if err != nil {
		return nil, err
	}
	guardrailFailureMode, err := resolveFailureMode(getEnv("GUARDRAIL_FAILURE_MODE", "auto"), true, "GUARDRAIL_FAILURE_MODE")
	if err != nil {
		return nil, err
	}
	retentionFailureMode, err := resolveFailureMode(getEnv("RETENTION_FAILURE_MODE", "open"), false, "RETENTION_FAILURE_MODE")
	if err != nil {
		return nil, err
	}
	outputSecurityMode, err := relay.ParseOutputSecurityMode(getEnv("GATEWAY_OUTPUT_SECURITY_MODE", "stream_enforce"))
	if err != nil {
		return nil, fmt.Errorf("GATEWAY_OUTPUT_SECURITY_MODE: %w", err)
	}
	holdback, err := boundedOutputBytes("GATEWAY_OUTPUT_STREAM_HOLDBACK_BYTES", 256, 4, 16<<10)
	if err != nil {
		return nil, err
	}
	batch, err := boundedOutputBytes("GATEWAY_OUTPUT_STREAM_SCAN_BATCH_BYTES", 1024, 4, 48<<10)
	if err != nil {
		return nil, err
	}
	pending, err := boundedOutputBytes("GATEWAY_OUTPUT_STREAM_PENDING_BYTES", 4<<20, 64<<10, 64<<20)
	if err != nil {
		return nil, err
	}
	strict, err := boundedOutputBytes("GATEWAY_OUTPUT_STRICT_MAX_BYTES", 4<<20, 1024, 64<<20)
	if err != nil {
		return nil, err
	}
	securityActionHeader, headerErr := strconv.ParseBool(strings.TrimSpace(os.Getenv("SECURITY_ACTION_HEADER_ENABLED")))
	headerDefaulted := headerErr != nil
	if headerDefaulted {
		securityActionHeader = !getEnvBool("SECURITY_AUDIT_ONLY", false)
	}
	cfg := &Config{
		ProductProfile:                productProfile,
		ProductName:                   productName,
		ProductVersion:                productVersion,
		ListenAddr:                    getEnv("LISTEN_ADDR", ":8080"),
		DatabaseURL:                   getEnv("DATABASE_URL", "postgres://jjdguard:jjdguard@postgres:5432/jjdguard?sslmode=disable"),
		RedisURL:                      redisURL,
		RedisAddr:                     redisAddr,
		SecurityEngineURL:             getEnv("SECURITY_ENGINE_URL", "http://security-engine:8000"),
		InputSecurityRequestTimeout:   positiveDuration("GATEWAY_INPUT_SECURITY_REQUEST_TIMEOUT", 30*time.Second),
		ControlPlaneURL:               getEnv("CONTROL_PLANE_URL", "http://control-plane:8081"),
		InternalAPISecret:             getEnv("JJD_INTERNAL_API_SECRET", getEnv("JJD_PROVIDER_SECRET_KEY", "")),
		SemanticGatewayAttestationKey: getEnv("JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY", ""),
		LogLevel:                      getEnv("LOG_LEVEL", "info"),
		MCPConfirmationScopeSecret:    getEnv("MCP_CONFIRMATION_SCOPE_SECRET", ""),
		ShutdownTimeout:               30 * time.Second,
		SecurityAuditOnly:             getEnvBool("SECURITY_AUDIT_ONLY", false),
		OutputSecurityMode:            string(outputSecurityMode),
		OutputStreamHoldbackBytes:     holdback,
		OutputStreamScanBatchBytes:    batch,
		OutputStreamPendingBytes:      pending,
		OutputStrictMaxBytes:          strict,
		SecurityActionHeader:          securityActionHeader,
		SecurityActionHeaderDefaulted: headerDefaulted,
		GuardrailFailureMode:          guardrailFailureMode,
		RetentionFailureMode:          retentionFailureMode,
		AuditAsyncEnabled:             getEnvBool("AUDIT_ASYNC_ENABLED", false),
		APIRequestBodyLimitBytes:      getEnvMegabytes("GATEWAY_API_BODY_LIMIT_MB", 200, 200),
		BillingEnabled:                billingMode != BillingModeOff,
		BillingMode:                   billingMode,
		BillingGroup:                  getEnv("BILLING_CUSTOMER_GROUP", "default"),
		MCPGatewayEnabled:             getEnvBool("MCP_GATEWAY_ENABLED", false),
		MCPToolResultGuardEnabled:     getEnvBool("MCP_TOOL_RESULT_GUARD_ENABLED", true),
		AgentEndpointEnabled:          getEnvBool("AGENT_ENDPOINT_ENABLED", productProfile == "agent-platform"),
		MCPPolicyFailMode:             getEnv("MCP_POLICY_FAIL_MODE", "open"),
		MCPAllowedOrigins:             mcpAllowedOrigins,
		UpstreamStreaming:             getEnvBool("GATEWAY_UPSTREAM_STREAMING", false),
		UpstreamStreamIdleTimeout:     getEnvDuration("GATEWAY_UPSTREAM_STREAM_IDLE_TIMEOUT", 60*time.Second),
		StreamKeepaliveInterval:       streamKeepaliveInterval(),
		ProxyEnabled:                  getEnvBool("PROXY_ENABLED", false),
		ProxyDefaultTenantID:          getEnv("PROXY_DEFAULT_TENANT_ID", "tenant_default"),
		GatewayForwardProxyMode:       getEnv("GATEWAY_FORWARD_PROXY_MODE", "deny_unlisted"),
		ProxyWhitelistFailMode:        getEnv("PROXY_WHITELIST_FAIL_MODE", "closed"),
		ProxyDefaultProjectID:         getEnv("PROXY_DEFAULT_PROJECT_ID", "project_default"),
		ProxyDefaultUserID:            getEnv("PROXY_DEFAULT_USER_ID", "system_proxy"),
		ProxyListenAddr:               getEnv("PROXY_LISTEN_ADDR", ":8082"),
		RetentionStorePath:            getEnv("RETENTION_STORE_PATH", ""),
		EnvironmentScope:              retentionartifact.NormalizeEnvironmentScope(getEnv("GATEWAY_ENVIRONMENT_SCOPE", retentionartifact.LegacyEnvironmentScope)),
	}
	if cfg.MCPGatewayEnabled && len([]byte(cfg.MCPConfirmationScopeSecret)) < 32 {
		return nil, fmt.Errorf("MCP_CONFIRMATION_SCOPE_SECRET must be at least 32 bytes when MCP_GATEWAY_ENABLED=true")
	}

	return cfg, nil
}

// Runtime Record suppresses the default header; explicit enablement remains independent.
func (c *Config) SecurityActionHeaderEnabled(auditOnly bool) bool {
	return c != nil && c.SecurityActionHeader && (!c.SecurityActionHeaderDefaulted || !auditOnly)
}

func resolveFailureMode(value string, allowAuto bool, key string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "open", "fail-open", "fail_open":
		return "open", nil
	case "close", "closed", "fail-close", "fail_close":
		return "close", nil
	case "auto":
		if allowAuto {
			return "auto", nil
		}
	}
	allowed := "open or close"
	if allowAuto {
		allowed = "auto, open, or close"
	}
	return "", fmt.Errorf("%s must be %s", key, allowed)
}

func resolveProductProfile(value string) (string, error) {
	if value == "" {
		return "gateway", nil
	}
	if value != "gateway" && value != "agent-platform" {
		return "", fmt.Errorf("PRODUCT_PROFILE must be gateway or agent-platform")
	}
	return value, nil
}

func resolveBillingMode(value string, legacyEnabled bool) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		if legacyEnabled {
			return BillingModePrepaid, nil
		}
		return BillingModeOff, nil
	}
	switch value {
	case BillingModeOff, BillingModeMetering, BillingModePrepaid:
		return value, nil
	default:
		return "", fmt.Errorf("BILLING_MODE must be off, metering, or prepaid")
	}
}

func getEnvMegabytes(key string, defaultMB, maxMB int64) int64 {
	megabytes, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(key)), 10, 64)
	if err != nil || megabytes <= 0 || megabytes > maxMB {
		megabytes = defaultMB
	}
	return megabytes << 20
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return defaultValue
	}
	return b
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return defaultValue
	}
	return d
}

// DefaultStreamKeepaliveInterval 要小于常见中间层的 60s 空闲超时。
const DefaultStreamKeepaliveInterval = 15 * time.Second

// streamKeepaliveInterval 读 GATEWAY_STREAM_KEEPALIVE_INTERVAL（Go duration，如 "15s"）。
// 空=默认 15s；"0"/"0s"/"false"/"off"/"disabled"/"no"=关闭；写错（如漏单位的 "15"）告警后用默认值；过小的值抬到 1s 防刷屏。
func streamKeepaliveInterval() time.Duration {
	const key = "GATEWAY_STREAM_KEEPALIVE_INTERVAL"
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return DefaultStreamKeepaliveInterval
	}
	switch strings.ToLower(raw) {
	case "0", "false", "off", "disabled", "no":
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		log.Printf("[config] %s=%q is not a valid duration (example: 15s, or 0 to disable); using default %s", key, raw, DefaultStreamKeepaliveInterval)
		return DefaultStreamKeepaliveInterval
	}
	if d > 0 && d < time.Second {
		log.Printf("[config] %s=%s is below 1s; using 1s", key, d)
		return time.Second
	}
	return d
}

func positiveDuration(key string, defaultValue time.Duration) time.Duration {
	d := getEnvDuration(key, defaultValue)
	if d <= 0 {
		return defaultValue
	}
	return d
}

func extractRedisAddr(redisURL string) string {
	if strings.HasPrefix(redisURL, "redis://") {
		addr := strings.TrimPrefix(redisURL, "redis://")
		parts := strings.Split(addr, "/")
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return redisURL
}

func boundedOutputBytes(key string, fallback, min, max int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < min || value > max {
		return 0, fmt.Errorf("%s must be between %d and %d bytes", key, min, max)
	}
	return value, nil
}
