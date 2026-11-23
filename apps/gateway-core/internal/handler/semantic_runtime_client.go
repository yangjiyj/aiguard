package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
	"github.com/yangjiyj/aiguard/packages/shared-go/errclass"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"github.com/yangjiyj/aiguard/packages/shared-go/runtimeoptions"
)

const (
	semanticGatewayConfigPath      = "/admin/v1/internal/security/semantic-config/gateway"
	semanticGatewayReportPath      = "/admin/v1/internal/security/semantic-runtime-report/gateway"
	semanticGatewayComponent       = "gateway-core"
	semanticGatewayReportTTL       = 2 * time.Minute
	maxSemanticConfigResponseBytes = 64 << 10
)

var semanticRuntimeRevisionPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type semanticRuntimeConfig struct {
	InspectionPolicy             *inspectionscope.Policy
	Revision                     string
	DesiredRevision              string
	SignedProjection             map[string]any
	Enabled                      bool
	InputEnabled                 bool
	AgentEnabled                 bool
	SecurityAuditOnly            bool
	SecurityExecutionModeManaged bool
	FileContentDLPEnabled        bool
	// GuardrailFailClosedEnabled is the explicit fail-closed option; false when
	// an older control plane does not send it.
	GuardrailFailClosedEnabled bool
	// RuntimeOptions 是故障处理与检测执行里由网关执行的几项（2.9.22），未下发的键为空。
	RuntimeOptions runtimeSecurityOptions
	// ForwardProxy 是控制台下发的正向代理设置（egresspolicy.Keys 中控制面发来的键；开关
	// 写成 "true"/"false"）。控制面没发的键不在这里，由部署环境变量作初值。
	ForwardProxy map[string]string
}

type semanticRuntimeConfigResponse struct {
	inspectionscope.Fields
	Revision                     string          `json:"revision"`
	SemanticEnabled              *bool           `json:"semantic_enabled"`
	SemanticInputEnabled         *bool           `json:"semantic_input_enabled"`
	SemanticAgentEnabled         *bool           `json:"semantic_agent_enabled"`
	SecurityAuditOnly            *bool           `json:"security_audit_only"`
	SecurityExecutionModeManaged json.RawMessage `json:"security_execution_mode_managed"`
	FileContentDLPEnabled        *bool           `json:"file_content_dlp_enabled"`
	GuardrailFailClosedEnabled   json.RawMessage `json:"guardrail_fail_closed_enabled"`
	// 2.9.22 可选键：只在库里存了时下发，值一律是字符串。
	SecurityCapacityFailMode      json.RawMessage `json:"security_capacity_fail_mode"`
	MCPPolicyFailMode             json.RawMessage `json:"mcp_policy_fail_mode"`
	RetentionFailureMode          json.RawMessage `json:"retention_failure_mode"`
	OutputSecurityMode            json.RawMessage `json:"output_security_mode"`
	OutputStrictMaxBytes          json.RawMessage `json:"output_strict_max_bytes"`
	UploadInspectionFailureAction json.RawMessage `json:"upload_inspection_failure_action"`
	// 正向代理设置（批次 3，egresspolicy.Keys）：开关是布尔，其余是字符串，控制面没发的键不出现。
	ForwardProxyAllowPrivate   json.RawMessage `json:"forward_proxy_egress_allow_private"`
	ForwardProxyAllowLoopback  json.RawMessage `json:"forward_proxy_egress_allow_loopback"`
	ForwardProxyAllowMetadata  json.RawMessage `json:"forward_proxy_egress_allow_metadata"`
	ForwardProxyAllowedCIDRs   json.RawMessage `json:"forward_proxy_egress_allowed_cidrs"`
	ForwardProxyAllowedHosts   json.RawMessage `json:"forward_proxy_egress_allowed_hosts"`
	ForwardProxyUnlistedAction json.RawMessage `json:"forward_proxy_unlisted_action"`
	ProxyWhitelistFailMode     json.RawMessage `json:"proxy_whitelist_fail_mode"`
}

// runtimeOptionFields 列出可选字符串键（键名见 packages/shared-go/runtimeoptions），便于统一校验并纳入签名。
func (d *semanticRuntimeConfigResponse) runtimeOptionFields() map[string]json.RawMessage {
	return map[string]json.RawMessage{
		runtimeoptions.SecurityCapacityFailMode:      d.SecurityCapacityFailMode,
		runtimeoptions.MCPPolicyFailMode:             d.MCPPolicyFailMode,
		runtimeoptions.RetentionFailureMode:          d.RetentionFailureMode,
		runtimeoptions.OutputSecurityMode:            d.OutputSecurityMode,
		runtimeoptions.OutputStrictMaxBytes:          d.OutputStrictMaxBytes,
		runtimeoptions.UploadInspectionFailureAction: d.UploadInspectionFailureAction,
	}
}

// decodeForwardProxyProjection 取出签名投影里的正向代理设置并补进 canonical 参与验签。
// 开关必须是布尔，其余必须是字符串；控制面没发的键不出现在结果里。
func decodeForwardProxyProjection(decoded semanticRuntimeConfigResponse, canonical map[string]any) (map[string]string, error) {
	values := map[string]string{}
	for key, raw := range map[string]json.RawMessage{
		egresspolicy.KeyAllowPrivate:  decoded.ForwardProxyAllowPrivate,
		egresspolicy.KeyAllowLoopback: decoded.ForwardProxyAllowLoopback,
		egresspolicy.KeyAllowMetadata: decoded.ForwardProxyAllowMetadata,
	} {
		if raw = bytes.TrimSpace(raw); len(raw) == 0 {
			continue
		}
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("%s must be boolean", key)
		}
		canonical[key] = value
		values[key] = strconv.FormatBool(value)
	}
	for key, raw := range map[string]json.RawMessage{
		egresspolicy.KeyAllowedCIDRs:      decoded.ForwardProxyAllowedCIDRs,
		egresspolicy.KeyAllowedHosts:      decoded.ForwardProxyAllowedHosts,
		egresspolicy.KeyUnlistedAction:    decoded.ForwardProxyUnlistedAction,
		egresspolicy.KeyWhitelistFailMode: decoded.ProxyWhitelistFailMode,
	} {
		if raw = bytes.TrimSpace(raw); len(raw) == 0 {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("%s must be a string", key)
		}
		canonical[key] = value
		values[key] = value
	}
	return values, nil
}

func semanticGatewayConfigRevision(config map[string]any, key string) (string, error) {
	if len(key) < 16 {
		return "", fmt.Errorf("semantic config verification key is unavailable")
	}
	keys := make([]string, 0, len(config))
	for name := range config {
		if name != "revision" {
			keys = append(keys, name)
		}
	}
	sort.Strings(keys)
	var canonical bytes.Buffer
	for _, name := range keys {
		_, _ = fmt.Fprintf(&canonical, "%d:%s=", len([]byte(name)), name)
		// 与控制面 semanticCanonicalPayload 同一编码：布尔 b:0/1，字符串 s:长度:内容。
		switch value := config[name].(type) {
		case bool:
			if value {
				canonical.WriteString("b:1;")
			} else {
				canonical.WriteString("b:0;")
			}
		case string:
			raw := []byte(value)
			_, _ = fmt.Fprintf(&canonical, "s:%d:", len(raw))
			canonical.Write(raw)
			canonical.WriteByte(';')
		default:
			return "", fmt.Errorf("semantic config field %s has unsupported type", name)
		}
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte("jjdguard:semantic-config:" + semanticGatewayComponent + "\n"))
	_, _ = mac.Write(canonical.Bytes())
	return hex.EncodeToString(mac.Sum(nil)[:16]), nil
}

func (c *ToolRiskClient) fetchSemanticRuntimeConfig(ctx context.Context) (semanticRuntimeConfig, error) {
	if c == nil {
		return semanticRuntimeConfig{}, fmt.Errorf("tool risk client is nil")
	}
	endpoint := strings.TrimRight(c.controlPlaneURL, "/") + semanticGatewayConfigPath
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return semanticRuntimeConfig{}, fmt.Errorf("create semantic config request: %w", err)
	}
	if c.internalAPISecret != "" {
		request.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return semanticRuntimeConfig{}, fmt.Errorf("fetch semantic config: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return semanticRuntimeConfig{}, &errclass.HTTPStatusError{Op: "semantic config", Status: response.StatusCode}
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxSemanticConfigResponseBytes+1))
	if err != nil {
		return semanticRuntimeConfig{}, fmt.Errorf("read semantic config: %w", err)
	}
	if len(payload) > maxSemanticConfigResponseBytes {
		return semanticRuntimeConfig{}, fmt.Errorf("semantic config response exceeds limit")
	}
	var decoded semanticRuntimeConfigResponse
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return semanticRuntimeConfig{}, fmt.Errorf("decode semantic config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return semanticRuntimeConfig{}, fmt.Errorf("semantic config has trailing data")
	}
	decoded.Revision = strings.TrimSpace(decoded.Revision)
	if !semanticRuntimeRevisionPattern.MatchString(decoded.Revision) ||
		decoded.SemanticEnabled == nil ||
		decoded.SemanticInputEnabled == nil ||
		decoded.SemanticAgentEnabled == nil ||
		decoded.SecurityAuditOnly == nil ||
		decoded.FileContentDLPEnabled == nil {
		return semanticRuntimeConfig{}, fmt.Errorf("semantic config is incomplete")
	}
	canonical := map[string]any{
		"semantic_enabled":         *decoded.SemanticEnabled,
		"semantic_input_enabled":   *decoded.SemanticInputEnabled,
		"semantic_agent_enabled":   *decoded.SemanticAgentEnabled,
		"security_audit_only":      *decoded.SecurityAuditOnly,
		"file_content_dlp_enabled": *decoded.FileContentDLPEnabled,
	}
	inspectionPolicy, err := decoded.Fields.Resolve()
	if err != nil {
		return semanticRuntimeConfig{}, err
	}
	decoded.Fields.AddCanonical(canonical)
	managed := false
	if raw := bytes.TrimSpace(decoded.SecurityExecutionModeManaged); len(raw) > 0 {
		switch string(raw) {
		case "true":
			managed = true
		case "false":
		default:
			return semanticRuntimeConfig{}, fmt.Errorf("security execution mode marker must be boolean")
		}
		canonical["security_execution_mode_managed"] = managed
	}
	// Optional: an older control plane omits the key, the revision is then
	// verified without it and the option resolves to false.
	failClosed := false
	if raw := bytes.TrimSpace(decoded.GuardrailFailClosedEnabled); len(raw) > 0 {
		switch string(raw) {
		case "true":
			failClosed = true
		case "false":
		default:
			return semanticRuntimeConfig{}, fmt.Errorf("guardrail fail-closed option must be boolean")
		}
		canonical["guardrail_fail_closed_enabled"] = failClosed
	}
	var runtimeOptions runtimeSecurityOptions
	ignoredOptions := map[string]string{}
	for name, raw := range decoded.runtimeOptionFields() {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return semanticRuntimeConfig{}, fmt.Errorf("semantic config %s must be a string", name)
		}
		// 取值照样纳入签名；不认识的取值只让该键按未下发处理（新控制面多了取值时不连累整份配置）。
		if err := runtimeOptions.apply(name, value); err != nil {
			ignoredOptions[name] = value
		}
		canonical[name] = value
	}
	forwardProxy, err := decodeForwardProxyProjection(decoded, canonical)
	if err != nil {
		return semanticRuntimeConfig{}, err
	}
	expectedRevision, err := semanticGatewayConfigRevision(canonical, c.semanticConfigAttestationKey)
	if err != nil {
		return semanticRuntimeConfig{}, err
	}
	if subtle.ConstantTimeCompare([]byte(expectedRevision), []byte(decoded.Revision)) != 1 {
		return semanticRuntimeConfig{}, fmt.Errorf("semantic config attestation is invalid")
	}
	// 验签通过后才记不认识的取值，且同一取值只记一次（周期刷新不刷屏）。
	if changed := c.ignoredRuntimeOptions.Changed(ignoredOptions); len(changed) > 0 {
		log.Printf("semantic config: unrecognized values for %s ignored; those options fall back to local defaults", strings.Join(changed, ","))
	}
	desiredProjection := make(map[string]any, len(canonical))
	for key, value := range canonical {
		desiredProjection[key] = value
	}
	// 部署变量 SECURITY_AUDIT_ONLY=true 只在没有显式执行模式时作初值（2.9.22 D7）：
	// 控制台显式选了防护阻断（managed）就按防护执行。
	effectiveAuditOnly := *decoded.SecurityAuditOnly || (!managed && securityAuditOnlyForcedByEnvironment())
	effectiveRevision := decoded.Revision
	if effectiveAuditOnly != *decoded.SecurityAuditOnly {
		canonical["security_audit_only"] = effectiveAuditOnly
		effectiveRevision, err = semanticGatewayConfigRevision(canonical, c.semanticConfigAttestationKey)
		if err != nil {
			return semanticRuntimeConfig{}, err
		}
	}
	return semanticRuntimeConfig{
		InspectionPolicy:             &inspectionPolicy,
		Revision:                     effectiveRevision,
		DesiredRevision:              decoded.Revision,
		SignedProjection:             desiredProjection,
		Enabled:                      *decoded.SemanticEnabled,
		InputEnabled:                 *decoded.SemanticInputEnabled,
		AgentEnabled:                 *decoded.SemanticAgentEnabled,
		SecurityAuditOnly:            effectiveAuditOnly,
		SecurityExecutionModeManaged: managed,
		FileContentDLPEnabled:        *decoded.FileContentDLPEnabled,
		GuardrailFailClosedEnabled:   failClosed,
		RuntimeOptions:               runtimeOptions,
		ForwardProxy:                 forwardProxy,
	}, nil
}

// ForwardProxyValues 返回控制台下发的正向代理设置；运行时配置还没加载时 ok=false。
func (c *ToolRiskClient) ForwardProxyValues(ctx context.Context) (map[string]string, bool) {
	config, err := c.semanticRuntimeConfig(ctx)
	if err != nil {
		return nil, false
	}
	values := make(map[string]string, len(config.ForwardProxy))
	for key, value := range config.ForwardProxy {
		values[key] = value
	}
	return values, true
}

func (c *ToolRiskClient) InspectionPolicy(ctx context.Context) inspectionscope.Policy {
	if config, err := c.semanticRuntimeConfig(ctx); err == nil && config.InspectionPolicy != nil {
		return *config.InspectionPolicy
	}
	return inspectionscope.Default()
}

func semanticRuntimeNodeID() string {
	nodeID := strings.TrimSpace(os.Getenv("SEMANTIC_RUNTIME_NODE_ID"))
	if nodeID == "" {
		nodeID = strings.TrimSpace(os.Getenv("HOSTNAME"))
	}
	if nodeID == "" {
		nodeID = semanticGatewayComponent
	}
	if len(nodeID) > 128 {
		nodeID = nodeID[:128]
	}
	return nodeID
}

func semanticRuntimeReportPayload(config semanticRuntimeConfig, errorCode string) map[string]any {
	payload := map[string]any{
		"component":     semanticGatewayComponent,
		"node_id":       semanticRuntimeNodeID(),
		"config_loaded": config.Revision != "",
	}
	if config.Revision != "" {
		payload["applied_revision"] = config.Revision
		payload["held_revision"] = config.Revision
	}
	if config.DesiredRevision != "" {
		payload["desired_revision"] = config.DesiredRevision
	}
	if errorCode != "" {
		payload["error_code"] = errorCode
	}
	return payload
}

func (c *ToolRiskClient) reportSemanticRuntime(ctx context.Context, config semanticRuntimeConfig, errorCode string) error {
	endpoint := strings.TrimRight(c.controlPlaneURL, "/") + semanticGatewayReportPath
	fields := semanticRuntimeReportPayload(config, errorCode)
	if c.postureProvider != nil {
		if posture := c.postureProvider(ctx, config); posture != nil {
			actual := make(map[string]any, len(config.SignedProjection))
			for key, value := range config.SignedProjection {
				actual[key] = value
			}
			actual["security_audit_only"] = *posture.SecurityAuditOnly
			if revision, err := semanticGatewayConfigRevision(actual, c.semanticConfigAttestationKey); err == nil && posture.Validate() == nil {
				fields["applied_revision"], fields["held_revision"] = revision, revision
				fields["posture"] = posture
			}
		}
	}
	payload, _ := json.Marshal(fields)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create semantic report request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if c.internalAPISecret != "" {
		request.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("report semantic runtime: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &errclass.HTTPStatusError{Op: "semantic runtime report", Status: response.StatusCode}
	}
	return nil
}
func (c *ToolRiskClient) refreshSemanticRuntimeConfig(ctx context.Context) (semanticRuntimeConfig, error) {
	value, err, _ := c.semanticRefreshGroup.Do("semantic-config", func() (any, error) {
		config, fetchErr := c.fetchSemanticRuntimeConfig(ctx)
		if fetchErr != nil {
			held, _ := c.runtimeCache.getSemanticConfig()
			reportCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if reportErr := c.reportSemanticRuntime(reportCtx, held, "config_fetch_failed"); reportErr != nil {
				log.Printf("semantic degraded runtime report failed: %s", errclass.Summary(reportErr))
			}
			return semanticRuntimeConfig{}, fetchErr
		}
		c.runtimeCache.setSemanticConfig(config)
		if reportErr := c.reportSemanticRuntime(ctx, config, ""); reportErr != nil {
			log.Printf("semantic runtime report failed: %s", errclass.Summary(reportErr))
		}
		return config, nil
	})
	if err != nil {
		return semanticRuntimeConfig{}, err
	}
	return value.(semanticRuntimeConfig), nil
}

func (c *ToolRiskClient) semanticRuntimeConfig(_ context.Context) (semanticRuntimeConfig, error) {
	if c == nil || c.runtimeCache == nil {
		return semanticRuntimeConfig{}, fmt.Errorf("semantic runtime cache is unavailable")
	}
	if config, ok := c.runtimeCache.getSemanticConfig(); ok {
		return config, nil
	}
	return semanticRuntimeConfig{}, fmt.Errorf("semantic runtime config is not loaded")
}

func (c *ToolRiskClient) SemanticAgentEnabled(ctx context.Context, fallback bool) bool {
	config, err := c.semanticRuntimeConfig(ctx)
	if err != nil {
		return fallback
	}
	return config.Enabled && config.AgentEnabled
}

// FileContentDLPEnabled 解析当前生效的文件内容 DLP 全局动态开关。
// 动态缓存值优先；控制平面不可用或缓存未加载时回落到启动环境后备。
func (c *ToolRiskClient) FileContentDLPEnabled(ctx context.Context, fallback bool) bool {
	config, err := c.semanticRuntimeConfig(ctx)
	if err != nil {
		return fallback
	}
	return config.FileContentDLPEnabled
}

// GuardrailFailClosedEnabled reports the signed fail-closed option. There is
// no environment fallback: an unloaded or unavailable snapshot is false.
func (c *ToolRiskClient) GuardrailFailClosedEnabled(ctx context.Context) bool {
	config, err := c.semanticRuntimeConfig(ctx)
	if err != nil {
		return false
	}
	return config.GuardrailFailClosedEnabled
}

func (c *ToolRiskClient) SemanticInputEnabled(ctx context.Context, fallback bool) bool {
	config, err := c.semanticRuntimeConfig(ctx)
	if err != nil {
		return fallback
	}
	return config.Enabled && config.InputEnabled
}

// logSemanticRefreshFailure 记录语义运行时配置刷新失败：只含错误类别（超时/连接失败/HTTP 状态码…），
// 不含正文或 URL。30 秒一次的周期下，持续故障会一夜刷上千行，故首条必打、之后每 10 条一条。
func (c *ToolRiskClient) logSemanticRefreshFailure(err error) {
	if c == nil || c.semanticRefreshLog == nil {
		log.Printf("semantic runtime refresh failed: %s", errclass.Summary(err))
		return
	}
	c.semanticRefreshLog.Printf(errclass.Classify(err), "semantic runtime refresh failed: %s", errclass.Summary(err))
}

func normalizeSemanticRefreshInterval(interval time.Duration) time.Duration {
	if interval < 5*time.Second {
		return 5 * time.Second
	}
	maximum := semanticGatewayReportTTL / 2
	if interval > maximum {
		return maximum
	}
	return interval
}

func (c *ToolRiskClient) StartSemanticRuntimeRefresh(ctx context.Context, interval time.Duration) {
	c.startSemanticRuntimeRefresh(ctx, interval)
}

// startSemanticRuntimeRefresh 启动后台刷新协程，返回的 channel 在协程退出后关闭（测试用来等待退出，避免读日志时协程仍在写）。
func (c *ToolRiskClient) startSemanticRuntimeRefresh(ctx context.Context, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	if c == nil {
		close(done)
		return done
	}
	interval = normalizeSemanticRefreshInterval(interval)
	go func() {
		defer close(done)
		refresh := func() {
			refreshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if _, err := c.refreshSemanticRuntimeConfig(refreshCtx); err != nil {
				c.logSemanticRefreshFailure(err)
			}
			// D4：启动首次与之后每次模式/来源变化时，明确报告实际生效的执行模式。
			c.logEffectiveExecutionModeIfChanged()
		}
		refresh()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()
	return done
}
