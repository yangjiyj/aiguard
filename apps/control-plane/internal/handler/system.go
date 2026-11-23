package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alert"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/executionmode"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
	"github.com/yangjiyj/aiguard/packages/shared-go/logretention"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// maskedSecretValue 是面向 UI / 审计日志的密钥占位符（不回传明文/密文）。
const maskedSecretValue = "***"

// encryptedSecretPrefix 标识已加密的密钥密文，避免重复加密。
const encryptedSecretPrefix = "enc:v1:"

const (
	outboundProxyURLSettingKey                = "outbound_proxy_url"
	outboundProxyEnabledSettingKey            = "outbound_proxy_enabled"
	securityExecutionModeSettingKey           = executionmode.SettingKey
	securityExecutionModeModifiedBySettingKey = "security_execution_mode_modified_by"
	securityExecutionModeModifiedAtSettingKey = "security_execution_mode_modified_at"
	securityExecutionModeRecord               = executionmode.Record
	securityExecutionModeProtect              = executionmode.Protect
	securityExecutionModeChangeReasonKey      = "change_reason"
)

type securityExecutionModeView struct {
	ConfiguredMode  string `json:"configured_mode"`
	EffectiveMode   string `json:"effective_mode"`
	Locked          bool   `json:"locked"`
	Source          string `json:"source"`
	RuntimeVerified bool   `json:"runtime_verified"`
	RuntimeStatus   string `json:"runtime_status"`
	LastModifiedBy  string `json:"last_modified_by"`
	LastModifiedAt  string `json:"last_modified_at"`
}

func securityExecutionModeForSettings(ctx context.Context, deps *Dependencies, settings []*repository.SystemSetting) securityExecutionModeView {
	values := make(map[string]string)
	lastModifiedAt := ""
	lastModifiedBy := ""
	for _, setting := range settings {
		if setting == nil {
			continue
		}
		values[setting.Key] = setting.Value
		switch setting.Key {
		case securityAuditOnlySettingKey:
			if !setting.UpdatedAt.IsZero() {
				lastModifiedAt = setting.UpdatedAt.UTC().Format(time.RFC3339Nano)
			}
		case securityExecutionModeModifiedBySettingKey:
			lastModifiedBy = setting.Value
		case securityExecutionModeModifiedAtSettingKey:
			if _, err := time.Parse(time.RFC3339Nano, setting.Value); err == nil {
				lastModifiedAt = setting.Value
			}
		}
	}
	auditOnly, source := executionmode.FromValues(values, executionmode.DeploymentRecordInitialValue())
	mode := executionmode.ModeName(auditOnly)
	// 2.9.22（设计 D7）：部署变量不再锁定控制台，locked 恒为 false（字段保留给旧前端）。
	locked := false
	configured, effective := mode, mode
	source = executionModeViewSource(source)
	view := securityExecutionModeView{
		ConfiguredMode: configured, EffectiveMode: effective, Locked: locked, Source: source,
		RuntimeStatus:  semanticRuntimeStatusUnavailable,
		LastModifiedBy: lastModifiedBy, LastModifiedAt: lastModifiedAt,
	}
	if configs, err := buildSemanticComponentConfigs(ctx, deps); err == nil {
		runtime := buildSemanticRuntimeStatus(semanticDesiredRevisions{
			Engine: configs.EngineRevision, Gateway: configs.GatewayRevision,
			EngineJudgeRequired: semanticEngineJudgeRequired(configs.Engine),
		}, time.Now().UTC())
		view.RuntimeVerified = runtime.RuntimeVerified
		view.RuntimeStatus = runtime.Status
	}
	return view
}

// GetSystemSettings returns all system settings
func GetSystemSettings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		settings, err := deps.SystemRepo.GetAll(r.Context())
		if err != nil {
			writeError(w, "internal_error", "failed to get settings")
			return
		}

		mode := securityExecutionModeForSettings(r.Context(), deps, settings)
		// L-2：安全员（isFullTenantRole 为真只是因为它要租户内读安全记录）拿的是「安全相关子集」，不是全量。
		// 登录策略、IP 白名单、锁定阈值、出口代理、许可证、通知、计费等系统类配置属于系统管理员职责
		// （docs/design/ws4-rbac-matrix.md：/system/settings 页面只对系统管理员开放）。
		if roles.IsSecurityOfficer(user.Role) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(securityOfficerSettingsView(r.Context(), deps, settings, mode))
			return
		}
		if !isFullTenantRole(user.Role) {
			w.Header().Set("Content-Type", "application/json")
			// The public client endpoint is safe for key holders; keep private settings restricted.
			data := map[string]any{securityExecutionModeSettingKey: mode}
			for _, setting := range settings {
				if setting.Key == "gateway_public_base_url" || setting.Key == "gateway_public_endpoints" || setting.Key == "gateway_public_url_mode" {
					data[setting.Key] = setting.Value
				}
			}
			_ = json.NewEncoder(w).Encode(data)
			return
		}

		data := make(map[string]any)
		for _, s := range settings {
			if s.Key != securityAuditOnlySettingKey &&
				s.Key != securityExecutionModeModifiedBySettingKey &&
				s.Key != securityExecutionModeModifiedAtSettingKey {
				data[s.Key] = s.Value
			}
		}
		data[securityExecutionModeSettingKey] = mode
		if _, exists := data[blockResponseModeSettingKey]; !exists {
			data[blockResponseModeSettingKey] = "error"
		}
		data["security_block_notice_default_template"] = defaultBlockNoticeTemplate
		// 告警自动关闭：库里没有合法值时展示实际生效的兜底值（环境变量或默认关闭），
		// 避免界面显示"关闭"而运行态其实按环境变量开着。
		{
			var dbEnabled, dbDays *string
			if v, ok := data[alert.AlertTTLEnabledSettingKey].(string); ok {
				dbEnabled = &v
			}
			if v, ok := data[alert.AlertGroupTTLDaysSettingKey].(string); ok {
				dbDays = &v
			}
			ttl := alert.ResolveAlertTTLConfig(dbEnabled, dbDays, os.Getenv("ALERT_TTL_ENABLED"), os.Getenv("ALERT_GROUP_TTL_DAYS"))
			data[alert.AlertTTLEnabledSettingKey] = strconv.FormatBool(ttl.Enabled)
			data[alert.AlertGroupTTLDaysSettingKey] = strconv.Itoa(ttl.TTLDays)
		}
		if _, exists := data[fileContentDLPSettingKey]; !exists {
			data[fileContentDLPSettingKey] = strconv.FormatBool(fileContentDLPEnabled(r.Context(), deps))
		}

		fillAIContentLabelDefaults(data)
		fillPlatformEgressEffectiveValues(data)
		fillResponseCacheDefaults(data)

		// 面向 UI 的端点：judge_api_key 一律脱敏，存在即显占位，绝不回传明文/密文。
		// 注意：仅此 UI 端点脱敏；GetInternalSystemSettings 供 engine 拿真值，不在此列。
		if _, ok := data["judge_api_key"]; ok {
			data["judge_api_key"] = maskedSecretValue
		}

		// 客户出口代理可能含认证口令；控制台只知道是否已配置，绝不回显明文或密文。
		proxyURL, _ := data[outboundProxyURLSettingKey].(string)
		if strings.TrimSpace(proxyURL) != "" {
			data[outboundProxyEnabledSettingKey] = "true"
			data[outboundProxyURLSettingKey] = maskedSecretValue
		} else {
			data[outboundProxyEnabledSettingKey] = "false"
			data[outboundProxyURLSettingKey] = ""
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	}
}

// securityOfficerSettingKeys 是安全员可见的配置键白名单（只增不默认放行）：安全员的页面（MCP 三页的执行模式与网关入口、
// 语义检测控制台、文件内容策略、拦截应答）实际读取的键。新增系统类配置默认对安全员不可见。
var securityOfficerSettingKeys = map[string]bool{
	// 语义检测 / 研判（SemanticConsole）
	"semantic_enabled": true, "semantic_agent_enabled": true, "semantic_input_enabled": true, "semantic_total_timeout": true,
	"inspect_user_input": true, "inspect_model_output": true, "inspect_tool_results": true, "inspect_history": true,
	"inspect_builtin_context": true, "fp_suppression_enabled": true,
	"judge_backend": true, "judge_model": true, "judge_provider_id": true, "judge_url": true, "judge_allow_private_egress": true,
	"guardrail_fail_closed_enabled": true,
	// 文件内容策略 / 拦截应答 / 双人审批
	"file_content_dlp_enabled": true, "content_file_policy_json": true,
	"security_block_response_mode": true, "security_block_notice_template": true,
	"agentguard_dual_approval": true, agentGuardAllowSelfApprovalSettingKey: true,
	// 告警自动关闭（告警处置职责）
	"alert_ttl_enabled": true, "alert_group_ttl_days": true,
	// 网关入口：MCP 服务页展示接入地址（与精简视图一致）
	"gateway_public_base_url": true, "gateway_public_endpoints": true, "gateway_public_url_mode": true,
	// 故障处理与检测执行（2.9.22，键名见 packages/shared-go/runtimeoptions）
	"security_capacity_fail_mode": true, "mcp_policy_fail_mode": true, "retention_failure_mode": true,
	"output_security_mode": true, "output_strict_max_bytes": true, "upload_inspection_failure_action": true,
	"semantic_block_stages": true, "agent_security_monitor_disposition": true, "model_output_classified_disposition": true,
	"confidence_gating_enabled": true, "confidence_threshold": true,
	// 正向代理出站（批次 3）：生效值与来源见 securityOfficerSettingsView
	egresspolicy.KeyAllowPrivate: true, egresspolicy.KeyAllowLoopback: true, egresspolicy.KeyAllowMetadata: true,
	egresspolicy.KeyAllowedCIDRs: true, egresspolicy.KeyAllowedHosts: true, egresspolicy.KeyUnlistedAction: true, egresspolicy.KeyWhitelistFailMode: true,
}

// securityOfficerSettingsView 组装安全员的配置视图：仅白名单键；执行模式与脱敏规则与全量视图一致。
func securityOfficerSettingsView(ctx context.Context, deps *Dependencies, settings []*repository.SystemSetting, mode securityExecutionModeView) map[string]any {
	data := map[string]any{securityExecutionModeSettingKey: mode}
	for _, st := range settings {
		if securityOfficerSettingKeys[st.Key] {
			data[st.Key] = st.Value
		}
	}
	// judge_api_key 只显示占位，绝不回传明文/密文；是否已配置对研判设置有用。
	for _, st := range settings {
		if st.Key == "judge_api_key" && strings.TrimSpace(st.Value) != "" {
			data["judge_api_key"] = maskedSecretValue
		}
	}
	if _, exists := data[blockResponseModeSettingKey]; !exists {
		data[blockResponseModeSettingKey] = "error"
	}
	data["security_block_notice_default_template"] = defaultBlockNoticeTemplate
	if _, exists := data[fileContentDLPSettingKey]; !exists {
		data[fileContentDLPSettingKey] = strconv.FormatBool(fileContentDLPEnabled(ctx, deps))
	}
	// 出站设置的生效值与来源与全量视图同一个函数折算，只留安全员可见的键（身份源、LDAP 键不给）。
	{
		egress := map[string]any{}
		for key, value := range data {
			egress[key] = value
		}
		fillPlatformEgressEffectiveValues(egress)
		allSources, _ := egress["egress_setting_sources"].(map[string]string)
		sources := map[string]string{}
		for _, key := range egresspolicy.Keys {
			if securityOfficerSettingKeys[key] {
				data[key] = egress[key]
				if source, ok := allSources[key]; ok {
					sources[key] = source
				}
			}
		}
		data["egress_setting_sources"] = sources
	}
	{
		var dbEnabled, dbDays *string
		if v, ok := data[alert.AlertTTLEnabledSettingKey].(string); ok {
			dbEnabled = &v
		}
		if v, ok := data[alert.AlertGroupTTLDaysSettingKey].(string); ok {
			dbDays = &v
		}
		ttl := alert.ResolveAlertTTLConfig(dbEnabled, dbDays, os.Getenv("ALERT_TTL_ENABLED"), os.Getenv("ALERT_GROUP_TTL_DAYS"))
		data[alert.AlertTTLEnabledSettingKey] = strconv.FormatBool(ttl.Enabled)
		data[alert.AlertGroupTTLDaysSettingKey] = strconv.Itoa(ttl.TTLDays)
	}
	return data
}

func GetInternalSystemSettings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, err := deps.SystemRepo.GetAll(r.Context())
		if err != nil {
			writeError(w, "internal_error", "failed to get settings")
			return
		}

		data := make(map[string]string)
		for _, s := range settings {
			data[s.Key] = s.Value
		}
		// 显式模式和部署初值都折算到旧键，供只认旧键的内部读者使用；旧键与安全默认保持原样。
		if auditOnly, source := executionmode.FromValues(data, executionmode.DeploymentRecordInitialValue()); source == executionmode.SourceAdminSettings || source == executionmode.SourceDeployment {
			data[securityAuditOnlySettingKey] = strconv.FormatBool(auditOnly)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	}
}

// normalizeAlertTTLSettings 校验告警组自动关闭的两个设置键：开关只接受 true/false，
// 天数为 1~365 的整数；合法值规范化后落库（定时任务每小时读取，无需重启）。
func normalizeAlertTTLSettings(settings map[string]string) error {
	if raw, ok := settings[alert.AlertTTLEnabledSettingKey]; ok {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "true":
			settings[alert.AlertTTLEnabledSettingKey] = "true"
		case "false":
			settings[alert.AlertTTLEnabledSettingKey] = "false"
		default:
			return fmt.Errorf("alert_ttl_enabled must be true or false")
		}
	}
	if raw, ok := settings[alert.AlertGroupTTLDaysSettingKey]; ok {
		days, err := alert.ParseAlertTTLDays(raw)
		if err != nil {
			return err
		}
		settings[alert.AlertGroupTTLDaysSettingKey] = strconv.Itoa(days)
	}
	return nil
}

func parseLogRetentionDays(raw string) (int, error) {
	return logretention.Validate(raw)
}

// normalizeOutboundProxyURL accepts only HTTP CONNECT proxies. SOCKS is not
// supported by Go's standard Transport here, and paths/query strings risk
// accidentally treating a credential-bearing URL as an API endpoint.
func normalizeOutboundProxyURL(raw string) (string, error) {
	proxyURL, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid outbound proxy URL")
	}
	proxyURL.Scheme = strings.ToLower(proxyURL.Scheme)
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
		return "", fmt.Errorf("出网代理仅支持 HTTP 或 HTTPS 地址")
	}
	if proxyURL.Host == "" {
		return "", fmt.Errorf("出网代理地址必须包含主机和端口")
	}
	if (proxyURL.Path != "" && proxyURL.Path != "/") || proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
		return "", fmt.Errorf("出网代理地址不能包含路径、查询参数或片段")
	}
	return proxyURL.String(), nil
}

func prepareOutboundProxySetting(ctx context.Context, deps *Dependencies, settings map[string]string) error {
	rawEnabled, enabledSet := settings[outboundProxyEnabledSettingKey]
	rawURL, urlSet := settings[outboundProxyURLSettingKey]
	if !enabledSet && !urlSet {
		return nil
	}
	delete(settings, outboundProxyEnabledSettingKey)

	enabled := urlSet
	if enabledSet {
		parsed, err := strconv.ParseBool(strings.TrimSpace(rawEnabled))
		if err != nil {
			return fmt.Errorf("出网代理开关必须是 true 或 false")
		}
		enabled = parsed
	}
	if !enabled {
		settings[outboundProxyURLSettingKey] = ""
		return nil
	}

	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" || trimmed == maskedSecretValue {
		existing, err := deps.SystemRepo.Get(ctx, outboundProxyURLSettingKey)
		if err != nil {
			return fmt.Errorf("读取现有出网代理配置失败")
		}
		if existing == nil || strings.TrimSpace(existing.Value) == "" {
			return fmt.Errorf("启用出网代理时必须填写代理地址")
		}
		delete(settings, outboundProxyURLSettingKey)
		return nil
	}

	normalized, err := normalizeOutboundProxyURL(trimmed)
	if err != nil {
		return err
	}
	ciphertext, _, err := secrets.EncryptProviderSecret(normalized)
	if err != nil {
		return fmt.Errorf("出网代理凭据加密失败")
	}
	settings[outboundProxyURLSettingKey] = ciphertext
	return nil
}

func loadConfiguredOutboundProxyURL(ctx context.Context, deps *Dependencies) (string, error) {
	if deps == nil || deps.SystemRepo == nil {
		return "", nil
	}

	setting, err := deps.SystemRepo.Get(ctx, outboundProxyURLSettingKey)
	if err != nil {
		return "", fmt.Errorf("读取出网代理配置失败")
	}
	if setting == nil || strings.TrimSpace(setting.Value) == "" {
		return "", nil
	}
	proxyURL, err := secrets.DecryptProviderSecret(setting.Value)
	if err != nil {
		return "", fmt.Errorf("出网代理凭据解密失败")
	}
	return normalizeOutboundProxyURL(proxyURL)
}

// securityWritableSettingKeyList 是平台管理员和平台级安全员都能写的平台级防护设置（D8），走
// PUT /admin/v1/security/system-settings；全量入口 PUT /system/settings 仍只有平台管理员能调，全局执行模式、
// 身份源与 LDAP 键也只归平台管理员。新批次的键追加到这里，
// 取值校验、版本推进和审计都走 updateSettingsWithScope 的通用链，不另写；安全员视图
// securityOfficerSettingKeys 要同时列上（TestSecurityOfficerReadsBackEveryWritableKey 守着）。
var securityWritableSettingKeyList = []string{
	// 人工确认（批次 2B）
	agentGuardAllowSelfApprovalSettingKey,
	// 故障处理与检测执行（批次 4，键名见 packages/shared-go/runtimeoptions；也可经语义设置入口写）
	"security_capacity_fail_mode", "mcp_policy_fail_mode", "retention_failure_mode",
	"output_security_mode", "output_strict_max_bytes", "upload_inspection_failure_action",
	"semantic_block_stages", "agent_security_monitor_disposition", "model_output_classified_disposition",
	guardrailFailClosedSettingKey, "confidence_gating_enabled", "confidence_threshold",
	// 正向代理出站（批次 3，egresspolicy.Keys）：校验、出站放宽审计（egress_override.enable）走通用链
	egresspolicy.KeyAllowPrivate, egresspolicy.KeyAllowLoopback, egresspolicy.KeyAllowMetadata,
	egresspolicy.KeyAllowedCIDRs, egresspolicy.KeyAllowedHosts, egresspolicy.KeyUnlistedAction, egresspolicy.KeyWhitelistFailMode,
}

var securityWritableSettingKeys = settingKeySet(securityWritableSettingKeyList)

func settingKeySet(keys []string) map[string]bool {
	set := make(map[string]bool, len(keys))
	for _, key := range keys {
		set[key] = true
	}
	return set
}

// UpdateSecuritySystemSettings 处理 PUT /admin/v1/security/system-settings：平台管理员与平台级安全员可写
// securityWritableSettingKeyList 里的键，白名单外一律 400，租户级账号、审计员 403。请求体与 /system/settings
// 相同的键值形式，只提交改动过的键，不带 expected_version；写入更新 updated_at，语义设置入口的
// config_version 随之推进，签名投影修订号按内容计算随之变化。写操作审计记本次改动键的前后值。
func UpdateSecuritySystemSettings(deps *Dependencies) http.HandlerFunc {
	return updateSettingsWithScope(deps, defaultSemanticJudgeNetwork(), systemSettingsScope{
		authorize:   func(user *repository.User) bool { return roles.CanManageSecurityPolicy(user.Role) },
		allowedKeys: securityWritableSettingKeys,
		auditAction: "update_security_system_settings",
		auditKeys:   securityWritableSettingKeyList,
		preflight: func(_ *http.Request, _ *Dependencies, user *repository.User, raw map[string]interface{}) (string, int, string, string) {
			if !roles.IsSystemAdmin(user.Role) && !isPlatformLevel(user) {
				return "", http.StatusForbidden, "global_config_requires_platform_level",
					"这项配置是全平台共享的，租户级账号不能修改；请使用平台级安全员或系统管理员账号"
			}
			if value, ok := raw[agentGuardAllowSelfApprovalSettingKey]; ok {
				switch v := value.(type) {
				case bool:
				case string:
					if v != "true" && v != "false" {
						return "", http.StatusBadRequest, "invalid_request", agentGuardAllowSelfApprovalSettingKey + " must be true or false"
					}
				default:
					return "", http.StatusBadRequest, "invalid_request", agentGuardAllowSelfApprovalSettingKey + " must be true or false"
				}
			}
			return "", 0, "", ""
		},
		auditDetail: func(before, after map[string]string, detail map[string]interface{}) {
			touched := map[string]string{}
			for key := range after {
				if value, ok := before[key]; ok {
					touched[key] = value
				}
			}
			detail["before"] = touched
			detail["after"] = after
		},
	})
}

// UpdateSystemSettings updates system settings
func UpdateSystemSettings(deps *Dependencies) http.HandlerFunc {
	return updateSystemSettingsWithSemanticNetwork(deps, defaultSemanticJudgeNetwork())
}

func updateSystemSettingsWithSemanticNetwork(deps *Dependencies, semanticNetwork semanticJudgeNetwork) http.HandlerFunc {
	return updateSettingsWithScope(deps, semanticNetwork, systemSettingsScope{
		authorize:   func(user *repository.User) bool { return user.Role == "platform_admin" },
		auditAction: "update_system_settings",
	})
}

// systemSettingsScope 限定一个写入入口能做什么：谁能调、能写哪些键、审计动作名。
// 全量入口 PUT /system/settings 不限键（allowedKeys 为 nil）；安全子集入口只允许白名单内的键，其余一律 400，
// 不是静默丢弃——调用方要能发现自己越界了。
type systemSettingsScope struct {
	authorize   func(*repository.User) bool
	allowedKeys map[string]bool
	auditAction string
	// beforeWrite 在白名单与格式校验之后、落库之前做角色相关的附加限制，返回非空 code 即以 403 拒绝。
	beforeWrite func(user *repository.User, raw map[string]interface{}) (code, message string)
	// stripBeforeValidate 返回需要在通用校验之前从请求体里取走的控制字段（如 expected_version），不会被当作设置键。
	stripBeforeValidate []string
	// beforeWriteCtx 与 beforeWrite 类似，但可访问请求上下文与依赖（查 provider、读原值），并且可以取走控制字段。
	// 返回 (httpStatus, code, message)；httpStatus 为 0 表示通过。
	// 通过时第二个返回值 token 会原样交给 commit（如调用者带回的 expected_version）。
	preflight func(r *http.Request, deps *Dependencies, user *repository.User, raw map[string]interface{}) (token string, status int, code, message string)
	// commit 替代 SetMultiple 落库（如带版本的原子比较并交换）；返回 (httpStatus, code, message)，0 表示成功。
	commit func(r *http.Request, deps *Dependencies, token string, settings map[string]string) (status int, code, message string)
	// auditDetail 允许调用方在写审计前改写明细（如补充变更前后值）；before 是写入前读到的原值。
	auditDetail func(before map[string]string, after map[string]string, detail map[string]interface{})
	// auditKeys 指定要读取原值用于审计的键。
	auditKeys []string
}

func updateSettingsWithScope(deps *Dependencies, semanticNetwork semanticJudgeNetwork, scope systemSettingsScope) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || !scope.authorize(user) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxSystemSettingsBodyBytes)
		var rawSettings map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&rawSettings); err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "request_too_large", "system settings request is too large")
				return
			}
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		var beforeValues map[string]string
		if len(scope.auditKeys) > 0 && deps != nil && deps.SystemRepo != nil {
			beforeValues = map[string]string{}
			for _, k := range scope.auditKeys {
				if st, err := deps.SystemRepo.Get(r.Context(), k); err == nil && st != nil {
					beforeValues[k] = st.Value
				}
			}
		}
		var preflightToken string
		if scope.preflight != nil {
			token, status, code, message := scope.preflight(r, deps, user, rawSettings)
			if status != 0 {
				writeErrorWithStatus(w, status, code, message)
				return
			}
			preflightToken = token
		}
		for _, k := range scope.stripBeforeValidate {
			delete(rawSettings, k)
		}
		if scope.allowedKeys != nil {
			var rejected []string
			for key := range rawSettings {
				if !scope.allowedKeys[key] {
					rejected = append(rejected, key)
				}
			}
			if len(rejected) > 0 {
				sort.Strings(rejected)
				writeErrorWithStatus(w, http.StatusBadRequest, "setting_not_allowed",
					"this endpoint cannot change: "+strings.Join(rejected, ", "))
				return
			}
		}
		if scope.beforeWrite != nil {
			if code, message := scope.beforeWrite(user, rawSettings); code != "" {
				writeErrorWithStatus(w, http.StatusForbidden, code, message)
				return
			}
		}

		for _, reserved := range []string{"security_execution_mode_managed", securityExecutionModeModifiedBySettingKey, securityExecutionModeModifiedAtSettingKey, executionModeBaselineKey} {
			if _, exists := rawSettings[reserved]; exists {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "security mode metadata is managed by the server")
				return
			}
		}
		requestedMode := ""
		changeReason := ""
		rawChangeReason, hasChangeReason := rawSettings[securityExecutionModeChangeReasonKey]
		if rawMode, ok := rawSettings[securityExecutionModeSettingKey]; ok {
			if len(rawSettings) != 1 && !(hasChangeReason && len(rawSettings) == 2) {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "security_execution_mode must be updated separately")
				return
			}
			if hasChangeReason {
				reason, ok := rawChangeReason.(string)
				reason = strings.TrimSpace(reason)
				if !ok || reason == "" || utf8.RuneCountInString(reason) > 500 {
					writeErrorWithStatus(w, http.StatusBadRequest, "invalid_change_reason", "change_reason must contain 1-500 characters")
					return
				}
				changeReason = reason
				delete(rawSettings, securityExecutionModeChangeReasonKey)
			}
			mode, ok := rawMode.(string)
			if !ok || (mode != securityExecutionModeRecord && mode != securityExecutionModeProtect) {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_security_execution_mode", "security_execution_mode must be record or protect")
				return
			}
			requestedMode = mode
			delete(rawSettings, securityExecutionModeSettingKey)
			rawSettings[securityAuditOnlySettingKey] = mode == securityExecutionModeRecord
		} else if hasChangeReason {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "change_reason is only accepted with security_execution_mode")
			return
		}
		if rawLegacy, ok := rawSettings[securityAuditOnlySettingKey]; ok {
			if requestedMode == "" {
				previous, err := deps.SystemRepo.Get(r.Context(), securityExecutionModeSettingKey)
				if err != nil {
					writeError(w, "internal_error", "failed to read security mode")
					return
				}
				if previous != nil && (previous.Value == "record" || previous.Value == "protect") {
					writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "use security_execution_mode to change the managed mode")
					return
				}
			}
			legacy, ok := rawLegacy.(bool)
			if !ok {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_security_execution_mode", "legacy security mode must be a boolean")
				return
			}
			// 旧键写入同时写成显式执行模式（2.9.22 审查第 9 项）：部署变量只在没有显式模式时
			// 作初值，只写旧键会出现“返回 200 却仍按部署变量记录”。
			if requestedMode == "" {
				requestedMode = securityExecutionModeProtect
				if legacy {
					requestedMode = securityExecutionModeRecord
				}
			}
		}

		oldConfiguredMode := securityExecutionModeRecord
		if requestedMode != "" {
			previous, err := deps.SystemRepo.GetAll(r.Context())
			if err != nil {
				writeError(w, "internal_error", "failed to read previous security mode")
				return
			}
			oldConfiguredMode = securityExecutionModeForSettings(r.Context(), deps, previous).ConfiguredMode
		}

		settings := make(map[string]string, len(rawSettings))
		for key, value := range rawSettings {
			switch v := value.(type) {
			case string:
				settings[key] = v
			case bool:
				settings[key] = strconv.FormatBool(v)
			case float64:
				settings[key] = strconv.FormatFloat(v, 'f', -1, 64)
			case nil:
				settings[key] = ""
			default:
				encoded, err := json.Marshal(v)
				if err != nil {
					writeError(w, "invalid_request", "invalid setting value")
					return
				}
				settings[key] = string(encoded)
			}
		}

		modeModifiedAt := ""
		if requestedMode != "" {
			settings[securityExecutionModeSettingKey] = requestedMode
			modeModifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
			settings[securityExecutionModeModifiedBySettingKey] = user.ID
			settings[securityExecutionModeModifiedAtSettingKey] = modeModifiedAt
		}

		if rawRetention, ok := settings["log_retention_days"]; ok {
			retentionDays, err := parseLogRetentionDays(rawRetention)
			if err != nil {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", logretention.ErrOutOfRange.Error())
				return
			}
			settings["log_retention_days"] = strconv.Itoa(retentionDays)
		}

		if err := normalizeGatewayPublicSettings(settings); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_gateway_address", err.Error())
			return
		}

		if err := normalizeAlertTTLSettings(settings); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		if err := normalizeBlockNoticeSettings(settings); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_block_notice", err.Error())
			return
		}

		if err := normalizeAIContentLabelSettings(settings); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_ai_content_label", err.Error())
			return
		}

		if err := normalizeResponseCacheSettings(settings); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_response_cache", err.Error())
			return
		}

		if err := prepareOutboundProxySetting(r.Context(), deps, settings); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_outbound_proxy", err.Error())
			return
		}

		if err := normalizePlatformEgressSettings(settings); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_egress_setting", err.Error())
			return
		}
		egressBefore := platformEgressSettingsBefore(r.Context(), deps, settings)

		if err := validateTier1ThresholdSettings(r.Context(), deps, settings); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_semantic_config", err.Error())
			return
		}

		if err := validateSemanticSettingValuesWithNetwork(r.Context(), settings, semanticNetwork); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_semantic_config", err.Error())
			return
		}

		if err := normalizeRuntimeSecuritySettings(settings); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_runtime_security_setting", err.Error())
			return
		}

		// judge_api_key 密钥三件套（spec §4）：落库前加密。前端仅在用户实际改动时提交此键，
		// 故收到非空明文即新填值；已加密(enc:v1:)的不重复加密。仅 special-case 这一个键。
		if rawKey, ok := settings["judge_api_key"]; ok {
			trimmed := strings.TrimSpace(rawKey)
			if trimmed != "" && !strings.HasPrefix(trimmed, encryptedSecretPrefix) {
				ciphertext, _, err := secrets.EncryptProviderSecret(trimmed)
				if err != nil {
					writeError(w, "internal_error", "failed to encrypt judge_api_key")
					return
				}
				settings["judge_api_key"] = ciphertext
			}
		}

		if scope.commit != nil {
			if status, code, message := scope.commit(r, deps, preflightToken, settings); status != 0 {
				writeErrorWithStatus(w, status, code, message)
				return
			}
		} else if err := deps.SystemRepo.SetMultiple(r.Context(), settings); err != nil {
			writeError(w, "internal_error", "failed to update settings")
			return
		}

		// Log audit —— judge_api_key 脱敏后再记录，绝不把明文/密文写进审计。
		auditDetail := make(map[string]interface{}, len(settings))
		for k, v := range settings {
			auditDetail[k] = v
		}
		if _, ok := auditDetail["judge_api_key"]; ok {
			auditDetail["judge_api_key"] = maskedSecretValue
		}
		if _, ok := auditDetail[outboundProxyURLSettingKey]; ok {
			auditDetail[outboundProxyURLSettingKey] = maskedSecretValue
		}
		if requestedMode != "" {
			delete(auditDetail, securityAuditOnlySettingKey)
			effectiveMode := requestedMode
			source := "admin_settings"
			delete(auditDetail, securityExecutionModeSettingKey)
			auditDetail["old_configured_mode"] = oldConfiguredMode
			auditDetail["new_configured_mode"] = requestedMode
			auditDetail["effective_mode"] = effectiveMode
			auditDetail["source"] = source
			auditDetail["last_modified_by"] = user.ID
			auditDetail["last_modified_at"] = modeModifiedAt
			delete(auditDetail, securityExecutionModeModifiedBySettingKey)
			delete(auditDetail, securityExecutionModeModifiedAtSettingKey)
			if changeReason != "" {
				auditDetail[securityExecutionModeChangeReasonKey] = changeReason
			}
		}
		if scope.auditDetail != nil {
			scope.auditDetail(beforeValues, settings, auditDetail)
		}
		logAudit(r, deps, scope.auditAction, auditDetail, "system", "settings")
		auditPlatformEgressLoosening(r, deps, egressBefore, settings)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "settings updated"})
	}
}

// ListAuditOperations returns paginated audit operations
func ListAuditOperations(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		limit := 100
		offset := 0
		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		if o := r.URL.Query().Get("offset"); o != "" {
			if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
				offset = parsed
			}
		}
		userID := r.URL.Query().Get("user_id")

		ops, total, err := deps.SystemRepo.ListAuditOperations(r.Context(), limit, offset, userID)
		if err != nil {
			writeError(w, "internal_error", "failed to list audit operations")
			return
		}

		data := make([]types.AuditOperationInfo, len(ops))
		for i, op := range ops {
			data[i] = types.AuditOperationInfo{
				ID:           op.ID,
				UserID:       op.UserID,
				ActionType:   op.ActionType,
				ActionDetail: op.ActionDetail,
				TargetType:   op.TargetType,
				TargetID:     op.TargetID,
				IPAddress:    op.IPAddress,
				CreatedAt:    op.CreatedAt.Format(time.RFC3339),
			}
		}

		resp := types.AuditOperationListResponse{Data: data, Total: total}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// validateTier1ThresholdSettings applies the smart-detection contract to the
// generic settings route, which accepts arbitrary keys and used to accept any
// value for the two tier1 thresholds. An empty value means "clear and fall back
// to the deployed default", so it is allowed and skips the numeric check.
func validateTier1ThresholdSettings(ctx context.Context, deps *Dependencies, settings map[string]string) error {
	lowRaw, hasLow := settings["tier1_low_threshold"]
	highRaw, hasHigh := settings["tier1_high_threshold"]
	if !hasLow && !hasHigh {
		return nil
	}
	stored := func(key string, fallback float64) float64 {
		if deps != nil && deps.SystemRepo != nil {
			if setting, err := deps.SystemRepo.Get(ctx, key); err == nil && setting != nil {
				if value, err := strconv.ParseFloat(strings.TrimSpace(setting.Value), 64); err == nil {
					return value
				}
			}
		}
		return fallback
	}
	low := stored("tier1_low_threshold", defaultTier1LowThreshold)
	high := stored("tier1_high_threshold", defaultTier1HighThreshold)
	// An empty value clears the setting, so the effective value becomes the
	// deployed default -- not whatever was stored before.
	if hasLow {
		value, err := tier1ThresholdValue("tier1_low_threshold", lowRaw, defaultTier1LowThreshold)
		if err != nil {
			return err
		}
		low = value
	}
	if hasHigh {
		value, err := tier1ThresholdValue("tier1_high_threshold", highRaw, defaultTier1HighThreshold)
		if err != nil {
			return err
		}
		high = value
	}
	if smartThresholdOutOfRange(low) || smartThresholdOutOfRange(high) {
		return fmt.Errorf("tier1_low_threshold and tier1_high_threshold must be between 0 and 1")
	}
	// The engine requires low < high; equal values make it reject the whole managed
	// semantic configuration and keep the previous runtime state.
	if low >= high {
		return fmt.Errorf("tier1_low_threshold must be lower than tier1_high_threshold")
	}
	// This route takes arbitrary keys, so nobody reads a warning here: the 2026-09-17
	// "0.0" went through it, switched the cascade off and cost a judge call per window
	// until someone diffed raw settings. Disabling the cascade is refused on this
	// route; the smart-detection configuration is the deliberate path and shows the
	// warning. Only a request that sets the lower bound is judged on it, so an old
	// value that is already stored never blocks changing the upper bound.
	if hasLow && low < tier1CascadeDisabledBelow {
		return fmt.Errorf("tier1_low_threshold below %.2f sends every window to the judge and disables the tier-1 cascade; set it deliberately in the smart-detection configuration", tier1CascadeDisabledBelow)
	}
	return nil
}

// tier1ThresholdDecimal is the plain decimal form the engine reads with Python
// float(). strconv.ParseFloat also accepts NaN, Inf, hex floats and underscores:
// those would be stored here and then make the engine refuse the whole managed
// semantic configuration, so every later console change silently stops applying.
var tier1ThresholdDecimal = regexp.MustCompile(`^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$`)

func tier1ThresholdValue(name, raw string, fallback float64) (float64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fallback, nil
	}
	if !tier1ThresholdDecimal.MatchString(trimmed) {
		return 0, fmt.Errorf("%s must be a number", name)
	}
	value, err := strconv.ParseFloat(trimmed, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, fmt.Errorf("%s must be a number", name)
	}
	return value, nil
}
