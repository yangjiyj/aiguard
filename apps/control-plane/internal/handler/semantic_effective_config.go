package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/executionmode"
	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
)

const (
	defaultSemanticTotalTimeout = "9"
	defaultSemanticSampleRate   = "1"
	defaultJudgeTimeout         = "8"
	defaultTier1URL             = "http://tier1-classifier:8000/classify"
	defaultTier1Timeout         = "1"
	defaultSemanticTier1Low     = "0.30"
	defaultSemanticTier1High    = "0.70"
	defaultConfidenceThreshold  = "0.55"
	defaultTriageTotalBudget    = "8"
	// 语义拦截最低置信度：只有策略「智能分析命中时」选了拦截才会用到。
	defaultSemanticBlockMinConfidence = "0.85"
	semanticBlockMinConfidenceKey     = "semantic_block_min_confidence"
	semanticRevisionBytes             = 16
	semanticRevisionHexLength         = semanticRevisionBytes * 2
	semanticEngineComponent           = "security-engine"
	semanticGatewayComponent          = "gateway-core"
)

// guardrailFailClosedSettingKey is the explicit, audited console option that
// turns a detection failure into a 503 rejection in protect mode.
const guardrailFailClosedSettingKey = "guardrail_fail_closed_enabled"

var semanticGatewayProjectionKeys = []string{
	"semantic_enabled", "semantic_input_enabled", "semantic_agent_enabled", "security_audit_only",
	"file_content_dlp_enabled", "security_execution_mode_managed", guardrailFailClosedSettingKey,
	"inspect_user_input", "inspect_model_output", "inspect_builtin_context", "inspect_history", "inspect_tool_results",
}

// Scope applies to every detector, independently of semantic stage switches.
var inspectionScopeDefaults = map[string]bool{
	"inspect_user_input": true, "inspect_model_output": true,
	"inspect_builtin_context": false, "inspect_history": false, "inspect_tool_results": true,
}

var semanticCoreBoolKeys = []string{
	"semantic_enabled",
	"semantic_input_enabled",
	"semantic_agent_enabled",
	"semantic_output_enabled",
}

var semanticOptionalBoolKeys = []string{
	"tier1_enabled",
	"fp_suppression_enabled",
	"source_aware_enabled",
	"confidence_gating_enabled",
	"coding_traffic_downgrade_enabled",
	"file_content_dlp_enabled",
}

var semanticOptionalBoolDefaults = map[string]bool{
	"tier1_enabled":                    true,
	"source_aware_enabled":             true,
	"confidence_gating_enabled":        true,
	"coding_traffic_downgrade_enabled": true,
}

var semanticEngineProjectionKeys = []string{
	"revision", "security_audit_only",
	"semantic_enabled", "semantic_input_enabled", "semantic_agent_enabled", "semantic_output_enabled",
	"tier1_enabled", "fp_suppression_enabled", "source_aware_enabled",
	"confidence_gating_enabled", "coding_traffic_downgrade_enabled",
	"judge_backend", "judge_url", "judge_model", "judge_api_key", "judge_timeout", "judge_allow_private_egress",
	"semantic_total_timeout", "semantic_sample_rate",
	"tier1_url", "tier1_timeout", "tier1_low_threshold", "tier1_high_threshold",
	"confidence_threshold", "triage_total_budget", semanticBlockMinConfidenceKey,
	"inspect_user_input", "inspect_model_output", "inspect_builtin_context", "inspect_history", "inspect_tool_results",
}

var semanticOptionalNumberKeys = []string{
	"tier1_low_threshold",
	"tier1_high_threshold",
}

func semanticBool(settings map[string]string, key string, fallback bool) bool {
	raw, ok := settings[key]
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback
	}
	return strings.EqualFold(strings.TrimSpace(raw), "true")
}

type semanticComponentConfigs struct {
	Engine          map[string]any
	Gateway         map[string]any
	EngineRevision  string
	GatewayRevision string
}

type semanticDesiredRevisions struct {
	Engine              string `json:"security-engine"`
	Gateway             string `json:"gateway-core"`
	EngineJudgeRequired bool   `json:"-"`
}

func semanticCanonicalPayload(config map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(config))
	for name := range config {
		if name != "revision" {
			keys = append(keys, name)
		}
	}
	sort.Strings(keys)
	var payload bytes.Buffer
	for _, name := range keys {
		_, _ = fmt.Fprintf(&payload, "%d:%s=", len([]byte(name)), name)
		switch value := config[name].(type) {
		case bool:
			if value {
				payload.WriteString("b:1;")
			} else {
				payload.WriteString("b:0;")
			}
		case string:
			raw := []byte(value)
			_, _ = fmt.Fprintf(&payload, "s:%d:", len(raw))
			_, _ = payload.Write(raw)
			payload.WriteByte(';')
		default:
			return nil, fmt.Errorf("semantic config field %s has unsupported type", name)
		}
	}
	return payload.Bytes(), nil
}

func semanticConfigRevision(component string, config map[string]any, key []byte) (string, error) {
	if component != semanticEngineComponent && component != semanticGatewayComponent {
		return "", errors.New("invalid semantic component")
	}
	if len(key) < 16 {
		return "", errors.New("semantic revision key is unavailable")
	}
	payload, err := semanticCanonicalPayload(config)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("jjdguard:semantic-config:" + component + "\n"))
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)[:semanticRevisionBytes]), nil
}

func semanticRevisionKey(deps *Dependencies) ([]byte, error) {
	if deps == nil {
		return nil, errors.New("semantic dependencies are unavailable")
	}
	key := deps.RulePackAttestationTokens[semanticConfigTenant]
	if len(key) < 16 {
		return nil, errors.New("semantic revision key is unavailable")
	}
	return []byte(key), nil
}

func semanticGatewayRevisionKey(deps *Dependencies) ([]byte, error) {
	if deps == nil || len(deps.SemanticGatewayAttestationKey) < 16 {
		return nil, errors.New("semantic gateway revision key is unavailable")
	}
	return []byte(deps.SemanticGatewayAttestationKey), nil
}

func buildSemanticEngineProjection(ctx context.Context, deps *Dependencies) (map[string]any, error) {
	if deps == nil || deps.SystemRepo == nil {
		return nil, errors.New("semantic settings source is unavailable")
	}
	settings, err := deps.SystemRepo.GetAll(ctx)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(settings))
	for _, setting := range settings {
		values[setting.Key] = setting.Value
	}

	out := map[string]any{}
	for key, fallback := range inspectionScopeDefaults {
		out[key] = semanticBool(values, key, fallback)
	}
	for _, key := range semanticCoreBoolKeys {
		if key == "semantic_output_enabled" {
			// 越狱、指令覆盖等语义攻击属于输入意图。输出侧继续执行
			// PII、密钥、文件与内容安全检测，但绝不运行输入攻击裁判。
			out[key] = false
			continue
		}
		out[key] = semanticBool(values, key, true)
	}
	auditOnly, modeSource := executionmode.FromValues(values, executionmode.DeploymentRecordInitialValue())
	if modeSource == executionmode.SourceAdminSettings {
		out["security_execution_mode_managed"] = true
	}
	out[securityAuditOnlySettingKey] = auditOnly
	addRuntimeSecurityProjection(values, out)

	for _, key := range semanticOptionalBoolKeys {
		fallback := semanticOptionalBoolDefaults[key]
		if key == fileContentDLPSettingKey {
			fallback = fileContentDLPEnvFallback()
		}
		out[key] = semanticBool(values, key, fallback)
	}
	// Explicit fail-closed option for detection failures (gateway projection
	// only; the gateway honours it in protect mode). Missing key = false.
	out[guardrailFailClosedSettingKey] = semanticBool(values, guardrailFailClosedSettingKey, false)
	out["judge_allow_private_egress"] = semanticBool(values, "judge_allow_private_egress", false)
	// 正向代理防跳板出站设置只下发给网关（见 buildSemanticComponentConfigs）。
	addForwardProxyGatewayProjection(out, values)
	out["semantic_total_timeout"] = defaultSemanticTotalTimeout
	if raw := strings.TrimSpace(values["semantic_total_timeout"]); raw != "" {
		out["semantic_total_timeout"] = raw
	}
	out["semantic_sample_rate"] = defaultSemanticSampleRate
	if raw := strings.TrimSpace(values["semantic_sample_rate"]); raw != "" {
		out["semantic_sample_rate"] = raw
	}
	numberDefaults := map[string]string{
		"tier1_low_threshold":  defaultSemanticTier1Low,
		"tier1_high_threshold": defaultSemanticTier1High,
	}
	for _, key := range semanticOptionalNumberKeys {
		out[key] = numberDefaults[key]
		if raw := strings.TrimSpace(values[key]); raw != "" {
			out[key] = raw
		}
	}
	for key, fallback := range map[string]string{
		"judge_timeout":        defaultJudgeTimeout,
		"tier1_timeout":        defaultTier1Timeout,
		"confidence_threshold": defaultConfidenceThreshold,
		"triage_total_budget":  defaultTriageTotalBudget,
	} {
		out[key] = fallback
		if raw := strings.TrimSpace(values[key]); raw != "" {
			out[key] = raw
		}
	}
	// 存量库里若有越界/非法值，下发默认值而不是让引擎整份配置校验失败。
	out[semanticBlockMinConfidenceKey] = defaultSemanticBlockMinConfidence
	if raw := strings.TrimSpace(values[semanticBlockMinConfidenceKey]); raw != "" {
		if value, err := strconv.ParseFloat(raw, 64); err == nil && value >= 0.5 && value <= 1 {
			out[semanticBlockMinConfidenceKey] = raw
		}
	}
	// Tier-1 是随产品交付的固定 sidecar，不接受数据库或 API 配置任意出站地址。
	out["tier1_url"] = defaultTier1URL

	backendName := strings.TrimSpace(values["judge_backend"])
	if backendName == "" {
		backendName = "bundled"
	}
	values["judge_backend"] = backendName
	out["judge_backend"] = backendName

	providers := map[string]*resolvedProvider{}
	if backendName == "provider" {
		providerID := strings.TrimSpace(values["judge_provider_id"])
		if providerID != "" && deps.ProviderRepo != nil {
			if provider, providerErr := deps.ProviderRepo.GetByID(ctx, semanticConfigTenant, providerID); providerErr == nil && provider != nil {
				key := ""
				if credential, credentialErr := deps.ProviderRepo.GetCredential(ctx, providerID); credentialErr == nil && credential != nil {
					key = decryptProviderKey(credential.SecretCiphertext)
				}
				providers[providerID] = &resolvedProvider{
					BaseURL: provider.BaseURL,
					Model:   strings.TrimSpace(values["judge_model"]),
					APIKey:  key,
				}
			}
		}
	}
	backend := resolveJudgeBackend(values, providers, decryptProviderKey)
	out["judge_url"] = backend.URL
	out["judge_model"] = backend.Model
	out["judge_api_key"] = backend.APIKey
	return out, nil
}

func buildSemanticComponentConfigs(ctx context.Context, deps *Dependencies) (semanticComponentConfigs, error) {
	engine, err := buildSemanticEngineProjection(ctx, deps)
	if err != nil {
		return semanticComponentConfigs{}, err
	}
	engineKey, err := semanticRevisionKey(deps)
	if err != nil {
		return semanticComponentConfigs{}, err
	}
	gatewayKey, err := semanticGatewayRevisionKey(deps)
	if err != nil {
		return semanticComponentConfigs{}, err
	}
	gateway := make(map[string]any, len(semanticGatewayProjectionKeys)+1)
	for _, name := range semanticGatewayProjectionKeys {
		if value, ok := engine[name]; ok {
			gateway[name] = value
		}
	}
	// The fail-closed option is a gateway-only decision input.
	delete(engine, guardrailFailClosedSettingKey)
	splitRuntimeSecurityProjection(engine, gateway)
	for _, name := range egresspolicy.Keys {
		if value, ok := engine[name]; ok {
			gateway[name] = value
			delete(engine, name)
		}
	}
	engineRevision, err := semanticConfigRevision(semanticEngineComponent, engine, engineKey)
	if err != nil {
		return semanticComponentConfigs{}, err
	}
	gatewayRevision, err := semanticConfigRevision(semanticGatewayComponent, gateway, gatewayKey)
	if err != nil {
		return semanticComponentConfigs{}, err
	}
	engine["revision"] = engineRevision
	gateway["revision"] = gatewayRevision
	return semanticComponentConfigs{
		Engine: engine, Gateway: gateway,
		EngineRevision: engineRevision, GatewayRevision: gatewayRevision,
	}, nil
}

func buildInternalSemanticConfig(ctx context.Context, deps *Dependencies) (map[string]any, error) {
	configs, err := buildSemanticComponentConfigs(ctx, deps)
	if err != nil {
		return nil, err
	}
	return configs.Engine, nil
}

func verifySemanticEngineAttestation(deps *Dependencies, r *http.Request) (int, string) {
	if strings.TrimSpace(r.Header.Get("X-Tenant-ID")) != semanticConfigTenant {
		return http.StatusUnauthorized, rulePackAttestationInvalidCode
	}
	return verifyRulePackAttestation(deps, semanticConfigTenant, r.Header.Get(rulePackAttestationHeader))
}

func GetInternalSemanticEngineConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if status, code := verifySemanticEngineAttestation(deps, r); status != 0 {
			writeErrorWithStatus(w, status, code, "semantic engine attestation failed")
			return
		}
		configs, err := buildSemanticComponentConfigs(r.Context(), deps)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "semantic_config_unavailable", "semantic configuration is unavailable")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		writeAgentGuardJSON(w, configs.Engine)
	}
}

func GetInternalSemanticGatewayConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configs, err := buildSemanticComponentConfigs(r.Context(), deps)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "semantic_config_unavailable", "semantic configuration is unavailable")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		writeAgentGuardJSON(w, configs.Gateway)
	}
}

func LegacySemanticConfigGone() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeErrorWithStatus(w, http.StatusGone, "semantic_config_endpoint_retired", "use a component-scoped semantic configuration endpoint")
	}
}
