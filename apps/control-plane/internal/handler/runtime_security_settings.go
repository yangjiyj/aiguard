package handler

// 故障处理与检测执行设置（2.9.22 契约 2.2 节）。键名、取值和范围的唯一定义在
// packages/shared-go/runtimeoptions，控制面、网关、独立代理共用。
//
// 这些键存在全局 system_settings，平台管理员和安全员经语义设置专用入口写（与
// roles.CanManageSecurityPolicy 一致，写操作审计），经签名投影下发：
//   - 网关专用键只进网关投影；引擎专用键只进引擎投影；
//   - 只下发库里存了且合法的键。未存时组件取自己的缺省，网关侧原环境变量
//     （SECURITY_CAPACITY_FAIL_CLOSED、MCP_POLICY_FAIL_MODE、RETENTION_FAILURE_MODE、
//     GATEWAY_OUTPUT_SECURITY_MODE、GATEWAY_OUTPUT_STRICT_MAX_BYTES）只在这时作初值。

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/runtimeoptions"
)

// uploadInspectionFailureActionKey 门户上传入口自己也要读（portal_upload_ingest.go）。
const uploadInspectionFailureActionKey = runtimeoptions.UploadInspectionFailureAction

// runtimeSecurityWritableKeys 由语义设置专用入口写入（平台管理员、平台级安全员），写操作的
// 审计会记这些键的前值。guardrail_fail_closed_enabled、confidence_gating_enabled、
// confidence_threshold 是已有键，2.9.22 起安全员也能改（设计 D8）。这些键也直接列在
// semanticSettingsWritableKeys 与 securityOfficerSettingKeys 的声明里。
var runtimeSecurityWritableKeys = append(append(runtimeoptions.GatewayKeys(), runtimeoptions.EngineKeys()...),
	guardrailFailClosedSettingKey, "confidence_gating_enabled", "confidence_threshold")

func isRuntimeSecurityOption(key string) bool {
	return runtimeoptions.IsGatewayKey(key) || runtimeoptions.IsEngineKey(key)
}

// normalizeRuntimeSecuritySettings 在落库前校验并规范化本组键（两个写入口共用）。
func normalizeRuntimeSecuritySettings(settings map[string]string) error {
	for key, raw := range settings {
		if !isRuntimeSecurityOption(key) {
			continue
		}
		value, err := runtimeoptions.Normalize(key, raw)
		if err != nil {
			return err
		}
		settings[key] = value
	}
	if raw, ok := settings["confidence_threshold"]; ok {
		value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil || value != value || value < 0 || value > 1 {
			return fmt.Errorf("confidence_threshold must be between 0 and 1")
		}
	}
	return nil
}

// addRuntimeSecurityProjection 把库里存了且合法的键放进投影；非法存量值不下发，
// 组件取缺省，免得一个坏值让整份签名配置校验失败。
func addRuntimeSecurityProjection(values map[string]string, out map[string]any) {
	for _, key := range append(runtimeoptions.GatewayKeys(), runtimeoptions.EngineKeys()...) {
		raw, ok := values[key]
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		if value, err := runtimeoptions.Normalize(key, raw); err == nil {
			out[key] = value
		}
	}
}

// splitRuntimeSecurityProjection 把网关专用键从引擎投影挪到网关投影，引擎专用键从网关投影删掉。
func splitRuntimeSecurityProjection(engine, gateway map[string]any) {
	for _, key := range runtimeoptions.GatewayKeys() {
		if value, ok := engine[key]; ok {
			gateway[key] = value
			delete(engine, key)
		}
	}
	for _, key := range runtimeoptions.EngineKeys() {
		delete(gateway, key)
	}
}
