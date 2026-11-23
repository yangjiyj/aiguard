// Package runtimeoptions 是故障处理与检测执行设置（system_settings，2.9.22 契约 2.2 节）的
// 键名、取值和范围的唯一定义。控制面写入校验、签名投影，网关解析，独立代理读取投影都用它。
//
// 这些键在投影里一律是字符串；只在库里存了且合法时下发，没下发时各组件取自己的缺省
// （网关、独立代理用原环境变量作初值）。
package runtimeoptions

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	SecurityCapacityFailMode         = "security_capacity_fail_mode"
	MCPPolicyFailMode                = "mcp_policy_fail_mode"
	RetentionFailureMode             = "retention_failure_mode"
	OutputSecurityMode               = "output_security_mode"
	OutputStrictMaxBytes             = "output_strict_max_bytes"
	UploadInspectionFailureAction    = "upload_inspection_failure_action"
	SemanticBlockStages              = "semantic_block_stages"
	AgentSecurityMonitorDisposition  = "agent_security_monitor_disposition"
	ModelOutputClassifiedDisposition = "model_output_classified_disposition"
)

// 缓冲严格模式的上限范围，与网关 GATEWAY_OUTPUT_STRICT_MAX_BYTES 一致。
const (
	MinOutputStrictMaxBytes = 1024
	MaxOutputStrictMaxBytes = 64 << 20
)

var choices = map[string][]string{
	SecurityCapacityFailMode:         {"open", "closed"},
	MCPPolicyFailMode:                {"open", "closed"},
	RetentionFailureMode:             {"open", "closed"},
	OutputSecurityMode:               {"stream_enforce", "strict_buffered", "stream_audit"},
	UploadInspectionFailureAction:    {"forward_alert", "block"},
	AgentSecurityMonitorDisposition:  {"observe", "follow_policy"},
	ModelOutputClassifiedDisposition: {"observe", "follow_policy"},
}

// semanticBlockStageOrder 是智能分析拦截阶段的规范顺序。
var semanticBlockStageOrder = []string{"input", "agent", "output"}

// GatewayKeys 只下发给网关（独立代理共用网关投影）；EngineKeys 只下发给引擎。
func GatewayKeys() []string {
	return []string{SecurityCapacityFailMode, MCPPolicyFailMode, RetentionFailureMode,
		OutputSecurityMode, OutputStrictMaxBytes, UploadInspectionFailureAction}
}

func EngineKeys() []string {
	return []string{SemanticBlockStages, AgentSecurityMonitorDisposition, ModelOutputClassifiedDisposition}
}

func IsGatewayKey(key string) bool { return contains(GatewayKeys(), key) }
func IsEngineKey(key string) bool  { return contains(EngineKeys(), key) }

func contains(list []string, key string) bool {
	for _, item := range list {
		if item == key {
			return true
		}
	}
	return false
}

// Normalize 校验并规范化一个键的取值；不认识的键或取值返回错误。
func Normalize(key, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	switch key {
	case OutputStrictMaxBytes:
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < MinOutputStrictMaxBytes || parsed > MaxOutputStrictMaxBytes {
			return "", fmt.Errorf("%s must be an integer between %d and %d", key, MinOutputStrictMaxBytes, MaxOutputStrictMaxBytes)
		}
		return strconv.Itoa(parsed), nil
	case SemanticBlockStages:
		return normalizeSemanticBlockStages(value)
	}
	allowed, ok := choices[key]
	if !ok {
		return "", fmt.Errorf("%s is not a runtime security option", key)
	}
	if !contains(allowed, value) {
		return "", fmt.Errorf("%s must be one of %s", key, strings.Join(allowed, ", "))
	}
	return value, nil
}

// normalizeSemanticBlockStages：非空 JSON 字符串数组，元素取 input/agent/output 且不重复，按规范顺序输出。
func normalizeSemanticBlockStages(raw string) (string, error) {
	var stages []string
	if err := json.Unmarshal([]byte(raw), &stages); err != nil || len(stages) == 0 {
		return "", fmt.Errorf("%s must be a non-empty JSON array of input, agent, output", SemanticBlockStages)
	}
	seen := map[string]bool{}
	for _, stage := range stages {
		if !contains(semanticBlockStageOrder, stage) || seen[stage] {
			return "", fmt.Errorf("%s must be a non-empty JSON array of input, agent, output", SemanticBlockStages)
		}
		seen[stage] = true
	}
	ordered := make([]string, 0, len(stages))
	for _, stage := range semanticBlockStageOrder {
		if seen[stage] {
			ordered = append(ordered, stage)
		}
	}
	encoded, _ := json.Marshal(ordered)
	return string(encoded), nil
}
