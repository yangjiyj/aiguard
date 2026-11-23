package repository

import (
	"encoding/json"
	"strings"
)

// SemanticJudgeComponent 是语义裁判（智能分析）能力的组件名。它产出的是概率性的
// 模型意见，拦不拦由策略单独的「智能分析命中时」决定，而不是策略的处置动作。
const SemanticJudgeComponent = "security-engine.semantic"

// 策略「智能分析命中时」的取值：缺省 audit（记录并告警）= 升级前的行为。
const (
	SemanticActionAudit   = "audit"
	SemanticActionBlock   = "block"
	SemanticActionObserve = "observe"
)

// IsSemanticJudgeCapability 判断能力是否由语义裁判执行。
func IsSemanticJudgeCapability(capability SecurityPolicyCapability) bool {
	return strings.TrimSpace(capability.Component) == SemanticJudgeComponent
}

// NormalizeSecurityPolicySemanticAction 空值视为 audit；其余只接受 audit/block/observe。
func NormalizeSecurityPolicySemanticAction(raw string) (string, error) {
	switch value := strings.TrimSpace(raw); value {
	case "", SemanticActionAudit:
		return SemanticActionAudit, nil
	case SemanticActionBlock, SemanticActionObserve:
		return value, nil
	default:
		return "", invalidSecurityPolicy("semantic_action must be audit, block or observe")
	}
}

// ParseSecurityPolicySemanticAction 从策略 scope 读取「智能分析命中时」；缺失或非法一律 audit，
// 绝不因为存储异常把语义意见升级为拦截。
func ParseSecurityPolicySemanticAction(scopeJSON []byte) string {
	var scope struct {
		SemanticAction string `json:"semantic_action"`
	}
	if len(scopeJSON) == 0 || json.Unmarshal(scopeJSON, &scope) != nil {
		return SemanticActionAudit
	}
	value, err := NormalizeSecurityPolicySemanticAction(scope.SemanticAction)
	if err != nil {
		return SemanticActionAudit
	}
	return value
}

// scopeWithSemanticAction 写入策略 scope；audit 是缺省值，删除键而不是写入，保持存量 scope 不变。
func scopeWithSemanticAction(scopeJSON []byte, raw string) ([]byte, error) {
	value, err := NormalizeSecurityPolicySemanticAction(raw)
	if err != nil {
		return nil, err
	}
	var scope map[string]any
	if len(scopeJSON) > 0 && json.Unmarshal(scopeJSON, &scope) != nil {
		return nil, invalidSecurityPolicy("policy scope is invalid")
	}
	if scope == nil {
		scope = map[string]any{}
	}
	if value == SemanticActionAudit {
		delete(scope, "semantic_action")
	} else {
		scope["semantic_action"] = value
	}
	return json.Marshal(scope)
}

// validateSemanticActionCapabilities：选拦截/仅记录必须绑定至少一个语义裁判能力，
// 选拦截时这些语义能力还必须允许 block。
func validateSemanticActionCapabilities(capabilities []SecurityPolicyCapability, action string) error {
	if action == SemanticActionAudit {
		return nil
	}
	semantic := 0
	for _, capability := range capabilities {
		if !IsSemanticJudgeCapability(capability) {
			continue
		}
		semantic++
		if action == SemanticActionBlock && !capabilityAllowsAction(capability, "block") {
			return invalidSecurityPolicy("semantic capability %s does not allow block", capability.Category)
		}
	}
	if semantic == 0 {
		return invalidSecurityPolicy("semantic_action requires at least one semantic analysis capability")
	}
	return nil
}
