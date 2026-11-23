package handler

import (
	"context"
	"encoding/json"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// confirmationReplayer 是 ConfirmationReplayer 的兼容实现：HITL 批准后，
// 只记录“已批准、等待客户端重试”，不声称本地工具已经执行。
//
// 设计取向（沿用「改造建议优先暴露/串接现有功能，而非新建模块」）：
// 非 MCP 本地工具没有中心执行通道，因此复用 ToolCallLogRepo.Create 留下
// invocation_proposed 证据并产出 tool_log_id；真实执行必须由后续可信事件证明。
type confirmationReplayer struct {
	toolCallLogRepo toolCallLogCreator
}

type toolCallLogCreator interface {
	Create(context.Context, *repository.ToolCallLog) error
}

// NewConfirmationReplayer 构造生产用的确认重放器。
func NewConfirmationReplayer(repo *repository.ToolCallLogRepository) ConfirmationReplayer {
	return &confirmationReplayer{toolCallLogRepo: repo}
}

// ReplayConfirmation 取出确认中持久化的原始调用上下文，记录批准事实并返回
// 新生成的 tool_log_id。它不会调用工具，也不会写 execution_observed=true。
func (rp *confirmationReplayer) ReplayConfirmation(ctx context.Context, c *repository.AgentGuardConfirmation) (string, error) {
	params := parseReplayArguments(c.ToolCallArguments)

	logEntry := &repository.ToolCallLog{
		RequestID:             c.RequestID,
		TenantID:              c.TenantID,
		ToolName:              c.ToolName,
		ToolType:              "agentguard-replay",
		RiskLevel:             "high",
		Parameters:            params,
		Result:                "human approved; client retry required; execution not observed",
		Status:                "audited",
		RawDecision:           "confirm",
		EffectiveDecision:     "allow",
		EffectiveReason:       "human approved; execution awaits client retry",
		TraceID:               c.TraceID,
		Provenance:            "agentguard_confirmation_replay",
		EventKind:             "confirmation_replay",
		ExecutionObserved:     false,
		ResultObserved:        false,
		ToolCallID:            c.ToolCallID,
		AttributionMode:       "explicit",
		AttributionConfidence: 1,
	}

	if err := rp.toolCallLogRepo.Create(ctx, logEntry); err != nil {
		return "", err
	}
	return logEntry.ID, nil
}

// parseReplayArguments 把原始工具调用参数（JSON 文本）解析为参数表；
// 若不是 JSON 对象（空串、数组、标量等），回退为 {"raw_arguments": <原文>}，
// 保证重放记录始终带上可审计的原始入参。
func parseReplayArguments(raw string) map[string]interface{} {
	if raw == "" {
		return map[string]interface{}{}
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &obj); err == nil && obj != nil {
		return obj
	}
	return map[string]interface{}{"raw_arguments": raw}
}
