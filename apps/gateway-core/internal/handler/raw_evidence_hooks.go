package handler

import (
	"context"
	"errors"
	"fmt"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// applyOutputSecurity 在原有输出安全检查（applyOutputSecurityCore）外加脱敏原文留证：
// 输出被脱敏改写，或整段回复被阻断时，另存一份加密原文。返回值与原函数逐项一致。
func (h *ChatCompletionsHandler) applyOutputSecurity(ctx context.Context, envelope *modelrouter.RequestEnvelope, requestMessages []Message, respBody []byte) ([]byte, *AuditResult, error) {
	secured, audit, err := h.applyOutputSecurityCore(ctx, envelope, requestMessages, respBody)
	switch {
	case err == nil && secured != nil:
		h.retainRawOutput(ctx, envelope, respBody, secured, audit, false)
	case outputBlockRetainsOriginal(ctx, err, audit):
		h.retainRawOutput(ctx, envelope, respBody, nil, audit, true)
	}
	return secured, audit, err
}

// outputTextBlockedError 表示回复正文因安全命中被阻断（错误文本与原先 fmt.Errorf 的完全一致）。
type outputTextBlockedError struct{ choice int }

func (e outputTextBlockedError) Error() string {
	return fmt.Sprintf("response blocked due to security findings in output choice %d", e.choice)
}

// outputBlockRetainsOriginal：只有正文因命中被阻断才按 blocked 留原文，与输入侧口径一致。
// 检测不可用（fail-closed）、严格模式超出完整检查预算、工具调用拦截、客户端断开都不是
// "内容命中阻断"，不留原文。
func outputBlockRetainsOriginal(ctx context.Context, err error, audit *AuditResult) bool {
	if err == nil || audit == nil || audit.OutputAction != "block" || clientGoneDuring(ctx, err) || isGuardrailDetectionUnavailable(err) {
		return false
	}
	if incomplete, _ := audit.ResponseMetadata["output_scan_incomplete"].(bool); incomplete {
		return false
	}
	var textBlocked outputTextBlockedError
	return errors.As(err, &textBlocked)
}

// installRedactionGapAlert 登记"脱敏响应还原不完整"告警的写出方：模型把占位符改得无法识别时，
// 每个请求写一条审计事件，管理员能在告警里发现这类请求。
func (h *ChatCompletionsHandler) installRedactionGapAlert(ctx context.Context) {
	if h == nil || h.auditWriter == nil {
		return
	}
	setRedactionGapSink(ctx, func(ctx context.Context, envelope *modelrouter.RequestEnvelope) {
		h.writeSecurityEvent(context.WithoutCancel(ctx), envelope, []SecurityFinding{{
			Type:               "redaction_restore",
			Category:           "redaction_restore_incomplete",
			Severity:           "low",
			Action:             "audit",
			RuleName:           "脱敏响应还原",
			MatchedTextPreview: "模型改写了脱敏标记，部分内容未能还原",
		}}, "security_audit", "脱敏响应还原不完整：模型输出里仍有本次请求的脱敏标记，未能还原为原值")
	})
}
