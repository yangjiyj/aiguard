package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type chatInputSecurityResult struct {
	reply       *SecurityReplyResult
	errorCode   string
	auditStatus string
	httpStatus  int
	message     string
	err         error
	// observedAction 是输入侧实际执行的最强非终止动作（mask/audit，空=未命中），
	// 仅用于成功路径的 X-Security-Action 陈述头，不参与任何动作决策。
	observedAction string
}

func (h *ChatCompletionsHandler) applyChatInputSecurity(ctx context.Context, envelope *modelrouter.RequestEnvelope, req *ChatCompletionRequest) chatInputSecurityResult {
	h.logToolResultObservations(ctx, envelope, req.Messages)
	h.recordToolResultFailures(ctx, envelope, req.Messages)
	if h.toolRiskClient != nil && len(req.Tools) > 0 {
		if err := h.checkToolRisk(ctx, envelope, req); err != nil {
			return chatInputSecurityResult{
				errorCode:   "tool_blocked",
				auditStatus: "tool_blocked",
				httpStatus:  http.StatusForbidden,
				message:     err.Error(),
				err:         err,
			}
		}
	}

	h.installRedactionGapAlert(ctx)
	rawCtx, rawCollector := withRawEvidenceCollector(ctx)
	rawBefore := snapshotRawInputForInspection(req)
	observed, err := h.applyInputSecurity(rawCtx, envelope, req)
	// 脱敏原文留证：只留证，不改变转发内容；客户端断开与检测不可用不是阻断。
	h.retainRawInput(ctx, envelope, rawBefore, req.Messages, err != nil && !clientGoneDuring(ctx, err) && !isGuardrailDetectionUnavailable(err), rawCollector)
	if err != nil {
		var replyErr *securityReplyError
		if errors.As(err, &replyErr) {
			return chatInputSecurityResult{reply: &SecurityReplyResult{
				Content:      replyErr.content,
				Findings:     replyErr.findings,
				MessageIndex: replyErr.messageIndex,
			}}
		}
		// 客户端在输入扫描期间已断开：先于 fail-closed / 阻断分类判定，按 client_canceled 收尾。
		if clientGoneDuring(ctx, err) {
			return chatInputSecurityResult{
				errorCode:   "request_canceled",
				auditStatus: "client_canceled",
				httpStatus:  http.StatusRequestTimeout,
				message:     "request was canceled",
				err:         err,
			}
		}
		if isGuardrailDetectionUnavailable(err) {
			return chatInputSecurityResult{
				errorCode:   guardrailDetectionUnavailableCode,
				auditStatus: "security_blocked",
				httpStatus:  http.StatusServiceUnavailable,
				message:     err.Error(),
				err:         err,
			}
		}
		return chatInputSecurityResult{
			errorCode:   "security_blocked",
			auditStatus: "security_blocked",
			httpStatus:  http.StatusForbidden,
			message:     err.Error(),
			err:         err,
		}
	}

	return chatInputSecurityResult{observedAction: observed}
}

func (h *ChatCompletionsHandler) secureChatOutput(ctx context.Context, envelope *modelrouter.RequestEnvelope, messages []Message, respBody []byte) ([]byte, *AuditResult, error) {
	return h.applyOutputSecurity(ctx, envelope, messages, respBody)
}
