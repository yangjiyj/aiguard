package handler

import (
	"context"
	"fmt"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// streamInspectionFailure 把实时流扫描失败转成流的处置。客户端在扫描期间断开（Esc / 中断）
// 不是检测失败：不写 output_scan_incomplete 事件（incomplete 回调不调用）、不走 fail-closed，
// 返回包装 context.Canceled 的哨兵错误，由调用方既有的 ctx.Err() != nil 分支记 client_canceled。
// ctx 必须是原始请求 ctx。
func (h *ChatCompletionsHandler) streamInspectionFailure(ctx context.Context, err error, incomplete func(string) error) error {
	if clientGoneDuring(ctx, err) {
		return fmt.Errorf("%w: stream inspection", errClientGoneDuringSecurity)
	}
	if incomplete != nil {
		if recordingErr := incomplete(securityexit.FailureReason(err, "output_security_check_failed")); recordingErr != nil {
			return recordingErr
		}
	}
	outcome := securityexit.DecideWithPolicy(h.exitMode(ctx), "block", securityexit.FailureCause(err), guardrailPolicy(ctx, h.toolRiskClient))
	if outcome.Enforce {
		return fmt.Errorf("%w: %w: %w", errLiveStreamOutputBlocked, errGuardrailDetectionUnavailable, err)
	}
	return nil
}

func streamInspectionRejectionStatus(tracker *relay.CommitTracker) (string, int) {
	if tracker.State() == relay.CommitNotStarted {
		return "security_blocked", http.StatusServiceUnavailable
	}
	return "stream_aborted", http.StatusOK
}
