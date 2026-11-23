package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
	"strings"
)

// Tool arguments are output data too. AgentGuard evaluates the proposed action;
// it does not replace output DLP on the data sent to the tool.
func (h *ChatCompletionsHandler) secureOutputToolArguments(ctx context.Context, envelope *modelrouter.RequestEnvelope, call ToolCall, index int, audit *AuditResult) (ToolCall, error) {
	if h.securityClient == nil || call.Function.Arguments == "" {
		return call, nil
	}
	// tool_may_egress 用送检前的原始参数算（不是脱敏后的）。
	projected := withOutputToolArgumentsProjection(ctx, call.Function.Name, outputToolCallMayEgress(call))
	action, masked, findings, err := h.checkOutputWithStatus(projected, envelope, call.Function.Arguments, index, audit)
	outputCtx := withSecurityEventStage(ctx, "output")
	if err != nil {
		// 客户端在工具参数扫描期间断开（Esc / 中断）：不是检测失败。不标 output_scan_incomplete，
		// 不写 security_output_check_failed，不走 fail-closed；交给调用方的 client_canceled 分支收尾。
		if clientGoneDuring(ctx, err) {
			return call, fmt.Errorf("%w: tool call %d arguments", errClientGoneDuringSecurity, index)
		}
		if audit.ResponseMetadata == nil {
			audit.ResponseMetadata = map[string]interface{}{}
		}
		audit.ResponseMetadata["output_scan_incomplete"] = true
		audit.ResponseMetadata["output_scan_incomplete_reason"] = "tool_output_check_failed"
		if h.auditWriter != nil {
			h.writeSecurityEvent(outputCtx, envelope, nil, "security_output_check_failed", "tool argument output check failed")
		}
		// A failed inspection is a coverage gap unless the explicit fail-closed
		// option applies (protect mode only).
		failure := securityexit.DecideWithPolicy(h.exitMode(ctx), "block", securityexit.FailureCause(err), guardrailPolicy(ctx, h.toolRiskClient))
		audit.OutputAction = failure.Action
		if failure.Enforce {
			return call, fmt.Errorf("%w: tool call %d arguments", errGuardrailDetectionUnavailable, index)
		}
		return call, nil
	}
	for _, item := range securityFindingsToAuditMaps(findings) {
		item["choice_index"] = index
		item["tool_call_id"] = call.ID
		item["output_field"] = "tool_arguments"
		audit.OutputFindings = append(audit.OutputFindings, item)
	}
	action = strings.ToLower(strings.TrimSpace(action))
	outputMode := h.outputExitMode(ctx)
	if outputMode == securityexit.Record {
		if action == "mask" || securityexit.Blocks(action) || hasSecurityFindings(findings) {
			audit.OutputAction = "audit"
			if h.auditWriter != nil {
				h.writeSecurityEvent(outputCtx, envelope, findings, "security_audit_only", "tool arguments matched output security policy")
			}
		}
		return call, nil
	}
	if action == "mask" {
		if masked == "" || !json.Valid([]byte(masked)) {
			// Masking would corrupt the tool-call JSON. The configured action
			// is "mask", not "block": forward the original and raise an alert.
			audit.OutputAction = strongerSecurityAction(audit.OutputAction, "audit")
			if h.auditWriter != nil {
				h.writeSecurityEvent(withMaskUnavailable(outputCtx), envelope, findings, "security_audit", "tool arguments could not be safely masked; forwarded unmasked")
			}
			return call, nil
		} else {
			call.Function.Arguments = masked
			audit.OutputAction = strongerSecurityAction(audit.OutputAction, "mask")
			if h.auditWriter != nil {
				h.writeSecurityEvent(outputCtx, envelope, findings, "security_masked", "tool arguments masked before forwarding")
			}
		}
	}
	if securityexit.Decide(outputMode, action, securityexit.RuleHit).Enforce {
		audit.OutputAction = "block"
		if h.auditWriter != nil {
			h.writeSecurityEvent(outputCtx, envelope, findings, "security_blocked", "tool arguments blocked before forwarding")
		}
		return call, fmt.Errorf("tool arguments blocked by output security policy")
	}
	return call, nil
}
