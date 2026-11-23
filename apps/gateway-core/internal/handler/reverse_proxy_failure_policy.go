package handler

import (
	"context"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

func (h *ReverseProxyHandler) reverseInspectionFailure(ctx context.Context, err error, reason string) reverseProxySecurityDecision {
	reason = securityexit.FailureReason(err, reason)
	err = securityexit.NewInspectionFailure(reason, err)
	outcome := securityexit.DecideWithPolicy(securityexit.ModeFromAuditOnly(h.securityAuditOnly(ctx)), "audit", securityexit.FailureCause(err), guardrailPolicy(ctx, h.runtimeConfigClient))
	return reverseProxySecurityDecision{Allowed: !outcome.Enforce, Action: outcome.Action, DetectionFailed: true, SemanticStatus: "incomplete", SemanticReason: securityexit.FailureReason(err, reason), RetryUnavailable: true}
}

func (h *ReverseProxyHandler) applyReverseInspectionPolicy(ctx context.Context, d reverseProxySecurityDecision) reverseProxySecurityDecision {
	mode := securityexit.ModeFromAuditOnly(h.securityAuditOnly(ctx))
	if d.RawAction == "" {
		d.RawAction = d.Action
	}
	if d.DetectionFailed || (d.SemanticStatus == "incomplete" && !securityexit.Blocks(d.Action)) {
		failure := h.reverseInspectionFailure(ctx, nil, d.SemanticReason)
		d.Action, d.Allowed = failure.Action, failure.Allowed
		d.DetectionFailed = true
		return d
	}
	if d.Stage == "output" && effectiveOutputSecurityMode(h.runtimeConfigClient, h.outputStreamConfig) == relay.OutputSecurityStreamAudit {
		mode = securityexit.Record
	}
	outcome := securityexit.DecideWithPolicy(mode, d.Action, securityexit.RuleHit, guardrailPolicy(ctx, h.runtimeConfigClient))
	d.Allowed, d.Action = !outcome.Enforce, outcome.Action
	return d
}
