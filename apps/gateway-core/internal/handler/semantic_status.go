package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

type semanticStatusContext struct {
	Diagnostics []map[string]interface{}
	Status      string
	Reason      string
}

type semanticStatusCtxKey struct{}

func withSemanticStatus(ctx context.Context, status, reason string) context.Context {
	switch status {
	case "completed", "incomplete", "skipped", "not_requested":
		return context.WithValue(ctx, semanticStatusCtxKey{}, semanticStatusContext{
			Status: status,
			Reason: reason,
		})
	default:
		return ctx
	}
}

func semanticStatusFromContext(ctx context.Context) (semanticStatusContext, bool) {
	if ctx == nil {
		return semanticStatusContext{}, false
	}
	status, ok := ctx.Value(semanticStatusCtxKey{}).(semanticStatusContext)
	if !ok || status.Status == "" {
		return semanticStatusContext{}, false
	}
	return status, true
}

func annotateSemanticStatus(ctx context.Context, matchedSummary map[string]interface{}) {
	status, ok := semanticStatusFromContext(ctx)
	if !ok {
		return
	}
	matchedSummary["semantic_status"] = status.Status
	if len(status.Diagnostics) > 0 {
		matchedSummary["semantic_diagnostics"] = status.Diagnostics
	}
	if status.Reason != "" {
		matchedSummary["semantic_reason"] = status.Reason
	}
}

func semanticStatusFromFindings(findings []SecurityFinding) (string, string) {
	for _, finding := range findings {
		if finding.Type != "semantic_telemetry" {
			continue
		}
		reason, _ := finding.Triage["semantic_reason"].(string)
		if reason == "" {
			reason = finding.Category
		}
		return "incomplete", reason
	}
	for _, finding := range findings {
		if finding.Type == "semantic_attack" {
			return "completed", ""
		}
	}
	return "", ""
}

// Detailed output is optional so existing external checkers retain their contract.
type detailedOutputChecker interface {
	CheckOutputDetailed(context.Context, *modelrouter.RequestEnvelope, string, int) (*InputCheckOutcome, error)
}

func (h *ChatCompletionsHandler) checkOutputWithStatus(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, index int, audit *AuditResult) (string, string, []SecurityFinding, error) {
	if !h.inspectionPolicy(ctx).InspectModelOutput {
		return "allow", "", nil, nil
	}
	checker, ok := h.securityClient.(detailedOutputChecker)
	if !ok {
		return h.securityClient.CheckOutput(ctx, envelope, content, index)
	}
	out, err := checker.CheckOutputDetailed(ctx, envelope, content, index)
	if err != nil {
		return "", "", nil, err
	}
	if audit != nil && out.SemanticStatus != "" {
		if audit.ResponseMetadata == nil {
			audit.ResponseMetadata = map[string]interface{}{}
		}
		if current, _ := audit.ResponseMetadata["semantic_status"].(string); semanticStatusRank(out.SemanticStatus) > semanticStatusRank(current) {
			audit.ResponseMetadata["semantic_status"] = out.SemanticStatus
			audit.ResponseMetadata["semantic_reason"] = out.SemanticReason
		}
	}
	if out.SemanticStatus == "incomplete" {

		if audit != nil {
			if audit.ResponseMetadata == nil {
				audit.ResponseMetadata = map[string]interface{}{}
			}
			audit.ResponseMetadata["semantic_status"] = out.SemanticStatus
			audit.ResponseMetadata["semantic_reason"] = out.SemanticReason
			audit.ResponseMetadata["output_scan_incomplete"] = true
			audit.ResponseMetadata["output_scan_incomplete_reason"] = out.SemanticReason
			audit.OutputAction = strongerSecurityAction(audit.OutputAction, "audit")
		}
		if h.auditWriter != nil {
			h.recordSemanticIncomplete(ctx, envelope, "output", out.SemanticReason, out.Action, out.Findings)
		}
		// An incomplete semantic stage is a coverage gap in every mode; it is
		// recorded above and never interrupts the response.
		out.Action = strongerSecurityAction(out.Action, "audit")
	}
	return out.Action, out.MaskedContent, out.Findings, nil
}

type semanticEffectiveActionKey struct{}

func (h *ChatCompletionsHandler) recordSemanticIncomplete(ctx context.Context, envelope *modelrouter.RequestEnvelope, stage, reason, action string, findings []SecurityFinding) {
	mode := h.exitMode(ctx)
	if stage == "output" {
		mode = h.outputExitMode(ctx)
	}
	// What this request actually got: a deterministic blocking verdict is
	// enforced only in protect mode; the incompleteness itself never blocks.
	effective := "allow"
	if mode == securityexit.Record {
		effective = "audit"
	} else if securityexit.Decide(mode, action, securityexit.RuleHit).Enforce {
		effective = "block"
	}
	ctx = context.WithValue(withSemanticDiagnostics(withSemanticStatus(withSecurityEventStage(ctx, stage), "incomplete", reason), findings), semanticEffectiveActionKey{}, effective)
	if h.auditWriter == nil {
		return
	}
	// Capacity/availability incompletes are engine state, not content risk. Fold
	// repeats of the same (conversation, stage, reason) into one representative
	// event as occurrences so an overloaded judge does not mint one alert group
	// per message. The group's occurrence_count keeps the gap visible.
	if isCapacityIncompleteReason(reason) {
		dedupe := h.capacityDedupe()
		if dedupe != nil {
			if representativeEventID, repeat := dedupe.representative(envelope, stage, reason); repeat {
				contextKey := dedupe.occurrenceContextKey(envelope, stage, reason)
				occCtx := withFingerprintOccurrence(ctx, representativeEventID, contextKey)
				h.writeSecurityEvent(occCtx, envelope, nil, "security_check_failed", stage+" semantic detection incomplete: "+reason)
				return
			}
			// First time: write the full event with a pre-assigned ID, then register
			// it as the representative for later repeats of this (conversation, reason).
			representativeEventID := newAuditID("evt_")
			firstCtx := withSecurityEventID(ctx, representativeEventID)
			h.writeSecurityEvent(firstCtx, envelope, nil, "security_check_failed", stage+" semantic detection incomplete: "+reason)
			dedupe.register(envelope, stage, reason, representativeEventID)
			return
		}
	}
	h.writeSecurityEvent(ctx, envelope, nil, "security_check_failed", stage+" semantic detection incomplete: "+reason)
}

func deterministicBlockingAction(action string) bool {
	return securityexit.Blocks(action)
}

func semanticStatusRank(status string) int {
	switch status {
	case "incomplete":
		return 4
	case "completed":
		return 3
	case "skipped":
		return 2
	case "not_requested":
		return 1
	default:
		return 0
	}
}

func withSemanticDiagnostics(ctx context.Context, findings []SecurityFinding) context.Context {
	state, ok := semanticStatusFromContext(ctx)
	if !ok {
		return ctx
	}
	for _, f := range findings {
		if f.Type == "semantic_telemetry" {
			state.Diagnostics = append(state.Diagnostics, map[string]interface{}{"type": f.Type, "reason": f.Category, "triage": f.Triage})
		}
	}
	return context.WithValue(ctx, semanticStatusCtxKey{}, state)
}
