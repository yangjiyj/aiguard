package handler

import (
	"context"
	"time"
)

// Judge health uses the existing authenticated runtime ledger and its
// canonical configuration verdict. Reading health never invokes a model.
func judgeRuntimeComponent(ctx context.Context, deps ReadModelDeps, now time.Time) map[string]interface{} {
	comp := map[string]interface{}{
		"component": "judge", "status": "unknown", "observed_at": now,
		"fault_events_24h": nil,
		"evidence":         "authenticated semantic runtime reports and recent fault-event evidence",
		"reason_code":      "runtime_source_not_configured",
	}
	if deps.DB != nil {
		queryCtx, cancel := context.WithTimeout(ctx, readModelProbeTimeout)
		count, err := repositoryForReadModels(deps).SemanticFaultEventCount(queryCtx, serviceHealthEvidenceWindowHours)
		cancel()
		if err == nil {
			comp["fault_events_24h"] = count
		} else {
			comp["fault_evidence_reason_code"] = "evidence_query_failed"
		}
	}
	if deps.SemanticDeps == nil {
		return comp
	}
	runtimeCtx, cancel := context.WithTimeout(ctx, readModelProbeTimeout)
	configs, err := buildSemanticComponentConfigs(runtimeCtx, deps.SemanticDeps)
	cancel()
	if err != nil {
		comp["reason_code"] = "semantic_config_unavailable"
		return comp
	}
	runtime := buildSemanticRuntimeStatus(semanticDesiredRevisions{
		Engine: configs.EngineRevision, Gateway: configs.GatewayRevision,
		EngineJudgeRequired: semanticEngineJudgeRequired(configs.Engine),
	}, now)
	for _, component := range runtime.Components {
		if component.Component != semanticEngineComponent {
			continue
		}
		comp["runtime_status"] = component.Status
		comp["runtime_fresh"] = component.Fresh
		comp["runtime_active_nodes"] = component.ActiveNodes
		comp["runtime_applied_nodes"] = component.AppliedNodes
		comp["judge_required"] = component.JudgeRequired
		comp["judge_operational"] = component.JudgeOperational
		if !component.Fresh {
			comp["reason_code"] = "runtime_report_missing"
			return comp
		}
		comp["runtime_reported_at"] = component.ReportedAt
		comp["judge_last_attempt_at"] = component.JudgeLastAttemptAt
		comp["judge_last_success_at"] = component.JudgeLastSuccessAt
		comp["judge_consecutive_failures"] = component.JudgeConsecutiveFailures
		comp["judge_breaker_open"] = component.JudgeBreakerOpen
		comp["judge_window_attempts"] = component.JudgeWindowAttempts
		comp["judge_window_successes"] = component.JudgeWindowSuccesses
		comp["judge_window_timeouts"] = component.JudgeWindowTimeouts
		comp["judge_p50_latency_ms"] = component.JudgeP50LatencyMS
		switch component.Status {
		case semanticRuntimeStatusApplied:
			if component.JudgeRequired {
				comp["status"] = "healthy"
				delete(comp, "reason_code")
			} else {
				comp["status"] = "disabled"
				comp["reason_code"] = "judge_not_required"
			}
		case semanticRuntimeStatusDegraded:
			comp["status"] = "degraded"
			reason := component.LastError
			if !semanticErrorCodePattern.MatchString(reason) {
				reason = "runtime_report_error"
			}
			comp["reason_code"] = reason
		default:
			comp["status"] = "processing"
			comp["reason_code"] = "runtime_config_pending"
		}
		return comp
	}
	return comp
}
