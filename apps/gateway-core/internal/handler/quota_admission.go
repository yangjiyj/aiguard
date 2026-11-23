package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type QuotaAdmission interface {
	Admit(context.Context, governor.AdmissionRequest) (*governor.AdmissionLease, error)
	Heartbeat(context.Context, *governor.AdmissionLease) error
	Settle(context.Context, *governor.AdmissionLease, int64, int64, bool) error
	Release(context.Context, *governor.AdmissionLease, int64, int64) error
}

func writeQuotaAdmissionError(w http.ResponseWriter, admissionErr error, requestID string) {
	detail := ErrorDetail{
		Code: "quota_runtime_fault", Message: "配额服务暂不可用，请稍后重试",
		RequestID: requestID, Metric: "runtime_fault",
	}
	status := http.StatusServiceUnavailable
	var limitErr *governor.AdmissionLimitError
	var runtimeErr *governor.AdmissionRuntimeError
	if errors.As(admissionErr, &runtimeErr) && runtimeErr.BudgetCutoff {
		detail.Code = "billing_unavailable"
		detail.Message = governor.BillingUnavailableCutoffMessage
		if runtimeErr.RequestID != "" {
			detail.RequestID = runtimeErr.RequestID
		}
	} else if errors.As(admissionErr, &limitErr) {
		status = http.StatusTooManyRequests
		detail.Code = "quota_exceeded"
		detail.Message = legacyQuotaMessage(limitErr)
		if limitErr.BudgetCutoff {
			detail.Code = budgetExhaustedCode
			detail.Message = budgetExhaustedMessage(limitErr)
		}
		detail.Metric = limitErr.Metric
		detail.Scope = limitErr.Scope
		detail.Limit = quotaFactPointer(limitErr.Limit)
		detail.Used = quotaFactPointer(limitErr.Used)
		detail.Reserved = quotaFactPointer(limitErr.Reserved)
		detail.Requested = quotaFactPointer(limitErr.Requested)
		detail.RetryAfter = quotaFactPointer(limitErr.RetryAfter)
		if limitErr.RequestID != "" {
			detail.RequestID = limitErr.RequestID
		}
		if limitErr.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(limitErr.RetryAfter, 10))
		} else if limitErr.BudgetCutoff && !limitErr.ResetAt.IsZero() {
			if seconds := int64(time.Until(limitErr.ResetAt).Seconds()); seconds > 0 {
				w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
			}
		}
	} else {
		var idempotencyErr *governor.AdmissionIdempotencyError
		if errors.As(admissionErr, &idempotencyErr) {
			status = http.StatusConflict
			detail.Code = "quota_idempotency_conflict"
			detail.Message = "该幂等键已被占用，请更换后重试"
			detail.Metric = "idempotency"
			if idempotencyErr.RequestID != "" {
				detail.RequestID = idempotencyErr.RequestID
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if detail.RequestID != "" {
		w.Header().Set("X-Request-ID", detail.RequestID)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: detail})
}

func quotaFactPointer(value int64) *int64 { return &value }

func quotaAdmissionHTTPStatus(err error) (int, string) {
	var limitErr *governor.AdmissionLimitError
	if errors.As(err, &limitErr) {
		if limitErr.BudgetCutoff {
			return http.StatusTooManyRequests, budgetExhaustedCode
		}
		return http.StatusTooManyRequests, "quota_exceeded"
	}
	var idempotencyErr *governor.AdmissionIdempotencyError
	if errors.As(err, &idempotencyErr) {
		return http.StatusConflict, "quota_idempotency_conflict"
	}
	var runtimeErr *governor.AdmissionRuntimeError
	if errors.As(err, &runtimeErr) && runtimeErr.BudgetCutoff {
		return http.StatusServiceUnavailable, "billing_unavailable"
	}
	return http.StatusServiceUnavailable, "quota_runtime_fault"
}

// quotaAdmissionBillingOutcome 返回被预算断流拒绝的请求应写入 billing_outcome 的取值；非断流拒绝返回空串。
func quotaAdmissionBillingOutcome(err error) string {
	var limitErr *governor.AdmissionLimitError
	if errors.As(err, &limitErr) && limitErr.BudgetCutoff {
		return billingOutcomeBudgetExhausted
	}
	var runtimeErr *governor.AdmissionRuntimeError
	if errors.As(err, &runtimeErr) && runtimeErr.BudgetCutoff {
		return billingOutcomeBudgetUnavailable
	}
	return ""
}

type quotaAdmissionEventRecorder func(context.Context, governor.Decision)

func attachQuotaAdmission(
	ctx context.Context,
	admission QuotaAdmission,
	envelope *modelrouter.RequestEnvelope,
	estimatedTokens int64,
	record quotaAdmissionEventRecorder,
) error {
	if admission == nil || envelope == nil {
		return nil
	}
	lease, err := admission.Admit(ctx, governor.AdmissionRequest{
		Ref: governor.ScopeRef{
			TenantID: envelope.TenantID, TeamID: envelope.TeamID, ProjectID: envelope.ProjectID,
			UserID: trustedActorUserID(envelope), KeyID: envelope.ClientID,
			ModelID: envelope.ModelID, ModelName: envelope.Model,
		},
		RequestID: envelope.RequestID, IdempotencyKey: envelope.ClientRetryID,
		EstimatedTokens: estimatedTokens, EstimatedCostMicros: envelope.QuotaEstimatedCostMicros,
		CostEstimateAvailable:    envelope.QuotaCostEstimateAvailable,
		CostEstimateMissingPrice: envelope.QuotaCostEstimateMissingPrice,
		CostCurrency:             envelope.QuotaCostCurrency,
	})
	if err != nil {
		recordQuotaAdmissionError(ctx, record, err)
		return err
	}
	for _, observation := range lease.Observations {
		recordQuotaAdmissionDecision(ctx, record, governor.Decision{
			Action: governor.ActionAlert, AlertOnly: true,
			TriggeredMetric: observation.Metric, TriggeredScope: observation.Scope,
			Reason: fmt.Sprintf("soft quota overage: limit=%d used=%d reserved=%d requested=%d", observation.Limit, observation.Used, observation.Reserved, observation.Requested),
		})
	}
	if lease.State != "acquired" {
		if lease.State == "observation_unavailable" {
			recordQuotaAdmissionDecision(ctx, record, governor.Decision{Action: governor.ActionAlert, AlertOnly: true, TriggeredMetric: "runtime_fault", Reason: "soft quota observation unavailable"})
		}
		return nil
	}

	envelope.QuotaAdmissionManaged = true
	envelope.QuotaEstimatedTokens = lease.EstimatedTokens
	envelope.QuotaEstimatedCostMicros = lease.EstimatedCostMicros
	envelope.QuotaCostEstimateAvailable = lease.CostEstimateAvailable
	envelope.QuotaAccountingScopes = make([]modelrouter.QuotaAccountingScope, 0, len(lease.Scopes))
	for _, scope := range lease.Scopes {
		envelope.QuotaAccountingScopes = append(envelope.QuotaAccountingScopes, modelrouter.QuotaAccountingScope{Scope: scope.Scope, ID: scope.ID})
	}
	leaseSnapshot := cloneAdmissionLease(lease)
	heartbeatCtx, cancelHeartbeat := context.WithCancel(context.WithoutCancel(ctx))
	heartbeatDone := make(chan struct{})
	var stopOnce sync.Once
	stopHeartbeat := func() {
		stopOnce.Do(func() {
			cancelHeartbeat()
			<-heartbeatDone
		})
	}
	envelope.QuotaHeartbeatStop = stopHeartbeat
	leaseTTL := time.Duration(lease.LeaseTTLMillis) * time.Millisecond
	if leaseTTL <= 0 {
		leaseTTL = time.Until(lease.ExpiresAt)
	}
	interval := leaseTTL / 3
	if interval <= 0 || interval > 30*time.Second {
		interval = 30 * time.Second
	}
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		faultReported := false
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				heartbeatLease := cloneAdmissionLease(leaseSnapshot)
				if err := heartbeatQuotaAdmission(heartbeatCtx, admission, heartbeatLease); err != nil {
					if heartbeatCtx.Err() != nil {
						return
					}
					log.Printf("[quota.admission] heartbeat request_id=%s failed: %v", envelope.RequestID, err)
					if !faultReported {
						recordQuotaAdmissionError(ctx, record, err)
						faultReported = true
					}
					continue
				}
				faultReported = false
			}
		}
	}()

	envelope.QuotaFinalize = func(finalizeCtx context.Context, actualTokens, actualCostMicros int64, actualCostAvailable, success bool) error {
		stopHeartbeat()
		finalLease := cloneAdmissionLease(leaseSnapshot)
		var finalizeErr error
		if success {
			finalizeErr = admission.Settle(finalizeCtx, finalLease, actualTokens, actualCostMicros, actualCostAvailable)
		} else {
			finalizeErr = admission.Release(finalizeCtx, finalLease, actualTokens, actualCostMicros)
		}
		if finalizeErr != nil {
			recordQuotaAdmissionError(finalizeCtx, record, finalizeErr)
		}
		return finalizeErr
	}
	return nil
}

func heartbeatQuotaAdmission(ctx context.Context, admission QuotaAdmission, lease *governor.AdmissionLease) error {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		lastErr = admission.Heartbeat(attemptCtx, lease)
		cancel()
		if lastErr == nil {
			return nil
		}
		if ctx.Err() != nil || attempt == 3 {
			break
		}
		timer := time.NewTimer(time.Duration(attempt) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

func quotaAdmissionEventType(decision governor.Decision) string {
	if decision.TriggeredMetric == "" {
		return "quota.admission"
	}
	return "quota.admission." + decision.TriggeredMetric
}

func cloneAdmissionLease(lease *governor.AdmissionLease) *governor.AdmissionLease {
	if lease == nil {
		return nil
	}
	cloned := *lease
	cloned.Scopes = append([]governor.AdmissionScope(nil), lease.Scopes...)
	cloned.Observations = append([]governor.AdmissionObservation(nil), lease.Observations...)
	return &cloned
}

func recordQuotaAdmissionDecision(ctx context.Context, record quotaAdmissionEventRecorder, decision governor.Decision) {
	if record == nil {
		return
	}
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	record(recordCtx, decision)
}

func recordQuotaAdmissionError(ctx context.Context, record quotaAdmissionEventRecorder, err error) {
	if record == nil || err == nil {
		return
	}
	decision := governor.Decision{Action: governor.ActionAlert, AlertOnly: true, TriggeredMetric: "runtime_fault", Reason: "quota admission runtime fault"}
	var limitErr *governor.AdmissionLimitError
	if errors.As(err, &limitErr) {
		reason := "organization quota exceeded"
		if limitErr.BudgetCutoff {
			reason = "budget cutoff: money budget exhausted"
		}
		if limitErr.ConfiguredAction == "pause_key" || limitErr.ConfiguredAction == "downgrade_model" {
			reason = "unsupported configured overage action " + limitErr.ConfiguredAction + " was safely rate-limited"
		}
		decision = governor.Decision{
			Action: governor.ActionRateLimit, TriggeredMetric: limitErr.Metric,
			TriggeredScope: limitErr.Scope, Reason: reason,
		}
	}
	var idempotencyErr *governor.AdmissionIdempotencyError
	if errors.As(err, &idempotencyErr) {
		decision = governor.Decision{Action: governor.ActionAlert, AlertOnly: true, TriggeredMetric: "idempotency_conflict", Reason: "quota admission idempotency conflict"}
	}
	var overrun *governor.AdmissionOverrunError
	if errors.As(err, &overrun) {
		decision = governor.Decision{Action: governor.ActionAlert, AlertOnly: true, TriggeredMetric: "reservation_overrun", Reason: "actual token usage exceeded the conservative reservation", Estimated: overrun.EstimatedTokens, Actual: overrun.ActualTokens}
	}
	var costOverrun *governor.AdmissionCostOverrunError
	if errors.As(err, &costOverrun) {
		decision = governor.Decision{Action: governor.ActionAlert, AlertOnly: true, TriggeredMetric: "cost_reservation_overrun", Reason: "actual billable amount exceeded the conservative reservation", Estimated: costOverrun.EstimatedMicros, Actual: costOverrun.ActualMicros}
	}
	recordQuotaAdmissionDecision(ctx, record, decision)
}

func estimatedChatAdmissionTokens(request *ChatCompletionRequest) int64 {
	return estimatedChatAdmissionTokensScaled(request, 1000)
}

// estimatedChatAdmissionTokensScaled 在输入估算上乘以 promptPermille/1000（只放大输入，不放大输出上限预留），
// 系数的来由与适用范围见 chat_estimate_anthropic.go。promptPermille<=1000 时与旧行为完全一致。
func estimatedChatAdmissionTokensScaled(request *ChatCompletionRequest, promptPermille int64) int64 {
	if request == nil {
		return 1
	}
	estimated := scaleEstimatePermille(estimateChatPromptTokens(request), promptPermille)
	maxOutput := request.MaxTokens
	if request.MaxCompletionTokens > maxOutput {
		maxOutput = request.MaxCompletionTokens
	}
	if maxOutput <= 0 {
		maxOutput = 4096
	}
	output := int64(maxOutput)
	if output >= maxExactTokenCount || estimated >= maxExactTokenCount-output {
		return maxExactTokenCount
	}
	return estimated + output
}

func estimatedImageAdmissionTokens(prompt string) int64 {
	if len(prompt) < 1 {
		return 1
	}
	return int64(len(prompt))
}
