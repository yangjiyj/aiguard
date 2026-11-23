package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type chatPolicyPreflightInput struct {
	ctx             context.Context
	w               http.ResponseWriter
	r               *http.Request
	requestID       string
	authInfo        *auth.AuthInfo
	startedAt       time.Time
	request         *ChatCompletionRequest
	modelRecord     *modelrouter.ModelRecord
	partialEnvelope *modelrouter.RequestEnvelope
}

type chatPolicyPreflightResult struct {
	concurrencyAcquired bool
}

func quotaPolicyEnforced(policy *modelrouter.QuotaPolicy) bool {
	if policy == nil {
		return false
	}
	// Empty is retained only for injected legacy implementations. The real DB
	// resolver always normalizes old rows to soft.
	return policy.EnforcementMode == "" || policy.EnforcementMode == "enforce"
}

func (h *ChatCompletionsHandler) runChatPolicyPreflight(input chatPolicyPreflightInput) (chatPolicyPreflightResult, error) {
	result := chatPolicyPreflightResult{}
	ctx := input.ctx
	authInfo := input.authInfo
	partialEnvelope := input.partialEnvelope
	req := input.request
	modelRecord := input.modelRecord

	modelPolicy, err := h.modelResolver.GetModelPolicy(ctx, authInfo.ProjectID)
	if !auth.UserModelAllowed(ctx, req.Model) || (!auth.UserModelAccessEnforced(ctx) && err == nil && !modelPolicy.IsModelAllowed(req.Model)) {
		// Audit contract: request log for policy rejection
		partialEnvelope.RejectReason = modelDenialRejectReason(ctx, req.Model)
		h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
		h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, auth.ModelDenialCode(ctx, req.Model), http.StatusForbidden, int(time.Since(input.startedAt)/time.Millisecond), nil)
		writeErrorResponse(input.w, auth.ModelDenialCode(ctx, req.Model), modelDeniedMessage(ctx, req.Model), input.requestID)
		return result, fmt.Errorf("%s", auth.ModelDenialCode(ctx, req.Model))
	}

	releaseConcurrencyOnError := func() {
		if result.concurrencyAcquired {
			h.rateLimiter.ReleaseConcurrency(ctx, authInfo.ProjectID)
		}
	}

	// Skip tenant-specific quota checks for proxy requests (proxy has its own rate limiting)
	if !isProxyRequest(ctx) && h.quotaAdmission == nil {
		quotaPolicy, err := h.modelResolver.GetQuotaPolicy(ctx, authInfo.ProjectID)
		if err == nil && quotaPolicyEnforced(quotaPolicy) {
			if quotaPolicy.RPMLimit > 0 {
				allowed, checkErr := h.rateLimiter.CheckRPM(ctx, authInfo.ProjectID, quotaPolicy.RPMLimit)
				// Only reject if check succeeded AND explicitly not allowed.
				// On error, allow the request to proceed (fail-open for availability).
				if checkErr == nil && !allowed {
					// Audit contract: request log for rate limit rejection
					h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
					h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "rate_limited", http.StatusTooManyRequests, int(time.Since(input.startedAt)/time.Millisecond), nil)
					writeErrorResponse(input.w, "rate_limited", "RPM limit exceeded", input.requestID)
					return result, fmt.Errorf("rate_limited")
				}
			}

			if quotaPolicy.ConcurrencyLimit > 0 {
				allowed, _, checkErr := h.rateLimiter.CheckConcurrency(ctx, authInfo.ProjectID, quotaPolicy.ConcurrencyLimit)
				// Only reject if check succeeded AND explicitly not allowed.
				if checkErr == nil && !allowed {
					// Audit contract: request log for concurrency limit rejection
					h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
					h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "concurrency_limit", http.StatusTooManyRequests, int(time.Since(input.startedAt)/time.Millisecond), nil)
					writeErrorResponse(input.w, "concurrency_limit", "concurrency limit exceeded", input.requestID)
					return result, fmt.Errorf("concurrency_limit")
				}
				if checkErr == nil && allowed {
					result.concurrencyAcquired = true
				}
			}

			if quotaPolicy.DailyTokenLimit > 0 {
				allowed, _, checkErr := h.rateLimiter.CheckDailyTokenLimit(ctx, authInfo.ProjectID, quotaPolicy.DailyTokenLimit)
				// Only reject if check succeeded AND explicitly not allowed.
				if checkErr == nil && !allowed {
					releaseConcurrencyOnError()
					// Audit contract: request log for quota rejection
					h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
					h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "quota_exceeded", http.StatusTooManyRequests, int(time.Since(input.startedAt)/time.Millisecond), nil)
					writeErrorResponse(input.w, "quota_exceeded", "daily token limit exceeded", input.requestID)
					return result, fmt.Errorf("quota_exceeded")
				}
			}

			if quotaPolicy.MonthlyTokenLimit > 0 {
				allowed, _, checkErr := h.rateLimiter.CheckMonthlyTokenLimit(ctx, authInfo.ProjectID, quotaPolicy.MonthlyTokenLimit)
				// Only reject if check succeeded AND explicitly not allowed.
				if checkErr == nil && !allowed {
					releaseConcurrencyOnError()
					// Audit contract: request log for quota rejection
					h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
					h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "quota_exceeded", http.StatusTooManyRequests, int(time.Since(input.startedAt)/time.Millisecond), nil)
					writeErrorResponse(input.w, "quota_exceeded", "monthly token limit exceeded", input.requestID)
					return result, fmt.Errorf("quota_exceeded")
				}
			}
		}
	}

	// Proxy (no-token) security checks.
	if isProxyRequest(ctx) {
		proxyCfg := ParseProxyConfig(modelRecord)

		if !proxyCfg.Enabled {
			h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
			h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "unauthorized", http.StatusUnauthorized, int(time.Since(input.startedAt)/time.Millisecond), nil)
			writeErrorResponse(input.w, "unauthorized", "authentication required", input.requestID)
			return result, fmt.Errorf("proxy_not_enabled")
		}

		clientIP := getClientIP(ctx)

		if h.proxyKeyVerifier != nil {
			rawProxyKey := input.r.Header.Get("X-Proxy-Key")
			if _, verr := h.proxyKeyVerifier.VerifyProxyKey(ctx, rawProxyKey, modelRecord.ID); verr != nil {
				h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
				h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "unauthorized", http.StatusUnauthorized, int(time.Since(input.startedAt)/time.Millisecond), nil)
				writeErrorResponse(input.w, "unauthorized", "invalid proxy key", input.requestID)
				return result, fmt.Errorf("proxy_key_invalid: %w", verr)
			}
		}

		if len(proxyCfg.IPAllowlist) > 0 && !matchIPAllowlist(clientIP, proxyCfg.IPAllowlist) {
			h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
			h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "forbidden", http.StatusForbidden, int(time.Since(input.startedAt)/time.Millisecond), nil)
			writeErrorResponse(input.w, "forbidden", "IP not allowed", input.requestID)
			return result, fmt.Errorf("proxy_ip_not_allowed")
		}

		if len(proxyCfg.OriginAllowlist) > 0 {
			origin := input.r.Header.Get("Origin")
			if origin == "" || !matchOriginAllowlist(origin, proxyCfg.OriginAllowlist) {
				h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
				h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "forbidden", http.StatusForbidden, int(time.Since(input.startedAt)/time.Millisecond), nil)
				writeErrorResponse(input.w, "forbidden", "origin not allowed", input.requestID)
				return result, fmt.Errorf("proxy_origin_not_allowed")
			}
		}

		if h.proxyRateLimiter != nil && proxyCfg.RPM > 0 {
			allowed, _ := h.proxyRateLimiter.CheckIPRPM(ctx, clientIP, modelRecord.ID, proxyCfg.RPM, 60)
			if !allowed {
				h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
				h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "rate_limited", http.StatusTooManyRequests, int(time.Since(input.startedAt)/time.Millisecond), nil)
				writeErrorResponse(input.w, "rate_limited", "proxy rate limit exceeded", input.requestID)
				return result, fmt.Errorf("proxy_rate_limited")
			}
		}

		if h.proxyRateLimiter != nil && proxyCfg.GlobalRPM > 0 {
			allowed, _ := h.proxyRateLimiter.CheckGlobalRPM(ctx, modelRecord.ID, proxyCfg.GlobalRPM)
			if !allowed {
				h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
				h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "rate_limited", http.StatusTooManyRequests, int(time.Since(input.startedAt)/time.Millisecond), nil)
				writeErrorResponse(input.w, "rate_limited", "global proxy rate limit exceeded", input.requestID)
				return result, fmt.Errorf("proxy_global_rate_limited")
			}
		}

		if h.proxyRateLimiter != nil && proxyCfg.DailyCap > 0 {
			allowed, _ := h.proxyRateLimiter.CheckDailyCap(ctx, modelRecord.ID, proxyCfg.DailyCap)
			if !allowed {
				h.auditWriter.EnsureRequestLog(ctx, partialEnvelope)
				h.auditWriter.FinalizeRequestLog(ctx, partialEnvelope, nil, "quota_exceeded", http.StatusTooManyRequests, int(time.Since(input.startedAt)/time.Millisecond), nil)
				writeErrorResponse(input.w, "quota_exceeded", "daily proxy cap reached", input.requestID)
				return result, fmt.Errorf("proxy_daily_cap")
			}
		}

		// Override authInfo with system-level proxy identity.
		authInfo.TenantID = h.cfg.ProxyDefaultTenantID
		authInfo.ProjectID = h.cfg.ProxyDefaultProjectID
		authInfo.UserID = h.cfg.ProxyDefaultUserID + ":" + clientIP
	}

	return result, nil
}
