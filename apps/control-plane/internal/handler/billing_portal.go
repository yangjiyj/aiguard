package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

// portalBillingUser verifies that a portal BFF cannot set limits or redeem a
// card for a user from another tenant, even though the browser never sees the
// portal integration secret.
func portalBillingUser(r *http.Request, w http.ResponseWriter, deps *Dependencies, tenantID, userID string) bool {
	if deps == nil || deps.UserRepo == nil {
		portalNotConfigured(w, "user repository")
		return false
	}
	user, err := deps.UserRepo.GetByID(r.Context(), userID)
	if err != nil {
		writeError(w, "billing_internal_error", "failed to validate customer account")
		return false
	}
	if user == nil || user.TenantID != tenantID {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "customer account not found")
		return false
	}
	return true
}

type portalBillingLimitsRequest struct {
	UserID              string `json:"user_id"`
	DailyAmountMicros   int64  `json:"daily_amount_micros"`
	MonthlyAmountMicros int64  `json:"monthly_amount_micros"`
	DailyTokenLimit     int64  `json:"daily_token_limit"`
	MonthlyTokenLimit   int64  `json:"monthly_token_limit"`
	RPMLimit            int64  `json:"rpm_limit"`
	ConcurrencyLimit    int64  `json:"concurrency_limit"`
}

// UpdatePortalCustomerBillingLimits lets a customer set only their own
// amount, Token and request caps. Zero clears that particular cap.
func UpdatePortalCustomerBillingLimits(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		var req portalBillingLimitsRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		req.UserID = strings.TrimSpace(req.UserID)
		if req.UserID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "user_required", "user_id is required")
			return
		}
		if !portalBillingUser(r, w, deps, tenantID, req.UserID) {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		limits, err := store.SetCustomerLimits(r.Context(), tenantID, req.UserID, billing.CustomerLimits{
			DailyAmountMicros: billing.Micros(req.DailyAmountMicros), MonthlyAmountMicros: billing.Micros(req.MonthlyAmountMicros),
			DailyTokenLimit: req.DailyTokenLimit, MonthlyTokenLimit: req.MonthlyTokenLimit,
			RPMLimit: req.RPMLimit, ConcurrencyLimit: req.ConcurrencyLimit,
		})
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		portalLogAudit(r, deps, tenantID, "portal_billing_limits_update", map[string]interface{}{
			"user_id": req.UserID, "daily_amount_micros": req.DailyAmountMicros,
			"monthly_amount_micros": req.MonthlyAmountMicros, "daily_token_limit": req.DailyTokenLimit,
			"monthly_token_limit": req.MonthlyTokenLimit, "rpm_limit": req.RPMLimit,
			"concurrency_limit": req.ConcurrencyLimit,
		}, "billing_customer_limit", req.UserID)
		writeJSON(w, map[string]any{"data": map[string]any{"limits": limits}})
	}
}

type portalBillingRedemptionRequest struct {
	UserID string `json:"user_id"`
	Code   string `json:"code"`
}

// RedeemPortalCustomerBillingCode performs a one-time, transactionally safe
// credit. The full code is never included in logs, the ledger, or the reply.
func RedeemPortalCustomerBillingCode(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		var req portalBillingRedemptionRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		req.UserID = strings.TrimSpace(req.UserID)
		req.Code = strings.TrimSpace(req.Code)
		if req.UserID == "" || req.Code == "" || len(req.Code) > 128 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "user_id and a valid redemption code are required")
			return
		}
		if !portalBillingUser(r, w, deps, tenantID, req.UserID) {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		if !portalSensitiveAction(w, r, deps, tenantID, req.UserID, "redeem") {
			return
		}
		wallet, amount, err := store.RedeemCode(r.Context(), tenantID, req.UserID, req.Code)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		portalLogAudit(r, deps, tenantID, "portal_billing_redemption", map[string]interface{}{
			"user_id": req.UserID, "wallet_id": wallet.ID, "amount_micros": amount,
		}, "billing_wallet", wallet.ID)
		writeJSON(w, map[string]any{"data": map[string]any{
			"wallet": map[string]any{
				"currency": wallet.Currency, "balance_micros": wallet.BalanceMicros,
				"reserved_micros": wallet.ReservedMicros, "available_micros": wallet.AvailableMicros(),
			},
			"credited_micros": amount,
		}})
	}
}
