package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
)

type cutoffStatus struct {
	HasMoneyQuota bool   `json:"has_money_quota"`
	Unpriced      bool   `json:"unpriced,omitempty"`
	Blocked       bool   `json:"blocked"`
	Layer         string `json:"layer,omitempty"`
	Message       string `json:"message,omitempty"`
	Resolved      bool   `json:"resolved"`
	UserID        string `json:"user_id,omitempty"`
}

const cutoffSourceIPLoginWindow = 12 * time.Hour

// GetBillingCutoffStatus serves the internal priced API admission check.
// 也可只给 source_ip，由控制面用“登录态映射”解析出唯一用户。仅内部共享密钥可访问。
func GetBillingCutoffStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := billingStore(deps)
		if !ok {
			writeJSON(w, map[string]any{"data": cutoffStatus{}})
			return
		}
		tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
		userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
		sourceIP := strings.TrimSpace(r.URL.Query().Get("source_ip"))
		if tenantID == "" || (userID == "" && sourceIP == "") {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "tenant_id 与 user_id 或 source_ip 必须提供其一")
			return
		}
		status := cutoffStatus{}
		var err error
		if userID == "" {
			userID, err = store.ResolveUserBySourceIP(r.Context(), tenantID, sourceIP, cutoffSourceIPLoginWindow)
			if err != nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "cutoff_status_unavailable", "断流状态暂不可用")
				return
			}
		}
		if userID == "" {
			writeJSON(w, map[string]any{"data": status})
			return
		}
		status.Resolved, status.UserID = true, userID
		modelName := strings.TrimSpace(r.URL.Query().Get("model_name"))
		if modelName == "" {
			status.Unpriced = true
			writeJSON(w, map[string]any{"data": status})
			return
		}
		quote, priceErr := resolveGatewayBillingQuote(r.Context(), store, tenantID, userID, modelName, billing.Usage{}, time.Now().UTC())
		if errors.Is(priceErr, billing.ErrPriceNotFound) || errors.Is(priceErr, billing.ErrImageVariantPriceNotFound) {
			status.Unpriced = true
			writeJSON(w, map[string]any{"data": status})
			return
		}
		if priceErr != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "cutoff_status_unavailable", "billing price lookup is unavailable")
			return
		}
		if deps.BillingMode == "metering" || deps.BillingMode == "prepaid" {
			if _, err = store.EnsureMonthlyWalletGrant(r.Context(), tenantID, userID, quote.Price.Currency, quote.AdmittedAt); err != nil {
				if errors.Is(err, billing.ErrAllowanceCurrency) {
					billingHTTPError(w, err)
				} else {
					writeErrorWithStatus(w, http.StatusServiceUnavailable, "cutoff_status_unavailable", "billing wallet lookup is unavailable")
				}
				return
			}
		}
		status.HasMoneyQuota, err = store.HasMoneyQuota(r.Context(), tenantID, userID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "cutoff_status_unavailable", "billing quota lookup is unavailable")
			return
		}

		if quote.Price.IsFullyFree() {
			writeJSON(w, map[string]any{"data": status})
			return
		}

		layer, message, err := evaluateUserCutoff(r.Context(), deps, store, tenantID, userID, quote.Price.Currency, time.Now().UTC())
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "cutoff_status_unavailable", "断流状态暂不可用")
			return
		}
		status.Blocked, status.Layer, status.Message = layer != "", layer, message
		writeJSON(w, map[string]any{"data": status})
	}
}

// evaluateUserCutoff checks explicit money budgets and actual wallet balances.
// currency 为本次准入报价的币种，用于提示文案的金额符号。
func evaluateUserCutoff(ctx context.Context, deps *Dependencies, store *billing.Store, tenantID, userID, currency string, now time.Time) (layer, message string, err error) {
	policies, err := store.UserBudgetPolicies(ctx, tenantID, userID)
	if err != nil {
		return "", "", err
	}
	if len(policies) > 0 {
		if deps.BudgetSnapshot == nil {
			// 有金额预算却读不到用量：无法确认，交给调用方按 fail-closed 处理。
			return "", "", errors.New("budget usage source unavailable")
		}
		scopes := make([]budget.SnapshotScope, 0, len(policies))
		for _, policy := range policies {
			scopes = append(scopes, budget.SnapshotScope{Scope: policy.Scope, ID: policy.ScopeID, Timezone: policy.Timezone})
		}
		usage, snapshotErr := deps.BudgetSnapshot.Get(ctx, tenantID, scopes)
		if snapshotErr != nil {
			return "", "", snapshotErr
		}
		for _, policy := range policies {
			current := usage[policy.Scope+":"+policy.ScopeID]
			layerName := map[string]string{"tenant": "organization_budget", "team": "department_budget", "user": "personal_budget"}[policy.Scope]
			if policy.MonthlyMicros > 0 && current.MonthCostMicros >= policy.MonthlyMicros {
				return layerName, budgetStatusMessage(policy, "本月", current.MonthCostMicros, policy.MonthlyMicros, now, false, currency), nil
			}
			if policy.DailyMicros > 0 && current.DayCostMicros >= policy.DailyMicros {
				return layerName, budgetStatusMessage(policy, "今日", current.DayCostMicros, policy.DailyMicros, now, true, currency), nil
			}
		}
	}
	if deps.BillingMode == "prepaid" || deps.BillingMode == "metering" {
		exhausted, walletErr := store.WalletCutoff(ctx, tenantID, userID)
		if walletErr != nil {
			return "", "", walletErr
		}
		if exhausted {
			return "wallet", "账户余额不足，已暂停使用，请联系管理员充值", nil
		}
	}
	return "", "", nil
}

func budgetStatusMessage(policy billing.BudgetPolicyScope, period string, used, limit int64, now time.Time, daily bool, currency string) string {
	layer := map[string]string{"tenant": "组织", "team": "部门", "user": "个人"}[policy.Scope]
	name := ""
	if policy.Name != "" {
		name = policy.Name + "，"
	}
	if used > limit {
		used = limit
	}
	location, err := time.LoadLocation(policy.Timezone)
	if err != nil {
		location = time.FixedZone("CST", 8*3600)
	}
	local := now.In(location)
	reset := time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, location).AddDate(0, 1, 0)
	if daily {
		reset = time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, location).AddDate(0, 0, 1)
	}
	return period + layer + "预算已用完（" + name + "已用 " + formatAllowanceMicros(used, currency) + " / " + formatAllowanceMicros(limit, currency) +
		"），" + itoa(int(reset.Month())) + " 月 " + itoa(reset.Day()) + " 日自动恢复，如需追加请联系管理员"
}

func itoa(value int) string { return strconv.Itoa(value) }
