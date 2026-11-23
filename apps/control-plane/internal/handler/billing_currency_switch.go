package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

// SwitchBillingCurrency 仅允许平台管理员切换租户系统币种（与 billingAdmin 保持一致）。
// 切换会把全部钱包按原数字改标成另一种币种并作废其他币种价格，影响面等同于资金调账，
// 因此不开放给租户管理员；三员分立中的审计员、安全员同样被拒绝。
func SwitchBillingCurrency(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "请先登录")
			return
		}
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, 403, "forbidden", "仅平台管理员可以切换系统币种")
			return
		}
		tenant := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
		if tenant == "" {
			tenant = user.TenantID
		}
		if tenant == "" {
			writeErrorWithStatus(w, 400, "invalid_request", "请指定租户")
			return
		}
		var req struct {
			Currency        string `json:"currency"`
			Preview         bool   `json:"preview"`
			ConfirmToken    string `json:"confirm_token"`
			ConfirmUnpriced bool   `json:"confirm_unpriced"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil || (req.Currency != "CNY" && req.Currency != "USD") {
			writeErrorWithStatus(w, 400, "invalid_request", "请选择人民币或美元")
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		result, err := store.SwitchCurrencyWithOptions(r.Context(), billing.CurrencySwitchRequest{
			Tenant: tenant, Actor: user.ID, IP: requestClientIP(r), Target: req.Currency,
			Preview: req.Preview, ConfirmToken: req.ConfirmToken, ConfirmUnpriced: req.ConfirmUnpriced,
		})
		if errors.Is(err, billing.ErrCurrencySwitchChanged) {
			writeErrorWithStatus(w, 409, "count_changed", err.Error())
			return
		}
		if errors.Is(err, billing.ErrCurrencySwitchInFlight) {
			writeErrorWithStatus(w, 409, "currency_switch_in_flight", err.Error())
			return
		}
		if errors.Is(err, billing.ErrCurrencySwitchBusy) {
			writeErrorWithStatus(w, 409, "currency_switch_busy", err.Error())
			return
		}
		if errors.Is(err, billing.ErrCurrencySwitchConflict) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(409)
			writeJSON(w, map[string]any{"error": map[string]any{"code": "currency_switch_conflict", "message": err.Error()}, "conflict_users": result.ConflictUsers})
			return
		}
		if errors.Is(err, billing.ErrCurrencySwitchUnpriced) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(409)
			writeJSON(w, map[string]any{"error": map[string]any{"code": "currency_switch_unpriced_confirm_required", "message": err.Error()}, "unpriced_models": result.UnpricedModels})
			return
		}
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		if result.Executed && !store.AuditChainInTx() {
			// 审计链未接入事务（例如测试或未启用审计链的部署）时，退回事后追加；关键审计清单会让它同步写入。
			appendAuditChain(context.WithoutCancel(r.Context()), deps, tenant, "billing.currency.switch", result.AuditID, map[string]any{"tenant_id": tenant, "currency": req.Currency, "previous_currency": result.CurrentCurrency})
		}
		writeJSON(w, map[string]any{"data": result})
	}
}
