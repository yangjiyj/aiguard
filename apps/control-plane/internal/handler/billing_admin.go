package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

// Billing operations are intentionally a platform-admin-only surface.
// The customer portal cannot reach these administration APIs.
func billingAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "user not found")
		return "", false
	}
	if user.Role != "platform_admin" {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can operate customer billing")
		return "", false
	}
	return user.ID, true
}

func billingTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		writeError(w, "invalid_request", "tenant_id is required")
		return "", false
	}
	return tenantID, true
}

func billingListLimit(r *http.Request) int {
	value, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	if err != nil || value <= 0 {
		return 100
	}
	if value > 500 {
		return 500
	}
	return value
}

func billingRuntimeDescription(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "prepaid":
		return "调用前冻结，完成后按实际用量扣款"
	case "metering":
		return "调用前冻结，完成后按实际用量扣款"
	default:
		return "计费已关闭"
	}
}

// BillingPrepaidToolsVisibleSettingKey 是“预付费账户（高级）”折叠区的显示开关（system_settings）。
// 只影响控制台是否展示客户账户、客户组、充值、兑换码等对外运营功能，不改变计费模式与任何接口。
const BillingPrepaidToolsVisibleSettingKey = "billing_prepaid_tools_visible"

// billingPrepaidToolsVisible：prepaid 模式恒显示；其他模式仅在系统设置显式为 true 时显示。
// 读取失败按隐藏处理——这是纯展示开关，隐藏不影响任何后端能力。
func billingPrepaidToolsVisible(ctx context.Context, deps *Dependencies, mode string) bool {
	if mode == "prepaid" {
		return true
	}
	if deps == nil || deps.SystemRepo == nil {
		return false
	}
	visible, err := deps.SystemRepo.GetBool(ctx, BillingPrepaidToolsVisibleSettingKey)
	return err == nil && visible
}

// GetBillingRuntime exposes only the billing mode semantics required by the
// operations console. It intentionally contains no secret or balance data.
func GetBillingRuntime(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		mode := strings.ToLower(strings.TrimSpace(deps.BillingMode))
		if mode != "metering" && mode != "prepaid" {
			mode = "off"
		}
		writeJSON(w, map[string]any{"data": map[string]any{
			"mode": mode, "description": billingRuntimeDescription(mode), "generated_at": time.Now().UTC(),
			"prepaid_tools_visible": billingPrepaidToolsVisible(r.Context(), deps, mode),
		}})
	}
}

func billingWalletResponse(wallet *billing.Wallet) map[string]any {
	return map[string]any{
		"id": wallet.ID, "tenant_id": wallet.TenantID, "user_id": wallet.UserID,
		"currency": wallet.Currency, "balance_micros": wallet.BalanceMicros,
		"reserved_micros": wallet.ReservedMicros, "available_micros": wallet.AvailableMicros(),
		"updated_at": wallet.UpdatedAt,
	}
}

// ListBillingCustomers returns the account-and-wallet table used by the
// billing operations console.
func ListBillingCustomers(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		// Pagination is opt-in: without the cursor parameter the legacy
		// non-paginated response (no meta) is preserved exactly, so existing
		// consumers keep their old shape. Passing ?cursor= (even empty)
		// switches to the keyset-paginated variant with meta.next_cursor.
		paginated := r.URL.Query().Has("cursor")
		data := make([]map[string]any, 0)
		response := map[string]any{}
		if paginated {
			customers, nextCursor, err := store.ListAdminCustomersPage(r.Context(), tenantID, billingListLimit(r), r.URL.Query().Get("cursor"))
			if err != nil {
				billingHTTPError(w, err)
				return
			}
			for _, item := range customers {
				available := item.BalanceMicros - item.ReservedMicros
				data = append(data, map[string]any{
					"user_id": item.UserID, "username": item.Username, "email": item.Email,
					"status": item.Status, "customer_group": item.CustomerGroup,
					"customer_group_name": item.GroupName, "customer_group_status": item.GroupStatus,
					"wallet_id": item.WalletID, "currency": item.Currency,
					"balance_micros": item.BalanceMicros, "reserved_micros": item.ReservedMicros,
					"available_micros": available, "updated_at": item.UpdatedAt,
				})
			}
			response["data"] = data
			response["meta"] = map[string]any{
				"next_cursor": nextCursor, "has_more": nextCursor != "",
			}
		} else {
			customers, err := store.ListAdminCustomers(r.Context(), tenantID, billingListLimit(r))
			if err != nil {
				billingHTTPError(w, err)
				return
			}
			for _, item := range customers {
				available := item.BalanceMicros - item.ReservedMicros
				data = append(data, map[string]any{
					"user_id": item.UserID, "username": item.Username, "email": item.Email,
					"status": item.Status, "customer_group": item.CustomerGroup,
					"customer_group_name": item.GroupName, "customer_group_status": item.GroupStatus,
					"wallet_id": item.WalletID, "currency": item.Currency,
					"balance_micros": item.BalanceMicros, "reserved_micros": item.ReservedMicros,
					"available_micros": available, "updated_at": item.UpdatedAt,
				})
			}
			response["data"] = data
		}
		writeJSON(w, response)
	}
}

type billingWalletCreditRequest struct {
	TenantID       string `json:"tenant_id"`
	UserID         string `json:"user_id"`
	AmountMicros   int64  `json:"amount_micros"`
	IdempotencyKey string `json:"idempotency_key"`
	Reason         string `json:"reason"`
}

func CreditCustomerWallet(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorID, ok := billingAdmin(w, r)
		if !ok {
			return
		}
		var request billingWalletCreditRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&request); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		request.TenantID = strings.TrimSpace(request.TenantID)
		request.UserID = strings.TrimSpace(request.UserID)
		request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
		request.Reason = strings.TrimSpace(request.Reason)
		if request.TenantID == "" || request.UserID == "" || request.AmountMicros <= 0 || request.IdempotencyKey == "" || len(request.IdempotencyKey) > 192 {
			writeError(w, "invalid_request", "tenant_id, user_id, positive amount_micros and idempotency_key are required")
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		wallet, err := store.CreditUserWallet(r.Context(), request.TenantID, request.UserID, request.IdempotencyKey, billing.Micros(request.AmountMicros), actorID, request.Reason)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.credit", map[string]interface{}{
			"tenant_id": request.TenantID, "user_id": request.UserID, "wallet_id": wallet.ID,
			"amount_micros": request.AmountMicros, "reason": request.Reason,
		}, "billing_wallet", wallet.ID)
		writeJSON(w, map[string]any{"data": billingWalletResponse(wallet)})
	}
}

type billingWalletAdjustmentRequest struct {
	TenantID       string `json:"tenant_id"`
	WalletID       string `json:"wallet_id"`
	AmountMicros   int64  `json:"amount_micros"`
	IdempotencyKey string `json:"idempotency_key"`
	Reason         string `json:"reason"`
}

func AdjustCustomerWallet(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorID, ok := billingAdmin(w, r)
		if !ok {
			return
		}
		var request billingWalletAdjustmentRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&request); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		request.TenantID = strings.TrimSpace(request.TenantID)
		request.WalletID = strings.TrimSpace(request.WalletID)
		request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
		request.Reason = strings.TrimSpace(request.Reason)
		if request.TenantID == "" || request.WalletID == "" || request.AmountMicros == 0 || request.IdempotencyKey == "" || len(request.IdempotencyKey) > 192 {
			writeError(w, "invalid_request", "tenant_id, wallet_id, non-zero amount_micros and idempotency_key are required")
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		wallet, err := store.Adjust(r.Context(), request.TenantID, request.WalletID, request.IdempotencyKey, billing.Micros(request.AmountMicros), actorID, request.Reason)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.adjustment", map[string]interface{}{
			"tenant_id": request.TenantID, "wallet_id": request.WalletID,
			"amount_micros": request.AmountMicros, "reason": request.Reason,
		}, "billing_wallet", wallet.ID)
		writeJSON(w, map[string]any{"data": billingWalletResponse(wallet)})
	}
}

func ListBillingLedger(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		// Pagination is opt-in via the cursor parameter: without it the
		// legacy non-paginated response (no meta) is preserved exactly.
		paginated := r.URL.Query().Has("cursor")
		walletID := strings.TrimSpace(r.URL.Query().Get("wallet_id"))
		data := make([]map[string]any, 0)
		response := map[string]any{}
		var entries []billing.LedgerEntry
		nextCursor := ""
		var err error
		if paginated {
			entries, nextCursor, err = store.ListLedgerEntriesPage(r.Context(), tenantID, walletID, billingListLimit(r), r.URL.Query().Get("cursor"))
		} else {
			entries, err = store.ListLedgerEntries(r.Context(), tenantID, walletID, billingListLimit(r))
		}
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		for _, item := range entries {
			data = append(data, map[string]any{
				"id": item.ID, "wallet_id": item.WalletID, "currency": item.Currency, "user_id": item.UserID, "username": item.Username,
				"department_id": item.DepartmentID, "department_name": item.DepartmentName,
				"reservation_id": item.ReservationID, "request_id": item.RequestID, "event_type": item.EventType,
				"balance_delta_micros": item.BalanceDeltaMicros, "reserved_delta_micros": item.ReservedDeltaMicros,
				"balance_after_micros": item.BalanceAfterMicros, "reserved_after_micros": item.ReservedAfterMicros,
				"actor_type": item.ActorType, "actor_id": item.ActorID, "idempotency_key": item.IdempotencyKey,
				"reason": item.Reason, "metadata": json.RawMessage(item.MetadataJSON), "created_at": item.CreatedAt,
			})
		}
		response["data"] = data
		if paginated {
			response["meta"] = map[string]any{
				"next_cursor": nextCursor, "has_more": nextCursor != "",
			}
		}
		writeJSON(w, response)
	}
}

func ListBillingPrices(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		scope := strings.TrimSpace(r.URL.Query().Get("scope"))
		// model_name is the approved, authoritative parameter; model remains a
		// compatible alias. Providing both with different values is an explicit
		// client error instead of a silent priority pick.
		modelName := strings.TrimSpace(r.URL.Query().Get("model_name"))
		modelAlias := strings.TrimSpace(r.URL.Query().Get("model"))
		if modelName != "" && modelAlias != "" && modelName != modelAlias {
			writeError(w, "invalid_request", "model_name and model must match when both are provided; model_name is authoritative")
			return
		}
		model := modelName
		if model == "" {
			model = modelAlias
		}
		var prices []billing.ModelPrice
		var err error
		switch {
		case scope == "effective" && model != "":
			prices, err = store.ListEffectiveModelPricesForModel(r.Context(), tenantID, model, billingListLimit(r))
		case scope == "effective":
			prices, err = store.ListEffectiveModelPrices(r.Context(), tenantID, billingListLimit(r))
		default:
			prices, err = store.ListModelPrices(r.Context(), tenantID, billingListLimit(r))
		}
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		data := make([]map[string]any, 0, len(prices))
		for _, item := range prices {
			data = append(data, map[string]any{
				"pricing_extras": item.Extensions,
				"id":             item.ID, "model_name": item.ModelName, "customer_group": item.CustomerGroup,
				"version": item.Version, "pricing_mode": item.PricingMode, "currency": item.Currency,
				"input_per_million_micros":        item.DirectPrice.InputPerMillionMicros,
				"cached_input_per_million_micros": item.DirectPrice.CachedInputPerMillionMicros,
				"cache_write_per_million_micros":  item.DirectPrice.CacheWritePerMillionMicros,
				"output_per_million_micros":       item.DirectPrice.OutputPerMillionMicros,
				"has_cached_input_price":          item.DirectPrice.HasCachedInputPrice,
				"has_cache_write_price":           item.DirectPrice.HasCacheWritePrice,
				"status":                          item.Status, "effective_at": item.EffectiveAt, "expires_at": item.ExpiresAt,
				"base_input_per_million_micros": item.RatioPrice.BaseInputPerMillionMicros,
				"model_ratio_ppm":               item.RatioPrice.ModelRatioPPM,
				"completion_ratio_ppm":          item.RatioPrice.CompletionRatioPPM,
				"group_ratio_ppm":               item.RatioPrice.GroupRatioPPM,
				"cached_input_ratio_ppm":        item.RatioPrice.CachedInputRatioPPM,
				"cache_write_ratio_ppm":         item.RatioPrice.CacheWriteRatioPPM,
				"has_cached_input_ratio":        item.RatioPrice.HasCachedInputRatio, "has_cache_write_ratio": item.RatioPrice.HasCacheWriteRatio,
				"created_by": item.CreatedBy, "created_at": item.CreatedAt,
			})
		}
		writeJSON(w, map[string]any{"data": data})
	}
}

type billingModelPriceRequest struct {
	PricingExtras               billing.PriceExtensions `json:"pricing_extras"`
	TenantID                    string                  `json:"tenant_id"`
	ModelName                   string                  `json:"model_name"`
	Currency                    string                  `json:"currency"`
	Status                      string                  `json:"status"`
	InputPerMillionMicros       int64                   `json:"input_per_million_micros"`
	OutputPerMillionMicros      int64                   `json:"output_per_million_micros"`
	CachedInputPerMillionMicros *int64                  `json:"cached_input_per_million_micros"`
	CacheWritePerMillionMicros  *int64                  `json:"cache_write_per_million_micros"`
	EffectiveAt                 string                  `json:"effective_at"`
	// ConfirmZeroPrice 必须由操作员明确确认才能把非零价格改成 0；缺省为 false。
	ConfirmZeroPrice bool `json:"confirm_zero_price"`
}

func CreateBillingPrice(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorID, ok := billingAdmin(w, r)
		if !ok {
			return
		}
		var request billingModelPriceRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&request); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		request.TenantID = strings.TrimSpace(request.TenantID)
		request.ModelName = strings.TrimSpace(request.ModelName)
		request.Currency = strings.ToUpper(strings.TrimSpace(request.Currency))
		request.Status = strings.TrimSpace(request.Status)
		if request.TenantID == "" || request.ModelName == "" || request.InputPerMillionMicros < 0 || request.OutputPerMillionMicros < 0 {
			writeError(w, "invalid_request", "tenant_id, model_name and non-negative direct prices are required")
			return
		}
		effectiveAt := time.Now().UTC()
		if request.EffectiveAt != "" {
			value, err := time.Parse(time.RFC3339, request.EffectiveAt)
			if err != nil {
				writeError(w, "invalid_request", "effective_at must be RFC3339")
				return
			}
			effectiveAt = value
		}
		price := billing.NewModelPrice{
			TenantID: request.TenantID, ModelName: request.ModelName, CustomerGroup: billing.DefaultCustomerGroup,
			PricingMode: billing.PricingModeDirect, Currency: request.Currency, Status: request.Status, Extensions: request.PricingExtras,
			EffectiveAt: effectiveAt, CreatedBy: actorID,
			DirectPrice: billing.DirectPrice{
				InputPerMillionMicros:  billing.Micros(request.InputPerMillionMicros),
				OutputPerMillionMicros: billing.Micros(request.OutputPerMillionMicros),
			},
		}
		if request.CachedInputPerMillionMicros != nil {
			price.DirectPrice.HasCachedInputPrice = true
			price.DirectPrice.CachedInputPerMillionMicros = billing.Micros(*request.CachedInputPerMillionMicros)
		}
		if request.CacheWritePerMillionMicros != nil {
			price.DirectPrice.HasCacheWritePrice = true
			price.DirectPrice.CacheWritePerMillionMicros = billing.Micros(*request.CacheWritePerMillionMicros)
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		saved, err := store.SaveModelPrice(r.Context(), price, billing.SavePriceOptions{
			ConfirmZeroPrice: request.ConfirmZeroPrice,
			Audit:            priceAuditSpec(r, actorID, "billing.price.create", request.TenantID, request.ModelName),
		})
		if err != nil {
			writePriceSaveError(w, r, deps, request.TenantID, err)
			return
		}
		created := saved.Price
		appendPriceAuditChain(r, deps, request.TenantID, saved)
		writeJSON(w, map[string]any{"data": map[string]any{
			"id": created.ID, "version": created.Version, "effective_at": created.EffectiveAt, "unchanged": saved.Unchanged,
		}})
	}
}
