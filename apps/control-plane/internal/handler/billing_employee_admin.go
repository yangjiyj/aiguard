package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"net/http"
	"strings"
	"time"
)

func GetEmployeeBillingSettings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "请先登录")
			return
		}
		switch user.Role {
		case "platform_admin", "admin", "tenant_owner", "tenant_admin":
		default:
			writeErrorWithStatus(w, 403, "forbidden", "仅管理员可以读取系统币种设置")
			return
		}
		// 租户管理员只能读取自身租户；平台管理员可以显式选择目标租户。
		tenant := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
		if tenant == "" {
			tenant = user.TenantID
		}
		if tenant == "" {
			writeErrorWithStatus(w, 400, "invalid_request", "请指定租户")
			return
		}
		if user.Role != "platform_admin" && tenant != user.TenantID {
			writeErrorWithStatus(w, 403, "forbidden", "不可读取其他租户的币种设置")
			return
		}

		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		cfg, err := store.GetEmployeeSettings(r.Context(), tenant)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": cfg})
	}
}
func PutEmployeeBillingSettings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		var req billing.EmployeeSettings
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
			writeErrorWithStatus(w, 400, "invalid_request", "\u8bf7\u6c42\u683c\u5f0f\u65e0\u6548")
			return
		}
		if err := store.SaveEmployeeSettings(r.Context(), tenant, req); err != nil {
			employeeAllowanceHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.employee.defaults.update", map[string]any{"tenant_id": tenant, "currency": req.Currency, "default_monthly_micros": req.DefaultMonthlyMicros}, "tenant", tenant)
		writeJSON(w, map[string]any{"data": req})
	}
}
func ListEmployeeMonthlyAllowances(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		rows, err := store.ListEmployeeAllowances(r.Context(), tenant, time.Now())
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": rows})
	}
}
func PutEmployeeMonthlyAllowances(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		var req struct {
			UserIDs       []string `json:"user_ids"`
			MonthlyMicros *int64   `json:"monthly_micros"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&req); err != nil {
			writeErrorWithStatus(w, 400, "invalid_request", "\u8bf7\u6c42\u683c\u5f0f\u65e0\u6548")
			return
		}
		if err := store.SetEmployeeAllowances(r.Context(), tenant, req.UserIDs, req.MonthlyMicros); err != nil {
			writeErrorWithStatus(w, 400, "invalid_allowance", "\u6bcf\u6708\u5145\u503c\u91d1\u989d\u6216\u7528\u6237\u9009\u62e9\u65e0\u6548")
			return
		}
		logAudit(r, deps, "billing.employee.allowances.update", map[string]any{"tenant_id": tenant, "users": req.UserIDs, "monthly_micros": req.MonthlyMicros}, "tenant", tenant)
		writeJSON(w, map[string]any{"updated": len(req.UserIDs)})
	}
}
func ListBillingUpstreamRates(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		rows, err := store.ListUpstreamRates(r.Context(), tenant)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": rows})
	}
}
func ListBillingUpstreamModels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		rows, err := store.ListUpstreamModels(r.Context(), tenant)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": rows})
	}
}
func PutBillingUpstreamRate(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		var req billing.UpstreamRate
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&req); err != nil {
			writeErrorWithStatus(w, 400, "invalid_request", "\u8bf7\u6c42\u683c\u5f0f\u65e0\u6548")
			return
		}
		if err := store.SaveUpstreamRate(r.Context(), tenant, req); err != nil {
			if errors.Is(err, billing.ErrAllowanceCurrency) {
				writeErrorWithStatus(w, 409, "cost_currency_mismatch", "\u91c7\u8d2d\u6210\u672c\u5e01\u79cd\u5fc5\u987b\u4e0e\u79df\u6237\u94b1\u5305\u8ba1\u4ef7\u5e01\u79cd\u4e00\u81f4\uff0c\u7cfb\u7edf\u4e0d\u8fdb\u884c\u6c47\u7387\u8f6c\u6362")
				return
			}
			writeErrorWithStatus(w, 400, "invalid_upstream_rate", "invalid rate or channel/model selection")
			return
		}
		logAudit(r, deps, "billing.upstream.rate.update", map[string]any{"tenant_id": tenant, "provider_id": req.ProviderID, "model_name": req.ModelName}, "tenant", tenant)
		writeJSON(w, map[string]any{"data": req})
	}
}
func employeeAllowanceHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, billing.ErrInsufficientBalance):
		billingHTTPError(w, err)
	case errors.Is(err, billing.ErrAllowanceExhausted):
		writeErrorWithStatus(w, 429, "monthly_allowance_exhausted", billingInsufficientBalanceMessage)
	case errors.Is(err, billing.ErrAllowanceCurrency):
		writeErrorWithStatus(w, 409, "allowance_currency_mismatch", "\u94b1\u5305\u4e0e\u6a21\u578b\u4ef7\u683c\u5e01\u79cd\u4e0d\u4e00\u81f4\uff1b\u7cfb\u7edf\u4e0d\u8fdb\u884c\u6c47\u7387\u8f6c\u6362\u3002\u672c\u6708\u5df2\u53d1\u653e\u8d60\u91d1\u65f6\u5e01\u79cd\u548c\u65f6\u533a\u4e0d\u53ef\u66f4\u6539")
	case errors.Is(err, billing.ErrInvalidPrice), errors.Is(err, billing.ErrInvalidUsage):
		writeErrorWithStatus(w, 400, "invalid_allowance", "\u6bcf\u6708\u5145\u503c\u91d1\u989d\u3001\u94b1\u5305\u5e01\u79cd\u6216\u65f6\u533a\u65e0\u6548")
	default:
		writeErrorWithStatus(w, 503, "allowance_unavailable", "\u94b1\u5305\u6821\u9a8c\u6682\u4e0d\u53ef\u7528\uff0c\u8bf7\u7a0d\u540e\u91cd\u8bd5")
	}
}

// formatAllowanceMicros 按币种给金额加符号：USD 为 $，其余（含历史调用未带币种）沿用 ¥。
// 只换符号，不做汇率换算。
func formatAllowanceMicros(micros int64, currency string) string {
	cents := (micros + 5_000) / 10_000
	whole, fraction := cents/100, cents%100
	digits := fmt.Sprintf("%d", whole)
	grouped := make([]byte, 0, len(digits)+len(digits)/3)
	for index := range digits {
		if index > 0 && (len(digits)-index)%3 == 0 {
			grouped = append(grouped, ',')
		}
		grouped = append(grouped, digits[index])
	}
	symbol := "¥"
	if strings.EqualFold(strings.TrimSpace(currency), "USD") {
		symbol = "$"
	}
	return fmt.Sprintf("%s%s.%02d", symbol, grouped, fraction)
}

// allowanceExhaustedMessage 生成员工月额度用尽的中文提示：哪位员工、已用/额度、何时恢复。
// 金额符号跟随错误里带的币种，不做汇率换算。
func allowanceExhaustedMessage(err error) string {
	var exhausted *billing.AllowanceExhaustedError
	if !errors.As(err, &exhausted) {
		return "本月个人额度已用完或可用额度不足，下月 1 日自动恢复，如需追加请联系管理员"
	}
	format := func(micros int64) string { return formatAllowanceMicros(micros, exhausted.Currency) }
	used := exhausted.UsedMicros + exhausted.ReservedMicros
	if used > exhausted.LimitMicros {
		used = exhausted.LimitMicros
	}
	who := ""
	if exhausted.Username != "" {
		who = exhausted.Username + "，"
	}
	reset := "下月 1 日自动恢复"
	if !exhausted.MonthEnd.IsZero() {
		loc := time.FixedZone("local", 8*3600)
		if parsed, loadErr := time.LoadLocation(exhausted.Timezone); loadErr == nil {
			loc = parsed
		}
		end := exhausted.MonthEnd.In(loc)
		reset = fmt.Sprintf("%d 月 %d 日自动恢复", int(end.Month()), end.Day())
	}
	return fmt.Sprintf("本月个人额度已用完（%s已用 %s / %s），%s，如需追加请联系管理员", who, format(used), format(exhausted.LimitMicros), reset)
}
