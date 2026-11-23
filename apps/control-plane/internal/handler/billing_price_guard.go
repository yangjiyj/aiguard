package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

// 价格写入的共用逻辑：清零拦截的错误映射、审计里的「旧值→新值」快照。
// 审计只记价格数字、币种与计价方式，不记任何密钥或请求体原文。

const (
	priceZeroConfirmationCode    = "price_zero_confirmation_required"
	priceZeroConfirmationMessage = "该模型当前有非零价格，本次提交会把输入、输出价格都改成 0（相当于免费）。" +
		"如确实要这样做，请在确认后重新提交（请求中带 confirm_zero_price=true；控制台会在确认框中让你勾选确认）。"
	priceZeroRejectedAction = "billing.price.zero_rejected"
	priceUnchangedAction    = "billing.price.unchanged"

	priceEffectiveInPastCode    = "price_effective_at_in_past"
	priceEffectiveInPastMessage = "生效时间不能早于当前时间（允许约 1 分钟的时钟误差）。价格表只追加、不回溯：" +
		"补录更早的生效时间会改写已经计费的那段历史。需要立即生效请留空或选择当前时间，需要定时生效请选择将来的时间。"
)

// writePriceSaveError 把价格写入错误翻译成 HTTP 响应。清零未确认返回 409 与稳定错误码；
// 生效时间早于当前时间返回 400；其余错误沿用 billingHTTPError。
// 清零拦截的审计已在 store 里独立落库，这里只负责把它接入审计链。
func writePriceSaveError(w http.ResponseWriter, r *http.Request, deps *Dependencies, tenantID string, err error) {
	var zeroErr *billing.ZeroPriceError
	switch {
	case errors.As(err, &zeroErr):
		if zeroErr.AuditID != "" {
			appendAuditChain(context.WithoutCancel(r.Context()), deps, tenantID, priceZeroRejectedAction, zeroErr.AuditID, zeroErr.AuditDetail)
		}
		writeErrorWithStatus(w, http.StatusConflict, priceZeroConfirmationCode, priceZeroConfirmationMessage)
	case errors.Is(err, billing.ErrPriceEffectiveInPast):
		writeErrorWithStatus(w, http.StatusBadRequest, priceEffectiveInPastCode, priceEffectiveInPastMessage)
	default:
		billingHTTPError(w, err)
	}
}

// priceAuditSpec 组装「与价格同一事务」的审计规格。audit_operations 的写入在 billing 包内、价格事务里完成，
// 提交后由 appendPriceAuditChain 接入审计链。
func priceAuditSpec(r *http.Request, actorID, createAction, tenantID, modelName string) *billing.PriceAuditSpec {
	return &billing.PriceAuditSpec{
		ActorUserID: actorID, IPAddress: requestClientIP(r),
		CreateAction: createAction,
		Detail: func(record billing.PriceAuditRecord) map[string]any {
			detail := priceAuditDetail(billingPriceAuditInput{
				TenantID: tenantID, ModelName: modelName,
				Created: record.Price, Previous: record.Previous, ZeroConfirmed: record.ZeroConfirmed,
			})
			if record.Price == record.Previous {
				// 提交的价格与生效版本完全相同：没有新增版本。
				detail["unchanged"] = true
				detail["change_summary"] = "提交的价格与当前生效价格相同，未新增版本"
			}
			return detail
		},
		UnchangedAction:    priceUnchangedAction,
		ZeroRejectedAction: priceZeroRejectedAction,
		RejectedDetail: func(rejected *billing.ZeroPriceError) map[string]any {
			return priceZeroRejectedDetail(tenantID, modelName, rejected)
		},
	}
}

// appendPriceAuditChain 在价格事务提交之后把已落库的审计记录接入审计链（关键动作同步，其余入队）。
func appendPriceAuditChain(r *http.Request, deps *Dependencies, tenantID string, saved *billing.SavePriceResult) {
	if saved == nil || saved.AuditID == "" {
		return
	}
	appendAuditChain(context.WithoutCancel(r.Context()), deps, tenantID, saved.AuditAction, saved.AuditID, saved.AuditDetail)
}

// priceSnapshot 返回一个价格版本的可审计快照。未设置的缓存价不出现（与「设置为 0」区分）。
func priceSnapshot(mode, currency string, direct billing.DirectPrice, ratio billing.RatioPrice) map[string]interface{} {
	snapshot := map[string]interface{}{"pricing_mode": mode, "currency": currency}
	switch mode {
	case billing.PricingModeNewAPIRatio:
		snapshot["base_input_per_million_micros"] = int64(ratio.BaseInputPerMillionMicros)
		snapshot["model_ratio_ppm"] = ratio.ModelRatioPPM
		snapshot["completion_ratio_ppm"] = ratio.CompletionRatioPPM
		if ratio.HasCachedInputRatio {
			snapshot["cached_input_ratio_ppm"] = ratio.CachedInputRatioPPM
		}
		if ratio.HasCacheWriteRatio {
			snapshot["cache_write_ratio_ppm"] = ratio.CacheWriteRatioPPM
		}
		// 折算后的实际单价，便于和直接单价版本对照。
		if effective, err := billing.NormalizeNewAPIRatioPrice(ratio); err == nil {
			direct = effective
		}
	}
	snapshot["input_per_million_micros"] = int64(direct.InputPerMillionMicros)
	snapshot["output_per_million_micros"] = int64(direct.OutputPerMillionMicros)
	if direct.HasCachedInputPrice {
		snapshot["cached_input_per_million_micros"] = int64(direct.CachedInputPerMillionMicros)
	}
	if direct.HasCacheWritePrice {
		snapshot["cache_write_per_million_micros"] = int64(direct.CacheWritePerMillionMicros)
	}
	return snapshot
}

func storedPriceSnapshot(price *billing.ModelPrice) map[string]interface{} {
	return priceSnapshot(price.PricingMode, price.Currency, price.DirectPrice, price.RatioPrice)
}

func attemptedPriceSnapshot(price billing.NewModelPrice) map[string]interface{} {
	return priceSnapshot(price.PricingMode, price.Currency, price.DirectPrice, price.RatioPrice)
}

// priceAmount 把 micros 格式化成人看得懂的金额，保留至少两位小数，去掉多余的尾零。
func priceAmount(currency string, value int64) string {
	text := formatBillingMicros(billing.Micros(value))
	if dot := strings.IndexByte(text, '.'); dot >= 0 {
		text = strings.TrimRight(text, "0")
		if len(text)-dot-1 < 2 {
			text += strings.Repeat("0", 2-(len(text)-dot-1))
		}
	}
	if currency == "USD" {
		return "$" + text
	}
	return "¥" + text
}

func snapshotAmount(snapshot map[string]interface{}, key string) (int64, bool) {
	value, ok := snapshot[key].(int64)
	return value, ok
}

// priceChangeSummary 生成一行中文变化摘要，例如「输入 $3.00→$2.00；输出 $15.00→$10.00」。
func priceChangeSummary(old, next map[string]interface{}) string {
	labels := []struct{ key, label string }{
		{"input_per_million_micros", "输入"},
		{"output_per_million_micros", "输出"},
		{"cached_input_per_million_micros", "缓存读"},
		{"cache_write_per_million_micros", "缓存写"},
	}
	oldCurrency, _ := old["currency"].(string)
	newCurrency, _ := next["currency"].(string)
	var parts []string
	if old["pricing_mode"] != next["pricing_mode"] {
		parts = append(parts, fmt.Sprintf("计价方式 %v→%v", old["pricing_mode"], next["pricing_mode"]))
	}
	if oldCurrency != newCurrency {
		parts = append(parts, fmt.Sprintf("币种 %s→%s", oldCurrency, newCurrency))
	}
	for _, item := range labels {
		before, hadBefore := snapshotAmount(old, item.key)
		after, hasAfter := snapshotAmount(next, item.key)
		switch {
		case hadBefore && hasAfter && before == after:
		case hadBefore && hasAfter:
			parts = append(parts, fmt.Sprintf("%s %s→%s", item.label, priceAmount(oldCurrency, before), priceAmount(newCurrency, after)))
		case hadBefore:
			parts = append(parts, fmt.Sprintf("%s %s→未设置", item.label, priceAmount(oldCurrency, before)))
		case hasAfter:
			parts = append(parts, fmt.Sprintf("%s 未设置→%s", item.label, priceAmount(newCurrency, after)))
		}
	}
	if len(parts) == 0 {
		return "仅附加收费或倍率参数变化"
	}
	return strings.Join(parts, "；")
}

// priceAuditDetail 组装价格版本创建的审计详情：保留原有键，补充旧值、新值与变化摘要。
func priceAuditDetail(request billingPriceAuditInput) map[string]interface{} {
	detail := map[string]interface{}{
		"tenant_id": request.TenantID, "model_name": request.ModelName, "price_id": request.Created.ID,
		"version": request.Created.Version, "pricing_mode": request.Created.PricingMode,
		"new":                  storedPriceSnapshot(request.Created),
		"zero_price_confirmed": request.ZeroConfirmed,
	}
	if request.Previous != nil {
		old := storedPriceSnapshot(request.Previous)
		detail["old"] = old
		detail["old_version"] = request.Previous.Version
		detail["old_price_id"] = request.Previous.ID
		detail["change_summary"] = priceChangeSummary(old, detail["new"].(map[string]interface{}))
	} else {
		detail["change_summary"] = "首次配置价格"
	}
	return detail
}

type billingPriceAuditInput struct {
	TenantID      string
	ModelName     string
	Created       *billing.ModelPrice
	Previous      *billing.ModelPrice
	ZeroConfirmed bool
}

// priceZeroRejectedDetail 组装「清零被拦截」的审计详情，便于事后看到谁试图清零、被拒的是什么。
func priceZeroRejectedDetail(tenantID, modelName string, rejected *billing.ZeroPriceError) map[string]interface{} {
	old := storedPriceSnapshot(&rejected.Previous)
	attempted := attemptedPriceSnapshot(rejected.Attempted)
	return map[string]interface{}{
		"tenant_id": tenantID, "model_name": modelName,
		"old": old, "attempted": attempted, "old_version": rejected.Previous.Version,
		"reason":         "未确认就把非零价格改成 0",
		"change_summary": priceChangeSummary(old, attempted),
	}
}
