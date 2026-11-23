package billing

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

// 成本联动路由（只做建议）：同一模型多个上游渠道的采购成本对比与近 7 天毛利。
// 只读计费事实与采购成本表，不改任何路由配置；毛利为负时给出“建议降低该渠道路由权重”，由管理员自行决定。

// ChannelUsage 是某渠道某模型在时间窗内的已结算用量。
type ChannelUsage struct {
	ProviderID, ProviderName, ModelName, Currency string
	Requests                                      int64
	CostKnownRequests                             int64
	BilledMicros                                  int64
	// BilledCostKnownMicros 只含采购成本已知的请求的计费金额，毛利用它与成本相减，
	// 避免把成本未知请求的收入算成利润。
	BilledCostKnownMicros int64
	CostMicros            int64
}

type ChannelMargin struct {
	ProviderID         string        `json:"provider_id"`
	ProviderName       string        `json:"provider_name"`
	HasRate            bool          `json:"has_rate"`
	Rate               *UpstreamRate `json:"rate,omitempty"`
	Currency           string        `json:"currency"`
	Requests           int64         `json:"requests"`
	CostKnownRequests  int64         `json:"cost_known_requests"`
	BilledMicros       int64         `json:"billed_micros"`
	CostMicros         int64         `json:"cost_micros"`
	VariableCostMicros int64         `json:"variable_cost_micros"`
	FixedCostMicros    int64         `json:"fixed_cost_micros"`
	CurrencyMismatch   bool          `json:"currency_mismatch"`
	CurrencyWarning    string        `json:"currency_warning,omitempty"`
	// MarginMicros 为 nil 表示没有成本已知的请求，无法计算毛利。
	MarginMicros *int64 `json:"margin_micros"`
	Negative     bool   `json:"negative"`
	Suggestion   string `json:"suggestion,omitempty"`
}

type ModelChannelMargins struct {
	ModelName   string          `json:"model_name"`
	Channels    []ChannelMargin `json:"channels"`
	HasNegative bool            `json:"has_negative"`
}

const negativeMarginSuggestion = "近 7 天该渠道采购成本高于内部结算金额，建议降低该渠道路由权重或调整内部结算价。系统不会自动修改路由。"

// BuildChannelMargins 按模型汇总各渠道采购成本与毛利。只返回至少有一个渠道录入了采购成本或产生了用量的模型。
type ChannelMarginWindow struct {
	FixedCosts []ChannelFixedCost
	Start, End time.Time
	Location   *time.Location
	Currency   string
}

func BuildChannelMargins(rates []UpstreamRate, usage []ChannelUsage, windows ...ChannelMarginWindow) []ModelChannelMargins {
	type key struct{ model, provider, currency string }
	channels := map[key]*ChannelMargin{}
	order := map[string][]key{}
	get := func(model, provider, name, currency string) *ChannelMargin {
		k := key{model, provider, currency}
		if c, ok := channels[k]; ok {
			if c.ProviderName == "" {
				c.ProviderName = name
			}
			return c
		}
		c := &ChannelMargin{ProviderID: provider, ProviderName: name, Currency: currency}
		channels[k] = c
		order[model] = append(order[model], k)
		return c
	}
	for i := range rates {
		r := rates[i]
		c := get(r.ModelName, r.ProviderID, r.ProviderName, r.Currency)
		c.HasRate, c.Rate = true, &r
		if c.Currency == "" {
			c.Currency = r.Currency
		}
	}
	for _, u := range usage {
		c := get(u.ModelName, u.ProviderID, u.ProviderName, u.Currency)
		c.Currency = u.Currency
		c.Requests += u.Requests
		c.CostKnownRequests += u.CostKnownRequests
		c.BilledMicros += u.BilledMicros
		c.CostMicros += u.CostMicros
		c.VariableCostMicros += u.CostMicros
		if u.CostKnownRequests > 0 {
			margin := u.BilledCostKnownMicros - u.CostMicros
			if c.MarginMicros != nil {
				margin += *c.MarginMicros
			}
			c.MarginMicros = &margin
		}
	}
	if len(windows) > 0 {
		window := windows[0]
		warn := func(c *ChannelMargin) {
			c.CurrencyMismatch = true
			c.CurrencyWarning = "已有采购成本与计价币种不一致，毛利无法计算。请管理员调整成本币种；系统不进行汇率转换。"
			c.MarginMicros = nil
		}
		for k, c := range channels {
			if window.Currency != "" && c.Currency != window.Currency {
				warn(c)
			}
			for _, r := range rates {
				if r.ProviderID == c.ProviderID && r.ModelName != "" && r.ModelName == k.model && r.Currency != c.Currency {
					warn(c)
				}
			}
		}
		type fixedKey struct{ provider, currency string }
		fixed := map[fixedKey]int64{}
		fixedNames := map[fixedKey]string{}
		for _, f := range window.FixedCosts {
			amount, err := ProrateChannelFixedCost(f, window.Start, window.End, window.Location)
			if err != nil {
				continue
			}
			if amount == 0 {
				continue
			}
			k := fixedKey{f.ProviderID, f.Currency}
			fixed[k] += amount
			fixedNames[k] = f.ProviderName
			if f.Currency != window.Currency {
				for _, c := range channels {
					if c.ProviderID == f.ProviderID {
						warn(c)
					}
				}
			}
		}
		for costKey, total := range fixed {
			provider := costKey.provider
			var candidates []key
			var requests int64
			for k, c := range channels {
				if c.ProviderID == provider && c.Requests > 0 && c.Currency == costKey.currency {
					candidates = append(candidates, k)
					requests += c.Requests
				}
			}
			sort.Slice(candidates, func(i, j int) bool { return candidates[i].model < candidates[j].model })
			if requests == 0 {
				c := get("", provider, fixedNames[costKey], costKey.currency)
				c.FixedCostMicros += total
				c.CostMicros += total
				negative := -total
				c.MarginMicros = &negative
				if c.Currency != window.Currency {
					warn(c)
				}
				continue
			}
			remaining := total
			for i, k := range candidates {
				c := channels[k]
				allocation := new(big.Int).Quo(new(big.Int).Mul(big.NewInt(total), big.NewInt(c.Requests)), big.NewInt(requests)).Int64()
				if i == len(candidates)-1 {
					allocation = remaining
				}
				remaining -= allocation
				c.FixedCostMicros += allocation
				c.CostMicros += allocation
				if c.MarginMicros != nil {
					*c.MarginMicros -= allocation
				} else if c.CostKnownRequests == c.Requests {
					margin := c.BilledMicros - c.CostMicros
					c.MarginMicros = &margin
				}
				if c.CurrencyMismatch {
					c.MarginMicros = nil
				}
			}
		}
	}
	models := make([]string, 0, len(order))
	for m := range order {
		models = append(models, m)
	}
	sort.Strings(models)
	out := make([]ModelChannelMargins, 0, len(models))
	for _, m := range models {
		group := ModelChannelMargins{ModelName: m}
		for _, k := range order[m] {
			c := channels[k]
			if c.MarginMicros != nil && *c.MarginMicros < 0 {
				c.Negative, c.Suggestion = true, negativeMarginSuggestion
				group.HasNegative = true
			}
			group.Channels = append(group.Channels, *c)
		}
		sort.SliceStable(group.Channels, func(i, j int) bool {
			if group.Channels[i].Requests != group.Channels[j].Requests {
				return group.Channels[i].Requests > group.Channels[j].Requests
			}
			if group.Channels[i].ProviderName != group.Channels[j].ProviderName {
				return group.Channels[i].ProviderName < group.Channels[j].ProviderName
			}
			return group.Channels[i].Currency < group.Channels[j].Currency
		})
		out = append(out, group)
	}
	return out
}

// ChannelMargins 读 [start,end) 内已结算的计费事实（按渠道 × 模型 × 币种聚合）与采购成本表。
func (s *Store) ChannelMargins(ctx context.Context, tenantID string, start, end time.Time) ([]ModelChannelMargins, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" || !end.After(start) {
		return nil, ErrInvalidUsage
	}
	rates, err := s.ListUpstreamRates(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `
		SELECT COALESCE(provider_id,''), COALESCE(NULLIF(MAX(provider_name),''),''), model_name, currency,
		       COUNT(*)::bigint, COUNT(upstream_cost_micros)::bigint,
		       COALESCE(SUM(billable_amount_micros),0)::bigint,
		       COALESCE(SUM(billable_amount_micros) FILTER (WHERE upstream_cost_micros IS NOT NULL),0)::bigint,
		       COALESCE(SUM(upstream_cost_micros),0)::bigint
		FROM billing_usage_facts
		WHERE tenant_id=$1 AND status='settled' AND usage_source NOT IN ('forward_proxy','reverse_proxy') AND occurred_at >= $2 AND occurred_at < $3 AND model_name <> ''
		GROUP BY 1, 3, 4
		LIMIT 5000`, tenantID, start, end)
	if err != nil {
		return nil, fmt.Errorf("channel margins: %w", err)
	}
	defer rows.Close()
	var usage []ChannelUsage
	for rows.Next() {
		var u ChannelUsage
		if err := rows.Scan(&u.ProviderID, &u.ProviderName, &u.ModelName, &u.Currency, &u.Requests, &u.CostKnownRequests, &u.BilledMicros, &u.BilledCostKnownMicros, &u.CostMicros); err != nil {
			return nil, err
		}
		usage = append(usage, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	fixed, err := s.ListChannelFixedCosts(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	cfg, err := s.GetEmployeeSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil {
		return nil, err
	}
	return BuildChannelMargins(rates, usage, ChannelMarginWindow{FixedCosts: fixed, Start: start, End: end, Location: loc, Currency: cfg.Currency}), nil
}
