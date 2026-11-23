package forecast

// QuotaParams holds the configuration for quota enforcement simulation.
type QuotaParams struct {
	MonthlyBudgetLimit float64 `json:"monthly_budget_limit"`
	MonthlyTokenLimit  int64   `json:"monthly_token_limit"`
	OverageAction      string  `json:"overage_action"`
	// DowngradeRatio：降级后剩余成本占原成本的比例（0.5 = 降级后仍花原价 50%）。
	// 节省 = Cost × (1 - DowngradeRatio)。默认 0.5 偏保守，避免高估节省；
	// 实际值随降级目标模型价格比而定，应由调用方按路由策略传入。
	DowngradeRatio float64 `json:"downgrade_ratio"`
}

// ReplayRow represents a single request log row for replay.
type ReplayRow struct {
	Cost   float64
	Tokens int64
	UserID string
}

// ReplayResult holds the aggregate results of a dry-run replay.
type ReplayResult struct {
	Total         int            `json:"total"`
	Intercepted   int            `json:"intercepted"`
	SavedUSD      float64        `json:"saved_usd"`
	SavedCNY      float64        `json:"saved_cny"`
	AffectedUsers int            `json:"affected_users"`
	ByAction      map[string]int `json:"by_action"`
}

// Simulator replays historical request rows against quota params (pure function, zero side effects).
type Simulator struct {
	params QuotaParams
	fxRate float64
}

// NewSimulator creates a new Simulator with a default fx rate of 7.20.
func NewSimulator(params QuotaParams) *Simulator {
	return &Simulator{params: params, fxRate: 7.20}
}

// SetFxRate sets the USD-to-CNY exchange rate (ignored if <= 0).
func (s *Simulator) SetFxRate(r float64) {
	if r > 0 {
		s.fxRate = r
	}
}

// Replay runs the quota enforcement logic over rows in order, accumulating cost/tokens,
// and counting intercepted requests. Pure memory operation, no DB or IO side effects.
func (s *Simulator) Replay(rows []ReplayRow) ReplayResult {
	res := ReplayResult{Total: len(rows), ByAction: map[string]int{}}
	affected := map[string]bool{}
	var cumCost float64
	var cumTokens int64
	ratio := s.params.DowngradeRatio
	if ratio <= 0 {
		ratio = 0.5 // 保守默认（原 0.1 过度乐观）
	}

	for _, row := range rows {
		cumCost += row.Cost
		cumTokens += row.Tokens
		over := (s.params.MonthlyBudgetLimit > 0 && cumCost >= s.params.MonthlyBudgetLimit) ||
			(s.params.MonthlyTokenLimit > 0 && cumTokens >= s.params.MonthlyTokenLimit)
		if !over {
			continue
		}
		res.Intercepted++
		affected[row.UserID] = true
		switch s.params.OverageAction {
		case "downgrade_model":
			res.SavedUSD += row.Cost * (1 - ratio)
			res.ByAction["downgrade_model"]++
		case "rate_limit", "pause_key":
			res.SavedUSD += row.Cost
			res.ByAction[s.params.OverageAction]++
		default:
			res.ByAction["alert"]++
		}
	}
	res.SavedCNY = res.SavedUSD * s.fxRate
	res.AffectedUsers = len(affected)
	return res
}
