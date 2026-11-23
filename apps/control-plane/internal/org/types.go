package org

import "time"

type Team struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Name         string    `json:"name"`
	ParentTeamID string    `json:"parent_team_id,omitempty"`
	Path         string    `json:"path"`
	CreatedAt    time.Time `json:"created_at"`
}

type TeamMember struct {
	TeamID    string    `json:"team_id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type ScopeRef struct {
	TenantID  string
	TeamID    string
	ProjectID string
	UserID    string
	KeyID     string
}

// DefaultAccountingTimezone is the timezone the gateway accounts a scope in
// when that scope has no quota policy of its own. It must stay in sync with
// gateway-core addAdmissionAccountingScopes, which hardcodes "Asia/Shanghai"
// for every accounting-only scope (and with normalizedQuotaTimezone's empty
// default there).
const DefaultAccountingTimezone = "Asia/Shanghai"

// EffectiveQuota is the minimum-wins merge of every policy on the scope path.
// Money limits are integer micros (1 CNY = 1_000_000); 0 means unconstrained.
type EffectiveQuota struct {
	DailyTokenLimit     int64  `json:"daily_token_limit"`
	MonthlyTokenLimit   int64  `json:"monthly_token_limit"`
	DailyBudgetMicros   int64  `json:"daily_budget_micros"`
	MonthlyBudgetMicros int64  `json:"monthly_budget_micros"`
	RPMLimit            int    `json:"rpm_limit"`
	ConcurrencyLimit    int    `json:"concurrency_limit"`
	TriggeredScope      string `json:"triggered_scope"`
	// QuotaTimezone is the timezone of the policy on the most specific scope
	// (key > user > project > team > tenant); empty when no policy exists.
	QuotaTimezone string `json:"quota_timezone,omitempty"`
}
