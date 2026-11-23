package providers

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
)

// quotaCacheEntry holds a cached quota result with its expiry.
type quotaCacheEntry struct {
	quota     governor.EffectiveQuotaInput
	scoped    []governor.ScopedQuota
	mode      string
	expiresAt time.Time
}

// ScopedQuotas returns each applicable policy separately so the decider can
// compare it only with the matching scope snapshot.
func (q *QuotaCache) ScopedQuotas(ctx context.Context, ref governor.ScopeRef) ([]governor.ScopedQuota, error) {
	q.mu.Lock()
	if e, ok := q.cache[cacheKey(ref)]; ok && time.Now().Before(e.expiresAt) {
		out := append([]governor.ScopedQuota(nil), e.scoped...)
		q.mu.Unlock()
		return out, nil
	}
	q.mu.Unlock()

	eq, err := q.load(ctx, ref)
	if err != nil {
		return nil, err
	}
	return append([]governor.ScopedQuota(nil), eq.scoped...), nil
}

// QuotaCache reads effective quota policies from DB with an in-memory TTL cache.
// It satisfies the governor.QuotaProvider interface.
type QuotaCache struct {
	db  *pgxpool.Pool
	ttl time.Duration

	mu    sync.Mutex
	cache map[string]quotaCacheEntry
}

// NewQuotaCache creates a QuotaCache with the given TTL.
func NewQuotaCache(db *pgxpool.Pool, ttl time.Duration) *QuotaCache {
	return &QuotaCache{
		db:    db,
		ttl:   ttl,
		cache: make(map[string]quotaCacheEntry),
	}
}

// cacheKey builds a stable cache key for the ScopeRef.
func cacheKey(ref governor.ScopeRef) string {
	return ref.TenantID + "|" + ref.TeamID + "|" + ref.ProjectID + "|" + ref.UserID + "|" + ref.KeyID
}

// GetEnforcementMode returns the effective enforcement mode for the scope.
// The most-restrictive mode along the scope path wins (bypass < soft < enforce).
func (q *QuotaCache) GetEnforcementMode(ctx context.Context, ref governor.ScopeRef) string {
	q.mu.Lock()
	if e, ok := q.cache[cacheKey(ref)]; ok && time.Now().Before(e.expiresAt) {
		mode := e.mode
		q.mu.Unlock()
		return mode
	}
	q.mu.Unlock()

	eq, err := q.load(ctx, ref)
	if err != nil {
		log.Printf("[quota_cache] GetEnforcementMode load error: %v", err)
		return "soft" // fail-open: treat as soft on load error
	}
	return eq.mode
}

// EffectiveQuota returns the computed effective quota for the scope.
func (q *QuotaCache) EffectiveQuota(ctx context.Context, ref governor.ScopeRef) (governor.EffectiveQuotaInput, error) {
	q.mu.Lock()
	if e, ok := q.cache[cacheKey(ref)]; ok && time.Now().Before(e.expiresAt) {
		out := e.quota
		q.mu.Unlock()
		return out, nil
	}
	q.mu.Unlock()

	eq, err := q.load(ctx, ref)
	if err != nil {
		return governor.EffectiveQuotaInput{}, err
	}
	return eq.quota, nil
}

// rawPolicy holds columns returned by the minimal quota_policies query.
type rawPolicy struct {
	scopeType, scopeRef, keyID               string
	dailyTokenLimit, monthlyTokenLimit       int64
	dailyTokenBlocked, monthlyTokenBlocked   bool
	dailyBudgetMicros, monthlyBudgetMicros   int64
	dailyBudgetBlocked, monthlyBudgetBlocked bool
	rpmLimit                                 int64
	rpmBlocked                               bool
	tpmLimit                                 *int64
	tpmBlocked                               bool
	concurrencyLimit                         int64
	concurrencyBlocked                       bool
	overageAction, enforcementMode           string
	quotaTimezone                            string
	downgradeModel                           string // legacy rows only; new quota configuration rejects this action
}

// load fetches all policies for the ref from DB and computes the minimum-per-dimension quota.
func (q *QuotaCache) load(ctx context.Context, ref governor.ScopeRef) (quotaCacheEntry, error) {
	teamScopeIDs, err := q.loadTeamScopeIDs(ctx, ref.TenantID, ref.TeamID)
	if err != nil {
		return quotaCacheEntry{}, err
	}
	// Fetch all active policies for this tenant that apply to any of the 5 scopes.
	// We use a single query with an IN clause across scope_type + relevant ID.
	const query = `
			SELECT scope_type,
			       COALESCE(scope_ref, ''),
			       COALESCE(key_id, ''),
		       COALESCE(daily_token_limit_canonical, GREATEST(COALESCE(daily_token_limit, 0), 0)),
		       COALESCE(monthly_token_limit_canonical, GREATEST(COALESCE(monthly_token_limit, 0), 0)),
		       COALESCE(daily_token_blocked, false),
		       COALESCE(monthly_token_blocked, false),
		       COALESCE(daily_budget_micros, CASE WHEN COALESCE(daily_budget_limit,0) > 0 THEN ROUND(daily_budget_limit * 1000000)::bigint ELSE 0 END),
		       COALESCE(monthly_budget_micros, CASE WHEN COALESCE(monthly_budget_limit,0) > 0 THEN ROUND(monthly_budget_limit * 1000000)::bigint ELSE 0 END),
		       COALESCE(daily_budget_blocked, false),
		       COALESCE(monthly_budget_blocked, false),
			       COALESCE(rpm_limit_canonical, GREATEST(COALESCE(rpm_limit, 0), 0)),
			       COALESCE(rpm_blocked, false),
			       tpm_limit,
			       COALESCE(tpm_blocked, false),
			       COALESCE(concurrency_limit_canonical, GREATEST(COALESCE(concurrency_limit, 0), 0)),
			       COALESCE(concurrency_blocked, false),
		       COALESCE(overage_action, 'notify'),
		       COALESCE(enforcement_mode, 'soft'),
		       COALESCE(quota_timezone, 'Asia/Shanghai'),
		       COALESCE(downgrade_model, '')
			FROM quota_policies qp
			WHERE qp.tenant_id = $1
			  AND qp.status = 'active'
			  AND (
			    (scope_type = 'tenant')
			    OR (scope_type = 'project'  AND COALESCE(project_id,'')  = $2 AND $2 != '')
			    OR (scope_type = 'user'     AND COALESCE(user_id,'')     = $3 AND $3 != '')
			    OR (scope_type = 'key' AND key_id = $4 AND $4 != ''
			        AND EXISTS (SELECT 1 FROM internal_keys owned_key
			                    WHERE owned_key.id = $4 AND owned_key.tenant_id = $1))
			    OR (scope_type = 'team'     AND COALESCE(scope_ref,'') = ANY($5::text[]))
		  )
		ORDER BY created_at
	`

	rows, err := q.db.Query(ctx, query,
		ref.TenantID,
		ref.ProjectID,
		ref.UserID,
		ref.KeyID,
		teamScopeIDs,
	)
	if err != nil {
		return quotaCacheEntry{}, err
	}
	defer rows.Close()

	var policies []rawPolicy
	for rows.Next() {
		var p rawPolicy
		if err := rows.Scan(
			&p.scopeType,
			&p.scopeRef,
			&p.keyID,
			&p.dailyTokenLimit, &p.monthlyTokenLimit,
			&p.dailyTokenBlocked, &p.monthlyTokenBlocked,
			&p.dailyBudgetMicros, &p.monthlyBudgetMicros,
			&p.dailyBudgetBlocked, &p.monthlyBudgetBlocked,
			&p.rpmLimit, &p.rpmBlocked, &p.tpmLimit, &p.tpmBlocked,
			&p.concurrencyLimit, &p.concurrencyBlocked,
			&p.overageAction, &p.enforcementMode,
			&p.quotaTimezone,
			&p.downgradeModel,
		); err != nil {
			if err == pgx.ErrNoRows {
				break
			}
			return quotaCacheEntry{}, err
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return quotaCacheEntry{}, err
	}
	teamPolicies := make(map[string]struct{}, len(teamScopeIDs))
	for _, policy := range policies {
		if policy.scopeType == "team" {
			teamPolicies[policy.scopeRef] = struct{}{}
		}
	}
	for _, teamID := range teamScopeIDs {
		if _, exists := teamPolicies[teamID]; !exists {
			policies = append(policies, rawPolicy{scopeType: "team", scopeRef: teamID, enforcementMode: "accounting", quotaTimezone: "Asia/Shanghai"})
		}
	}

	eq, mode := computeEffective(policies, ref)
	scoped := computeScopedQuotas(policies, ref)
	q.attachScopeNames(ctx, ref, scoped)
	entry := quotaCacheEntry{
		quota:     eq,
		scoped:    scoped,
		mode:      mode,
		expiresAt: time.Now().Add(q.ttl),
	}

	k := cacheKey(ref)
	q.mu.Lock()
	q.cache[k] = entry
	q.mu.Unlock()

	return entry, nil
}

// attachScopeNames 为团队/租户作用域补上展示名（部门名称），仅用于预算断流的中文提示。
// 查询失败不影响准入：提示里退回通用称呼。
func (q *QuotaCache) attachScopeNames(ctx context.Context, ref governor.ScopeRef, scoped []governor.ScopedQuota) {
	teamIDs := make([]string, 0, len(scoped))
	for _, quota := range scoped {
		if quota.Scope == "team" {
			teamIDs = append(teamIDs, quota.ID)
		}
	}
	if len(teamIDs) == 0 || q.db == nil {
		return
	}
	rows, err := q.db.Query(ctx, `SELECT id, name FROM teams WHERE tenant_id = $1 AND id = ANY($2::text[])`, ref.TenantID, teamIDs)
	if err != nil {
		return
	}
	defer rows.Close()
	names := map[string]string{}
	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) == nil {
			names[id] = name
		}
	}
	for index := range scoped {
		if scoped[index].Scope == "team" {
			scoped[index].Name = names[scoped[index].ID]
		}
	}
}

func (q *QuotaCache) loadTeamScopeIDs(ctx context.Context, tenantID, directTeamID string) ([]string, error) {
	if directTeamID == "" {
		return nil, nil
	}
	rows, err := q.db.Query(ctx, `
		SELECT ancestor.id
		FROM teams direct_team
		CROSS JOIN LATERAL unnest(string_to_array(trim(BOTH '/' FROM direct_team.path), '/')) WITH ORDINALITY path_id(id, ord)
		JOIN teams ancestor
		  ON ancestor.id = path_id.id
		 AND ancestor.tenant_id = direct_team.tenant_id
		WHERE direct_team.tenant_id = $1 AND direct_team.id = $2
		ORDER BY path_id.ord
	`, tenantID, directTeamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if id != "" {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

func computeScopedQuotas(policies []rawPolicy, ref governor.ScopeRef) []governor.ScopedQuota {
	out := make([]governor.ScopedQuota, 0, len(policies))
	for _, policy := range policies {
		id := ""
		switch policy.scopeType {
		case "tenant":
			id = ref.TenantID
		case "team":
			id = policy.scopeRef
		case "project":
			id = ref.ProjectID
		case "user":
			id = ref.UserID
		case "key":
			if policy.keyID == "" {
				continue
			}
			id = ref.KeyID
		}
		if id == "" {
			continue
		}
		mode := policy.enforcementMode
		if mode != "enforce" && mode != "bypass" && mode != "accounting" {
			mode = "soft"
		}
		out = append(out, governor.ScopedQuota{
			Scope:           policy.scopeType,
			ID:              id,
			EnforcementMode: mode,
			Limits: governor.EffectiveQuotaInput{
				MonthlyTokenLimit:    policy.monthlyTokenLimit,
				MonthlyTokenBlocked:  policy.monthlyTokenBlocked,
				MonthlyBudgetMicros:  policy.monthlyBudgetMicros,
				MonthlyBudgetBlocked: policy.monthlyBudgetBlocked,
				DailyTokenLimit:      policy.dailyTokenLimit,
				DailyTokenBlocked:    policy.dailyTokenBlocked,
				DailyBudgetMicros:    policy.dailyBudgetMicros,
				DailyBudgetBlocked:   policy.dailyBudgetBlocked,
				RPMLimit:             policy.rpmLimit,
				RPMBlocked:           policy.rpmBlocked,
				ConcurrencyLimit:     policy.concurrencyLimit,
				ConcurrencyBlocked:   policy.concurrencyBlocked,
				QuotaTimezone:        policy.quotaTimezone,
				OverageAction:        policy.overageAction,
				DowngradeTo:          policy.downgradeModel,
			},
		})
		if policy.tpmLimit != nil {
			out[len(out)-1].Limits.TPMConfigured = true
			out[len(out)-1].Limits.TPMLimit = *policy.tpmLimit
		}
		out[len(out)-1].Limits.TPMBlocked = policy.tpmBlocked
	}
	return out
}

// modeRank converts mode strings to a numeric rank so we can pick the strictest one.
// bypass (0) < soft (1) < enforce (2)
func modeRank(m string) int {
	switch m {
	case "enforce":
		return 2
	case "soft":
		return 1
	default:
		return 0
	}
}

// computeEffective applies minimum-wins logic across all scope policies.
func computeEffective(policies []rawPolicy, _ governor.ScopeRef) (governor.EffectiveQuotaInput, string) {
	if len(policies) == 0 {
		return governor.EffectiveQuotaInput{}, "soft"
	}

	var eq governor.EffectiveQuotaInput
	effectiveMode := "soft"
	triggeredScope := ""

	for _, p := range policies {
		// Pick strictest enforcement mode
		if modeRank(p.enforcementMode) > modeRank(effectiveMode) {
			effectiveMode = p.enforcementMode
		}

		// Minimum-wins per limit dimension (0 = unconstrained)
		if p.monthlyTokenLimit > 0 && (eq.MonthlyTokenLimit == 0 || p.monthlyTokenLimit < eq.MonthlyTokenLimit) {
			eq.MonthlyTokenLimit = p.monthlyTokenLimit
			triggeredScope = p.scopeType
		}
		if p.dailyTokenLimit > 0 && (eq.DailyTokenLimit == 0 || p.dailyTokenLimit < eq.DailyTokenLimit) {
			eq.DailyTokenLimit = p.dailyTokenLimit
		}
		if p.monthlyBudgetMicros > 0 && (eq.MonthlyBudgetMicros == 0 || p.monthlyBudgetMicros < eq.MonthlyBudgetMicros) {
			eq.MonthlyBudgetMicros = p.monthlyBudgetMicros
		}
		if p.dailyBudgetMicros > 0 && (eq.DailyBudgetMicros == 0 || p.dailyBudgetMicros < eq.DailyBudgetMicros) {
			eq.DailyBudgetMicros = p.dailyBudgetMicros
		}
		if p.rpmLimit > 0 && (eq.RPMLimit == 0 || p.rpmLimit < eq.RPMLimit) {
			eq.RPMLimit = p.rpmLimit
		}
		if p.tpmLimit != nil {
			eq.TPMConfigured = true
			if *p.tpmLimit > 0 && (eq.TPMLimit == 0 || *p.tpmLimit < eq.TPMLimit) {
				eq.TPMLimit = *p.tpmLimit
			}
		}
		eq.TPMBlocked = eq.TPMBlocked || p.tpmBlocked
		eq.RPMBlocked = eq.RPMBlocked || p.rpmBlocked
		eq.ConcurrencyBlocked = eq.ConcurrencyBlocked || p.concurrencyBlocked
		eq.DailyTokenBlocked = eq.DailyTokenBlocked || p.dailyTokenBlocked
		eq.MonthlyTokenBlocked = eq.MonthlyTokenBlocked || p.monthlyTokenBlocked
		eq.DailyBudgetBlocked = eq.DailyBudgetBlocked || p.dailyBudgetBlocked
		eq.MonthlyBudgetBlocked = eq.MonthlyBudgetBlocked || p.monthlyBudgetBlocked
		if p.concurrencyLimit > 0 && (eq.ConcurrencyLimit == 0 || p.concurrencyLimit < eq.ConcurrencyLimit) {
			eq.ConcurrencyLimit = p.concurrencyLimit
		}

		// Carry overage action from any enforcing policy (last writer wins for overageAction)
		if p.overageAction != "notify" && p.overageAction != "" {
			eq.OverageAction = p.overageAction
			eq.DowngradeTo = p.downgradeModel
		}
	}

	eq.TriggeredScope = triggeredScope
	return eq, effectiveMode
}
