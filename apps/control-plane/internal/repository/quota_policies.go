package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// QuotaPolicy represents a quota policy
type QuotaPolicy struct {
	ID                         string
	TenantID                   string
	ProjectID                  string
	ScopeType                  string
	ScopeRef                   string
	UserID                     string // user scope 时填
	KeyID                      string // key scope 的稳定 internal_keys.id
	KeyPrefix                  string // key scope 时填
	DailyTokenLimit            int64
	MonthlyTokenLimit          int64
	DailyTokenLimitCanonical   *int64
	MonthlyTokenLimitCanonical *int64
	DailyTokenBlocked          bool
	MonthlyTokenBlocked        bool
	DailyTokenCanonical        bool
	MonthlyTokenCanonical      bool
	DailyBudgetLimit           float64 // 新增字段
	MonthlyBudgetLimit         float64
	DailyBudgetMicros          *int64
	MonthlyBudgetMicros        *int64
	DailyBudgetBlocked         bool
	MonthlyBudgetBlocked       bool
	DailyBudgetCanonical       bool
	MonthlyBudgetCanonical     bool
	RPMLimit                   int
	RPMLimitCanonical          *int
	RPMBlocked                 bool
	RPMCanonical               bool
	TPMLimit                   *int64
	TPMBlocked                 bool
	ConcurrencyLimit           int
	ConcurrencyLimitCanonical  *int
	ConcurrencyBlocked         bool
	ConcurrencyCanonical       bool
	OverageAction              string
	EnforcementMode            string // soft | enforce | bypass
	QuotaTimezone              string
	QuotaTimezoneCanonical     bool
	Status                     string
	CreatedAt                  time.Time
}

// QuotaPolicyRepository handles quota policy database operations
type QuotaPolicyRepository struct {
	db *pgxpool.Pool
}

// NewQuotaPolicyRepository creates a new quota policy repository
func NewQuotaPolicyRepository(db *pgxpool.Pool) *QuotaPolicyRepository {
	return &QuotaPolicyRepository{db: db}
}

// scanQuotaPolicy scans a single row into a QuotaPolicy struct (shared helper).
func scanQuotaPolicy(row interface {
	Scan(dest ...any) error
}) (*QuotaPolicy, error) {
	var p QuotaPolicy
	err := row.Scan(
		&p.ID, &p.TenantID, &p.ProjectID, &p.ScopeType, &p.ScopeRef,
		&p.UserID, &p.KeyID, &p.KeyPrefix,
		&p.DailyTokenLimit, &p.MonthlyTokenLimit,
		&p.DailyTokenLimitCanonical, &p.MonthlyTokenLimitCanonical,
		&p.DailyTokenBlocked, &p.MonthlyTokenBlocked,
		&p.DailyBudgetLimit, &p.MonthlyBudgetLimit,
		&p.DailyBudgetMicros, &p.MonthlyBudgetMicros,
		&p.DailyBudgetBlocked, &p.MonthlyBudgetBlocked,
		&p.RPMLimit, &p.RPMLimitCanonical, &p.RPMBlocked,
		&p.TPMLimit, &p.TPMBlocked,
		&p.ConcurrencyLimit, &p.ConcurrencyLimitCanonical, &p.ConcurrencyBlocked,
		&p.OverageAction, &p.EnforcementMode, &p.QuotaTimezone,
		&p.Status, &p.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	p.DailyBudgetCanonical = true
	p.MonthlyBudgetCanonical = true
	p.DailyTokenCanonical = true
	p.MonthlyTokenCanonical = true
	p.RPMCanonical = true
	p.ConcurrencyCanonical = true
	p.QuotaTimezoneCanonical = true
	return &p, nil
}

const quotaPolicyCols = `
	id, tenant_id, COALESCE(project_id,''), scope_type, COALESCE(scope_ref,''),
	COALESCE(user_id,''), COALESCE(key_id,''), COALESCE(key_prefix,''),
	COALESCE(daily_token_limit,0), COALESCE(monthly_token_limit,0),
	daily_token_limit_canonical, monthly_token_limit_canonical,
	COALESCE(daily_token_blocked,false), COALESCE(monthly_token_blocked,false),
	COALESCE(daily_budget_limit,0), COALESCE(monthly_budget_limit,0),
	daily_budget_micros, monthly_budget_micros,
	COALESCE(daily_budget_blocked,false), COALESCE(monthly_budget_blocked,false),
	COALESCE(rpm_limit,0), rpm_limit_canonical, COALESCE(rpm_blocked,false),
	tpm_limit, COALESCE(tpm_blocked,false),
	COALESCE(concurrency_limit,0), concurrency_limit_canonical, COALESCE(concurrency_blocked,false),
	COALESCE(overage_action,'notify'), COALESCE(enforcement_mode,'soft'),
	COALESCE(quota_timezone,'Asia/Shanghai'),
	status, created_at
`

// GetByProject retrieves quota policy for a project within a tenant.
func (r *QuotaPolicyRepository) GetByProject(ctx context.Context, tenantID, projectID string) (*QuotaPolicy, error) {
	query := `SELECT ` + quotaPolicyCols + `
		FROM quota_policies
		WHERE tenant_id = $1 AND project_id = $2 AND scope_type = 'project' AND status = 'active'
	`
	row := r.db.QueryRow(ctx, query, tenantID, projectID)
	p, err := scanQuotaPolicy(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get quota policy: %w", err)
	}
	return p, nil
}

// GetByScope retrieves a quota policy by tenant + scope type + relevant scope identifier.
// For tenant scope, all other scope params are ignored.
func (r *QuotaPolicyRepository) GetByScope(ctx context.Context,
	tenantID, scopeType, projectID, teamID, userID, keyID string) (*QuotaPolicy, error) {

	var conditions string
	args := []any{tenantID, scopeType}
	switch scopeType {
	case "tenant":
		conditions = ""
	case "team":
		conditions = " AND scope_ref = $3"
		args = append(args, teamID)
	case "project":
		conditions = " AND project_id = $3"
		args = append(args, projectID)
	case "user":
		conditions = " AND user_id = $3"
		args = append(args, userID)
	case "key":
		conditions = ` AND (
			(key_id = $3 AND EXISTS (
				SELECT 1 FROM internal_keys ik WHERE ik.id = $3 AND ik.tenant_id = $1
			))
			OR (
				key_id IS NULL
				AND key_prefix = (SELECT target.key_prefix FROM internal_keys target WHERE target.id = $3 AND target.tenant_id = $1)
				AND 1 = (
					SELECT COUNT(*) FROM internal_keys sibling
					WHERE sibling.tenant_id = $1
					  AND sibling.key_prefix = (SELECT target.key_prefix FROM internal_keys target WHERE target.id = $3 AND target.tenant_id = $1)
				)
				AND 1 = (
					SELECT COUNT(*) FROM quota_policies legacy
					WHERE legacy.tenant_id = $1 AND legacy.scope_type = 'key'
					  AND legacy.key_id IS NULL AND legacy.key_prefix = quota_policies.key_prefix
				)
			)
		) ORDER BY (key_id = $3) DESC, created_at DESC`
		args = append(args, keyID)
	default:
		return nil, fmt.Errorf("invalid scope_type: %s", scopeType)
	}

	query := `SELECT ` + quotaPolicyCols + `
		FROM quota_policies
		WHERE tenant_id = $1 AND scope_type = $2 AND status = 'active'
	` + conditions + ` LIMIT 1`

	row := r.db.QueryRow(ctx, query, args...)
	p, err := scanQuotaPolicy(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return p, nil
}

// List retrieves quota policies for a tenant
func (r *QuotaPolicyRepository) List(ctx context.Context, tenantID string) ([]*QuotaPolicy, error) {
	query := `SELECT ` + quotaPolicyCols + `
		FROM quota_policies
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list quota policies: %w", err)
	}
	defer rows.Close()

	policies := []*QuotaPolicy{}
	for rows.Next() {
		p, err := scanQuotaPolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, nil
}

// ListKeyScopePolicies returns every ACTIVE key-scope quota policy that applies
// to one stable key id, ordered by created_at ascending.
//
// The WHERE clause is intentionally equivalent to the key branch of
// gateway-core quota_cache.go:
//
//	scope_type = 'key' AND key_id = $2 AND $2 != ''
//	  AND EXISTS (SELECT 1 FROM internal_keys owned_key
//	              WHERE owned_key.id = $2 AND owned_key.tenant_id = $1)
//	AND status = 'active'
//
// It deliberately does NOT reuse GetByScope: that helper still carries a legacy
// key_prefix fallback branch (match the single sibling key carrying that
// prefix) that the gateway has no equivalent for. A prefix-matched policy would
// hand the read model a timezone whose bucket the gateway never writes.
//
// The projection keeps canonical zero overrides and converts positive legacy
// decimal money with PostgreSQL ROUND, exactly like the gateway.
func (r *QuotaPolicyRepository) ListKeyScopePolicies(ctx context.Context, tenantID, keyID string) ([]*QuotaPolicy, error) {
	if tenantID == "" || keyID == "" {
		return nil, nil
	}
	return r.ListAccountingScopePolicies(ctx, tenantID, "key", keyID)
}

// ListAccountingScopePolicies reads only policies on the requested scope, using
// the gateway SQL projection rather than the inherited effective quota.
func (r *QuotaPolicyRepository) ListAccountingScopePolicies(ctx context.Context, tenantID, scopeType, scopeID string) ([]*QuotaPolicy, error) {
	var condition string
	switch scopeType {
	case "tenant":
		condition = " AND qp.tenant_id = $3"
	case "team":
		condition = " AND qp.scope_ref = $3"
	case "project":
		condition = " AND qp.project_id = $3"
	case "user":
		condition = " AND qp.user_id = $3"
	case "key":
		condition = ` AND qp.key_id = $3 AND $3 != ''
			AND EXISTS (SELECT 1 FROM internal_keys owned_key
			            WHERE owned_key.id = $3 AND owned_key.tenant_id = $1)`
	default:
		return nil, fmt.Errorf("invalid accounting scope: %s", scopeType)
	}
	cols := strings.Replace(quotaPolicyCols, "daily_budget_micros, monthly_budget_micros,", `
		COALESCE(daily_budget_micros, CASE WHEN COALESCE(daily_budget_limit,0) > 0 THEN ROUND(daily_budget_limit * 1000000)::bigint ELSE 0 END),
		COALESCE(monthly_budget_micros, CASE WHEN COALESCE(monthly_budget_limit,0) > 0 THEN ROUND(monthly_budget_limit * 1000000)::bigint ELSE 0 END),`, 1)
	query := `SELECT ` + cols + ` FROM quota_policies qp
		WHERE qp.tenant_id = $1 AND qp.status = 'active' AND qp.scope_type = $2` + condition + ` ORDER BY qp.created_at`
	rows, err := r.db.Query(ctx, query, tenantID, scopeType, scopeID)
	if err != nil {
		return nil, fmt.Errorf("failed to list key scope quota policies: %w", err)
	}
	defer rows.Close()

	policies := []*QuotaPolicy{}
	for rows.Next() {
		p, err := scanQuotaPolicy(rows)
		if err != nil {
			return nil, err
		}
		// Project the limit columns exactly as the gateway does, so the
		// effective-policy test cannot disagree with admission.
		if p.DailyTokenLimitCanonical != nil {
			p.DailyTokenLimit = *p.DailyTokenLimitCanonical
		} else if p.DailyTokenLimit < 0 {
			p.DailyTokenLimit = 0
		}
		if p.MonthlyTokenLimitCanonical != nil {
			p.MonthlyTokenLimit = *p.MonthlyTokenLimitCanonical
		} else if p.MonthlyTokenLimit < 0 {
			p.MonthlyTokenLimit = 0
		}
		if p.RPMLimitCanonical != nil {
			p.RPMLimit = *p.RPMLimitCanonical
		} else if p.RPMLimit < 0 {
			p.RPMLimit = 0
		}
		if p.ConcurrencyLimitCanonical != nil {
			p.ConcurrencyLimit = *p.ConcurrencyLimitCanonical
		} else if p.ConcurrencyLimit < 0 {
			p.ConcurrencyLimit = 0
		}
		if strings.TrimSpace(p.QuotaTimezone) == "" {
			p.QuotaTimezone = DefaultQuotaTimezone
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

func (r *QuotaPolicyRepository) AccountingScopeOwned(ctx context.Context, tenantID, scopeType, scopeID string) (bool, error) {
	if scopeType == "tenant" {
		return tenantID == scopeID, nil
	}
	var table string
	switch scopeType {
	case "team":
		table = "teams"
	case "project":
		table = "projects"
	case "user":
		table = "users"
	case "key":
		table = "internal_keys"
	default:
		return false, fmt.Errorf("invalid accounting scope: %s", scopeType)
	}
	var exists bool
	err := r.db.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+table+" WHERE tenant_id=$1 AND id=$2)", tenantID, scopeID).Scan(&exists)
	return exists, err
}

// CreateOrUpdate creates or updates a quota policy
func (r *QuotaPolicyRepository) CreateOrUpdate(ctx context.Context, policy *QuotaPolicy) error {
	quotaTimezoneCanonical := policy != nil && policy.QuotaTimezoneCanonical
	if err := NormalizeQuotaPolicy(policy); err != nil {
		return err
	}
	projectID := nullableString(policy.ProjectID)
	scopeRef := nullableString(policy.ScopeRef)
	userID := nullableString(policy.UserID)
	keyPrefix := nullableString(policy.KeyPrefix)
	keyID := nullableString(policy.KeyID)

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if policy.ScopeType == "key" {
		if policy.KeyID == "" {
			return fmt.Errorf("stable key id is required for key quota policy")
		}
		lockKey := fmt.Sprintf("quota-policy-key:%d:%s:%s", len(policy.TenantID), policy.TenantID, policy.KeyID)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
			return fmt.Errorf("failed to lock key quota policy: %w", err)
		}
		// Prevent a concurrent same-prefix key insert from invalidating the
		// uniqueness decision while a legacy row is upgraded.
		if _, err := tx.Exec(ctx, `LOCK TABLE internal_keys IN SHARE MODE`); err != nil {
			return fmt.Errorf("failed to stabilize key identity: %w", err)
		}
		var validIdentity bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM internal_keys
				WHERE tenant_id = $1 AND id = $2 AND key_prefix = $3
			)
		`, policy.TenantID, policy.KeyID, policy.KeyPrefix).Scan(&validIdentity); err != nil {
			return fmt.Errorf("failed to validate key quota identity: %w", err)
		}
		if !validIdentity {
			return fmt.Errorf("key quota identity does not belong to tenant")
		}
	}

	var existingID string
	err = tx.QueryRow(ctx, `
		SELECT id
		FROM quota_policies
		WHERE tenant_id = $1
		  AND scope_type = $3
		  AND (
			    ($3 = 'key' AND (
			      ($7::varchar IS NOT NULL AND key_id = $7::varchar)
			      OR (
			        key_id IS NULL
			        AND key_prefix IS NOT DISTINCT FROM $6::varchar
			        AND (SELECT COUNT(*) FROM internal_keys ik WHERE ik.tenant_id = $1 AND ik.key_prefix = $6::varchar) = 1
			        AND (SELECT COUNT(*) FROM quota_policies legacy
			             WHERE legacy.tenant_id = $1 AND legacy.scope_type = 'key'
			               AND legacy.key_id IS NULL
			               AND legacy.key_prefix IS NOT DISTINCT FROM $6::varchar) = 1
			      )
		    ))
		    OR ($3 <> 'key'
		      AND project_id IS NOT DISTINCT FROM $2::varchar
		      AND scope_ref IS NOT DISTINCT FROM $4::varchar
		      AND user_id IS NOT DISTINCT FROM $5::varchar
		      AND key_prefix IS NOT DISTINCT FROM $6::varchar
		      AND key_id IS NULL
		    )
		  )
		ORDER BY (key_id IS NOT DISTINCT FROM $7::varchar) DESC
		LIMIT 1
		FOR UPDATE
	`, policy.TenantID, projectID, policy.ScopeType, scopeRef, userID, keyPrefix, keyID).Scan(&existingID)

	switch err {
	case nil:
		policy.ID = existingID
		err = tx.QueryRow(ctx, `
			UPDATE quota_policies
			SET scope_ref                       = $2,
			    user_id                         = $3,
			    key_id                          = $4,
			    key_prefix                      = $5,
			    daily_token_limit               = $6,
			    monthly_token_limit             = $7,
			    daily_token_limit_canonical     = $8,
			    monthly_token_limit_canonical   = $9,
			    daily_token_blocked             = $10,
			    monthly_token_blocked           = $11,
			    daily_budget_limit              = $12,
			    monthly_budget_limit            = $13,
			    daily_budget_micros             = $14,
			    monthly_budget_micros           = $15,
			    daily_budget_blocked            = $16,
			    monthly_budget_blocked          = $17,
			    rpm_limit                       = $18,
			    rpm_limit_canonical             = $19,
			    rpm_blocked                     = $20,
			    tpm_limit                       = $21,
			    tpm_blocked                     = $22,
			    concurrency_limit               = $23,
			    concurrency_limit_canonical     = $24,
			    concurrency_blocked             = $25,
			    overage_action                  = $26,
			    enforcement_mode                = $27,
			    quota_timezone                  = CASE WHEN $28 THEN $29 ELSE quota_timezone END,
			    status                          = $30
			WHERE id = $1
			RETURNING quota_timezone
			`, policy.ID, scopeRef, userID, keyID, keyPrefix,
			policy.DailyTokenLimit, policy.MonthlyTokenLimit,
			policy.DailyTokenLimitCanonical, policy.MonthlyTokenLimitCanonical,
			policy.DailyTokenBlocked, policy.MonthlyTokenBlocked,
			policy.DailyBudgetLimit, policy.MonthlyBudgetLimit,
			policy.DailyBudgetMicros, policy.MonthlyBudgetMicros,
			policy.DailyBudgetBlocked, policy.MonthlyBudgetBlocked,
			policy.RPMLimit, policy.RPMLimitCanonical, policy.RPMBlocked,
			policy.TPMLimit, policy.TPMBlocked,
			policy.ConcurrencyLimit, policy.ConcurrencyLimitCanonical, policy.ConcurrencyBlocked,
			policy.OverageAction, policy.EnforcementMode,
			quotaTimezoneCanonical, policy.QuotaTimezone, policy.Status,
		).Scan(&policy.QuotaTimezone)
		if err != nil {
			return fmt.Errorf("failed to update quota policy: %w", err)
		}
	case pgx.ErrNoRows:
		if policy.ID == "" {
			policy.ID = "qpol_" + uuid.New().String()[:8]
		}
		err = tx.QueryRow(ctx, `
			INSERT INTO quota_policies
			  (id, tenant_id, project_id, scope_type, scope_ref,
			   user_id, key_id, key_prefix,
			   daily_token_limit, monthly_token_limit,
			   daily_token_limit_canonical, monthly_token_limit_canonical,
			   daily_token_blocked, monthly_token_blocked,
			   daily_budget_limit, monthly_budget_limit,
			   daily_budget_micros, monthly_budget_micros,
			   daily_budget_blocked, monthly_budget_blocked,
			   rpm_limit, rpm_limit_canonical, rpm_blocked,
			   tpm_limit, tpm_blocked,
			   concurrency_limit, concurrency_limit_canonical, concurrency_blocked,
			   overage_action, enforcement_mode, quota_timezone, status)
			VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
				$12, $13, $14, $15, $16, $17, $18, $19, $20, $21,
				$22, $23, $24, $25, $26, $27, $28, $29, $30,
				$31, $32
			)
			RETURNING quota_timezone
		`, policy.ID, policy.TenantID, projectID, policy.ScopeType, scopeRef,
			userID, keyID, keyPrefix,
			policy.DailyTokenLimit, policy.MonthlyTokenLimit,
			policy.DailyTokenLimitCanonical, policy.MonthlyTokenLimitCanonical,
			policy.DailyTokenBlocked, policy.MonthlyTokenBlocked,
			policy.DailyBudgetLimit, policy.MonthlyBudgetLimit,
			policy.DailyBudgetMicros, policy.MonthlyBudgetMicros,
			policy.DailyBudgetBlocked, policy.MonthlyBudgetBlocked,
			policy.RPMLimit, policy.RPMLimitCanonical, policy.RPMBlocked,
			policy.TPMLimit, policy.TPMBlocked,
			policy.ConcurrencyLimit, policy.ConcurrencyLimitCanonical, policy.ConcurrencyBlocked,
			policy.OverageAction, policy.EnforcementMode, policy.QuotaTimezone, policy.Status,
		).Scan(&policy.QuotaTimezone)
		if err != nil {
			return fmt.Errorf("failed to create quota policy: %w", err)
		}
	default:
		return fmt.Errorf("failed to lookup quota policy: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit quota policy: %w", err)
	}
	return nil
}
