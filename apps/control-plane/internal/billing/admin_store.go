package billing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AdminCustomer is the operator-facing customer account projection. It is
// tenant scoped and deliberately contains no credential material.
type AdminCustomer struct {
	UserID         string
	Username       string
	Email          string
	Status         string
	CustomerGroup  string
	GroupName      string
	GroupStatus    string
	WalletID       string
	Currency       string
	BalanceMicros  Micros
	ReservedMicros Micros
	UpdatedAt      *time.Time
}

type LedgerEntry struct {
	ID                  string
	WalletID            string
	Currency            string
	UserID              string
	Username            string
	DepartmentID        string
	DepartmentName      string
	ReservationID       string
	RequestID           string
	EventType           string
	BalanceDeltaMicros  Micros
	ReservedDeltaMicros Micros
	BalanceAfterMicros  Micros
	ReservedAfterMicros Micros
	ActorType           string
	ActorID             string
	MetadataJSON        []byte
	// IdempotencyKey and Reason surface the operator result trail: which
	// idempotent operation produced the entry and why it was issued.
	IdempotencyKey string
	Reason         string
	CreatedAt      time.Time
}

type BillingException struct {
	Kind      string
	RequestID string
	WalletID  string
	ModelName string
	Status    string
	CreatedAt time.Time
}

func billingLimit(limit, fallback, maximum int) int {
	if limit <= 0 {
		return fallback
	}
	if limit > maximum {
		return maximum
	}
	return limit
}

// ListAdminCustomers lists all customer identities for one tenant together
// with their configured billing wallet, if provisioned. This lets an operator credit a user
// before their first paid call.
func (s *Store) ListAdminCustomers(ctx context.Context, tenantID string, limit int) ([]AdminCustomer, error) {
	if tenantID == "" {
		return nil, ErrInvalidWalletState
	}
	if err := s.EnsureDefaultCustomerGroup(ctx, tenantID); err != nil {
		return nil, err
	}
	currency, err := s.BillingCurrencyForTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	limit = billingLimit(limit, 100, 500)
	rows, err := s.db.Query(ctx, `
        SELECT u.id, u.username, COALESCE(u.email, ''), COALESCE(u.status, ''),
               COALESCE(w.id, ''), COALESCE(w.currency, $3),
               COALESCE(w.balance_micros, 0), COALESCE(w.reserved_micros, 0), w.updated_at,
               COALESCE(m.customer_group, 'default'),
               COALESCE(g.name, 'Default customer group'), COALESCE(g.status, 'active')
        FROM users u
        LEFT JOIN billing_wallets w ON w.tenant_id = u.tenant_id AND w.user_id = u.id AND w.currency = $3
        LEFT JOIN billing_customer_group_memberships m ON m.tenant_id = u.tenant_id AND m.user_id = u.id
        LEFT JOIN billing_customer_groups g ON g.tenant_id = m.tenant_id AND g.code = m.customer_group
        WHERE u.tenant_id = $1 AND u.status <> 'deleted'
        ORDER BY u.username ASC, u.id ASC
        LIMIT $2
    `, tenantID, limit, currency)
	if err != nil {
		return nil, fmt.Errorf("list billing customers: %w", err)
	}
	defer rows.Close()
	items := make([]AdminCustomer, 0)
	for rows.Next() {
		var item AdminCustomer
		if err := rows.Scan(&item.UserID, &item.Username, &item.Email, &item.Status, &item.WalletID,
			&item.Currency, &item.BalanceMicros, &item.ReservedMicros, &item.UpdatedAt,
			&item.CustomerGroup, &item.GroupName, &item.GroupStatus); err != nil {
			return nil, fmt.Errorf("scan billing customer: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListLedgerEntries(ctx context.Context, tenantID, walletID string, limit int) ([]LedgerEntry, error) {
	if tenantID == "" {
		return nil, ErrInvalidWalletState
	}
	limit = billingLimit(limit, 100, 500)
	rows, err := s.db.Query(ctx, `
        SELECT l.id, l.wallet_id, w.currency, w.user_id, COALESCE(u.username, ''),
               COALESCE(t.id, ''), COALESCE(t.name, ''),
               COALESCE(l.reservation_id, ''), COALESCE(l.request_id, ''), l.event_type,
               l.balance_delta_micros, l.reserved_delta_micros,
               l.balance_after_micros, l.reserved_after_micros,
               l.actor_type, COALESCE(l.actor_id, ''), COALESCE(l.idempotency_key, ''),
               l.metadata_json, l.created_at
        FROM billing_ledger_entries l
        JOIN billing_wallets w ON w.id = l.wallet_id AND w.tenant_id = l.tenant_id
        LEFT JOIN users u ON u.id = w.user_id AND u.tenant_id = w.tenant_id
        LEFT JOIN teams t ON t.id = to_jsonb(u)->>'department_id' AND t.tenant_id = w.tenant_id
        WHERE l.tenant_id = $1 AND ($2 = '' OR l.wallet_id = $2)
        ORDER BY l.created_at DESC, l.id DESC
        LIMIT $3
    `, tenantID, walletID, limit)
	if err != nil {
		return nil, fmt.Errorf("list billing ledger: %w", err)
	}
	defer rows.Close()
	items := make([]LedgerEntry, 0)
	for rows.Next() {
		var item LedgerEntry
		if err := rows.Scan(&item.ID, &item.WalletID, &item.Currency, &item.UserID, &item.Username, &item.DepartmentID, &item.DepartmentName, &item.ReservationID,
			&item.RequestID, &item.EventType, &item.BalanceDeltaMicros, &item.ReservedDeltaMicros,
			&item.BalanceAfterMicros, &item.ReservedAfterMicros, &item.ActorType, &item.ActorID,
			&item.IdempotencyKey, &item.MetadataJSON, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan billing ledger: %w", err)
		}
		var metadata struct {
			Reason string `json:"reason"`
		}
		if len(item.MetadataJSON) > 0 && json.Unmarshal(item.MetadataJSON, &metadata) == nil {
			item.Reason = metadata.Reason
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListModelPrices(ctx context.Context, tenantID string, limit int) ([]ModelPrice, error) {
	if tenantID == "" {
		return nil, ErrInvalidPrice
	}
	limit = billingLimit(limit, 100, 500)
	rows, err := s.db.Query(ctx, `
        SELECT id, tenant_id, model_name, customer_group, version, pricing_mode, currency,
               COALESCE(input_per_million_micros, -1), COALESCE(cached_input_per_million_micros, -1),
               COALESCE(cache_write_per_million_micros, -1), COALESCE(output_per_million_micros, -1),
               COALESCE(base_input_per_million_micros, -1), COALESCE(model_ratio_ppm, -1),
               COALESCE(completion_ratio_ppm, -1), COALESCE(group_ratio_ppm, -1),
               COALESCE(cached_input_ratio_ppm, -1), COALESCE(cache_write_ratio_ppm, -1),
               status, effective_at, expires_at, COALESCE(created_by, ''), created_at, pricing_extras
        FROM billing_model_prices
        WHERE tenant_id = $1
        ORDER BY model_name ASC, customer_group ASC, version DESC
        LIMIT $2
    `, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list billing prices: %w", err)
	}
	defer rows.Close()
	items := make([]ModelPrice, 0)
	for rows.Next() {
		item, err := scanModelPrice(rows)
		if err != nil {
			return nil, fmt.Errorf("scan billing price: %w", err)
		}
		items = append(items, *item)
	}
	return items, rows.Err()
}

// ListBillingExceptions shows conditions requiring operator attention: stale
// reservations, charge records that could not settle normally, and recovered
// charges whose cache breakdown must be verified (7.5). Overdraft settlements
// are normal D5 bookings and never appear here.
func (s *Store) ListBillingExceptions(ctx context.Context, tenantID string, limit int) ([]BillingException, error) {
	if tenantID == "" {
		return nil, ErrInvalidWalletState
	}
	limit = billingLimit(limit, 100, 500)
	rows, err := s.db.Query(ctx, `
        SELECT kind, request_id, wallet_id, model_name, status, created_at
        FROM (
            SELECT 'stale_reservation' AS kind, request_id, wallet_id,
                   COALESCE(model_name, '') AS model_name, status, created_at
            FROM billing_reservations
            WHERE tenant_id = $1 AND status = 'reserved' AND created_at < NOW() - INTERVAL '15 minutes'
            UNION ALL
            SELECT 'charge_record' AS kind, request_id, wallet_id, model_name, status, created_at
            FROM billing_charge_records
            WHERE tenant_id = $1 AND status IN ('failed', 'unpriced')
            UNION ALL
            -- 7.5: recovered from request_logs without a cache breakdown while
            -- the price snapshot bills cache tokens differently; awaits true-up.
            SELECT 'recovered_without_cache' AS kind, c.request_id, c.wallet_id, c.model_name, c.status, c.created_at
            FROM billing_charge_records c
            WHERE c.tenant_id = $1 AND c.status = 'settled'
              AND c.raw_usage_json->>'usage_source' = 'recovered_request_log'
              AND c.prompt_tokens > 0
              AND (c.cached_input_per_million_micros <> c.input_per_million_micros
                   OR c.cache_write_per_million_micros <> c.input_per_million_micros)
              AND NOT EXISTS (
                  SELECT 1 FROM billing_exception_resolutions x
                  WHERE x.tenant_id = c.tenant_id AND x.request_id = c.request_id
                    AND x.kind = 'recovered_without_cache'
              )
            UNION ALL
            -- Metering showback gaps: calls recorded without any configured
            -- price, so revenue silently went unbilled.
            SELECT 'metering_unpriced' AS kind, request_id, '' AS wallet_id,
                   model_name, status, created_at
            FROM billing_usage_facts
            WHERE tenant_id = $1 AND usage_source NOT IN ('forward_proxy','reverse_proxy') AND billing_mode = 'metering' AND status = 'unpriced'
            UNION ALL
            -- Metering facts that ended failed instead of settled: the usage
            -- evidence exists but no billable amount was booked.
            SELECT 'metering_failed' AS kind, request_id, '' AS wallet_id,
                   model_name, status, created_at
            FROM billing_usage_facts
            WHERE tenant_id = $1 AND usage_source NOT IN ('forward_proxy','reverse_proxy') AND billing_mode = 'metering' AND status = 'failed'
            UNION ALL
            -- 正向代理请求已发生但解析不出 token 用量（如网页版对话）：金额记 0，
            -- 必须人工核对，不能当成已定价 0 元。
            SELECT 'usage_unknown' AS kind, request_id, '' AS wallet_id,
                   model_name, status, created_at
            FROM billing_usage_facts
            WHERE tenant_id = $1 AND usage_source NOT IN ('forward_proxy','reverse_proxy') AND billing_mode = 'metering' AND status = 'usage_unknown'
        ) exceptions
        ORDER BY created_at DESC
        LIMIT $2
    `, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list billing exceptions: %w", err)
	}
	defer rows.Close()
	items := make([]BillingException, 0)
	for rows.Next() {
		var item BillingException
		if err := rows.Scan(&item.Kind, &item.RequestID, &item.WalletID, &item.ModelName, &item.Status, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan billing exception: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

const keysetSeparator = "\x1f"

func encodeKeysetCursor(parts ...string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, keysetSeparator)))
}

// decodeKeysetCursor returns the decoded cursor parts; an empty cursor means
// "start from the beginning". Malformed cursors are a client error.
func decodeKeysetCursor(cursor string) ([]string, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid pagination cursor", ErrInvalidWalletState)
	}
	parts := strings.Split(string(raw), keysetSeparator)
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("%w: invalid pagination cursor", ErrInvalidWalletState)
		}
	}
	return parts, nil
}

// ListAdminCustomersPage is the keyset-paginated variant of
// ListAdminCustomers. The cursor carries (username, user_id); the returned
// nextCursor is empty once the window is exhausted.
func (s *Store) ListAdminCustomersPage(ctx context.Context, tenantID string, limit int, cursor string) ([]AdminCustomer, string, error) {
	if tenantID == "" {
		return nil, "", ErrInvalidWalletState
	}
	if err := s.EnsureDefaultCustomerGroup(ctx, tenantID); err != nil {
		return nil, "", err
	}
	currency, err := s.BillingCurrencyForTenant(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	limit = billingLimit(limit, 100, 500)
	parts, err := decodeKeysetCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if len(parts) != 0 && len(parts) != 2 {
		return nil, "", fmt.Errorf("%w: invalid pagination cursor", ErrInvalidWalletState)
	}
	query := `
        SELECT u.id, u.username, COALESCE(u.email, ''), COALESCE(u.status, ''),
               COALESCE(w.id, ''), COALESCE(w.currency, $2),
               COALESCE(w.balance_micros, 0), COALESCE(w.reserved_micros, 0), w.updated_at,
               COALESCE(m.customer_group, 'default'),
               COALESCE(g.name, 'Default customer group'), COALESCE(g.status, 'active')
        FROM users u
        LEFT JOIN billing_wallets w ON w.tenant_id = u.tenant_id AND w.user_id = u.id AND w.currency = $2
        LEFT JOIN billing_customer_group_memberships m ON m.tenant_id = u.tenant_id AND m.user_id = u.id
        LEFT JOIN billing_customer_groups g ON g.tenant_id = m.tenant_id AND g.code = m.customer_group
        WHERE u.tenant_id = $1 AND u.status <> 'deleted'`
	args := []any{tenantID, currency}
	if len(parts) == 2 {
		args = append(args, parts[0], parts[1])
		query += ` AND (u.username, u.id) > ($3, $4)`
	}
	args = append(args, limit+1)
	query += fmt.Sprintf(` ORDER BY u.username ASC, u.id ASC LIMIT $%d`, len(args))
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("list billing customers: %w", err)
	}
	defer rows.Close()
	items := make([]AdminCustomer, 0)
	for rows.Next() {
		var item AdminCustomer
		if err := rows.Scan(&item.UserID, &item.Username, &item.Email, &item.Status, &item.WalletID,
			&item.Currency, &item.BalanceMicros, &item.ReservedMicros, &item.UpdatedAt,
			&item.CustomerGroup, &item.GroupName, &item.GroupStatus); err != nil {
			return nil, "", fmt.Errorf("scan billing customer: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterate billing customers: %w", err)
	}
	nextCursor := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		nextCursor = encodeKeysetCursor(last.Username, last.UserID)
	}
	return items, nextCursor, nil
}

// ListLedgerEntriesPage is the keyset-paginated variant of ListLedgerEntries.
// The cursor carries (created_at RFC3339Nano, entry id) in descending order.
//
// What the keyset guarantees is only that paging is STABLE and total: the
// (created_at, id) pair is a total order over the rows and idx_billing_ledger_*
// supports it, so no row is skipped or repeated across pages. It is NOT a
// claim that created_at reflects the true chronological order of wallet state
// changes: created_at is DEFAULT now(), which in PostgreSQL is the TRANSACTION
// start time, so two concurrent transactions can commit in the opposite order
// to the timestamps they record (including inverting across the wallet row
// lock). Any read model that needs to reason about the real order of balance
// mutations must treat it as boundary_order_unverifiable rather than trusting
// this ordering.
func (s *Store) ListLedgerEntriesPage(ctx context.Context, tenantID, walletID string, limit int, cursor string) ([]LedgerEntry, string, error) {
	if tenantID == "" {
		return nil, "", ErrInvalidWalletState
	}
	limit = billingLimit(limit, 100, 500)
	parts, err := decodeKeysetCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if len(parts) != 0 && len(parts) != 2 {
		return nil, "", fmt.Errorf("%w: invalid pagination cursor", ErrInvalidWalletState)
	}
	query := `
        SELECT l.id, l.wallet_id, w.currency, w.user_id, COALESCE(u.username, ''),
               COALESCE(t.id, ''), COALESCE(t.name, ''),
               COALESCE(l.reservation_id, ''), COALESCE(l.request_id, ''), l.event_type,
               l.balance_delta_micros, l.reserved_delta_micros,
               l.balance_after_micros, l.reserved_after_micros,
               l.actor_type, COALESCE(l.actor_id, ''), COALESCE(l.idempotency_key, ''),
               l.metadata_json, l.created_at
        FROM billing_ledger_entries l
        JOIN billing_wallets w ON w.id = l.wallet_id AND w.tenant_id = l.tenant_id
        LEFT JOIN users u ON u.id = w.user_id AND u.tenant_id = w.tenant_id
        LEFT JOIN teams t ON t.id = to_jsonb(u)->>'department_id' AND t.tenant_id = w.tenant_id
        WHERE l.tenant_id = $1 AND ($2 = '' OR l.wallet_id = $2)`
	args := []any{tenantID, walletID}
	if len(parts) == 2 {
		cursorAt, err := time.Parse(time.RFC3339Nano, parts[0])
		if err != nil {
			return nil, "", fmt.Errorf("%w: invalid pagination cursor", ErrInvalidWalletState)
		}
		args = append(args, cursorAt, parts[1])
		query += ` AND (l.created_at, l.id) < ($3, $4)`
	}
	args = append(args, limit+1)
	query += fmt.Sprintf(` ORDER BY l.created_at DESC, l.id DESC LIMIT $%d`, len(args))
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("list billing ledger: %w", err)
	}
	defer rows.Close()
	items := make([]LedgerEntry, 0)
	for rows.Next() {
		var item LedgerEntry
		if err := rows.Scan(&item.ID, &item.WalletID, &item.Currency, &item.UserID, &item.Username, &item.DepartmentID, &item.DepartmentName, &item.ReservationID,
			&item.RequestID, &item.EventType, &item.BalanceDeltaMicros, &item.ReservedDeltaMicros,
			&item.BalanceAfterMicros, &item.ReservedAfterMicros, &item.ActorType, &item.ActorID,
			&item.IdempotencyKey, &item.MetadataJSON, &item.CreatedAt); err != nil {
			return nil, "", fmt.Errorf("scan billing ledger: %w", err)
		}
		var metadata struct {
			Reason string `json:"reason"`
		}
		if len(item.MetadataJSON) > 0 && json.Unmarshal(item.MetadataJSON, &metadata) == nil {
			item.Reason = metadata.Reason
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterate billing ledger: %w", err)
	}
	nextCursor := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		nextCursor = encodeKeysetCursor(last.CreatedAt.Format(time.RFC3339Nano), last.ID)
	}
	return items, nextCursor, nil
}

// ListEffectiveModelPrices returns only prices that are active and currently
// within their effective window, keeping the newest version per
// (model, customer group). This is the operator-facing "what is billed now"
// projection; the full history stays available through ListModelPrices.
func (s *Store) ListEffectiveModelPrices(ctx context.Context, tenantID string, limit int) ([]ModelPrice, error) {
	return s.listEffectiveModelPrices(ctx, tenantID, "", limit)
}

// ListEffectiveModelPricesForModel is ListEffectiveModelPrices restricted to
// one model name: the operator-facing "what is billed now for model X" query.
func (s *Store) ListEffectiveModelPricesForModel(ctx context.Context, tenantID, modelName string, limit int) ([]ModelPrice, error) {
	return s.listEffectiveModelPrices(ctx, tenantID, strings.TrimSpace(modelName), limit)
}

func (s *Store) listEffectiveModelPrices(ctx context.Context, tenantID, modelName string, limit int) ([]ModelPrice, error) {
	if tenantID == "" {
		return nil, ErrInvalidPrice
	}
	limit = billingLimit(limit, 100, 500)
	// 每个「模型+客户组」只取计费实际使用的那一版：排序口径与 ResolveModelPrice 完全一致
	// （effective_at DESC, version DESC）。补录了更早生效时间的新版本不会盖过仍在计费的旧版本。
	// 内层取每组第一条，外层再按模型名排序并截断，保证 LIMIT 截的是「模型」而不是历史版本。
	query := `
        SELECT id, tenant_id, model_name, customer_group, version, pricing_mode, currency,
               input_per_million_micros, cached_input_per_million_micros,
               cache_write_per_million_micros, output_per_million_micros,
               base_input_per_million_micros, model_ratio_ppm,
               completion_ratio_ppm, group_ratio_ppm,
               cached_input_ratio_ppm, cache_write_ratio_ppm,
               status, effective_at, expires_at, created_by, created_at, pricing_extras
        FROM (
          SELECT DISTINCT ON (model_name, customer_group)
               id, tenant_id, model_name, customer_group, version, pricing_mode, currency,
               COALESCE(input_per_million_micros, -1) AS input_per_million_micros,
               COALESCE(cached_input_per_million_micros, -1) AS cached_input_per_million_micros,
               COALESCE(cache_write_per_million_micros, -1) AS cache_write_per_million_micros,
               COALESCE(output_per_million_micros, -1) AS output_per_million_micros,
               COALESCE(base_input_per_million_micros, -1) AS base_input_per_million_micros,
               COALESCE(model_ratio_ppm, -1) AS model_ratio_ppm,
               COALESCE(completion_ratio_ppm, -1) AS completion_ratio_ppm,
               COALESCE(group_ratio_ppm, -1) AS group_ratio_ppm,
               COALESCE(cached_input_ratio_ppm, -1) AS cached_input_ratio_ppm,
               COALESCE(cache_write_ratio_ppm, -1) AS cache_write_ratio_ppm,
               status, effective_at, expires_at, COALESCE(created_by, '') AS created_by, created_at, pricing_extras
          FROM billing_model_prices
          WHERE tenant_id = $1 AND status = 'active'
            AND effective_at <= NOW() AND (expires_at IS NULL OR expires_at > NOW())`
	args := []any{tenantID}
	if modelName != "" {
		args = append(args, modelName)
		query += ` AND model_name = $2`
	}
	args = append(args, limit)
	query += fmt.Sprintf(`
          ORDER BY model_name, customer_group,
                   COALESCE(currency = (SELECT s.currency FROM billing_employee_settings s WHERE s.tenant_id = $1), false) DESC,
                   effective_at DESC, version DESC
        ) current_prices
        ORDER BY model_name ASC, customer_group ASC
        LIMIT $%d`, len(args))
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list effective billing prices: %w", err)
	}
	defer rows.Close()
	items := make([]ModelPrice, 0)
	for rows.Next() {
		item, err := scanModelPrice(rows)
		if err != nil {
			return nil, fmt.Errorf("scan billing price: %w", err)
		}
		items = append(items, *item)
	}
	return items, rows.Err()
}
