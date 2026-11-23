package billing

import (
	"context"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/userhistory"
	"time"
)

// CustomerSummary is deliberately scoped to one tenant and one user. It is
// the read model used by the customer portal; it never exposes another
// wallet, raw API key, prompt, or response content.
type CustomerSummary struct {
	Wallet        *Wallet              `json:"wallet"`
	CustomerGroup string               `json:"customer_group"`
	Usage         CustomerUsage        `json:"usage"`
	Daily         []CustomerDailyUsage `json:"daily"`
	Models        []CustomerModelUsage `json:"models"`
	Charges       []CustomerCharge     `json:"charges"`
	Limits        CustomerLimitSummary `json:"limits"`
	Failures      []CustomerFailure    `json:"failures"`
	GeneratedAt   time.Time            `json:"generated_at"`
}

type CustomerUsage struct {
	UnpricedRequests          int64  `json:"unpriced_requests"`
	UnpricedTokens            int64  `json:"unpriced_tokens"`
	UnpricedCachedInputTokens int64  `json:"unpriced_cached_input_tokens"`
	UnpricedCacheWriteTokens  int64  `json:"unpriced_cache_write_input_tokens"`
	Requests                  int64  `json:"requests"`
	PromptTokens              int64  `json:"prompt_tokens"`
	CachedInputTokens         int64  `json:"cached_input_tokens"`
	CacheWriteTokens          int64  `json:"cache_write_input_tokens"`
	OutputTokens              int64  `json:"output_tokens"`
	AmountMicros              Micros `json:"amount_micros"`
}

type CustomerDailyUsage struct {
	Date         string `json:"date"`
	Requests     int64  `json:"requests"`
	Tokens       int64  `json:"tokens"`
	AmountMicros Micros `json:"amount_micros"`
}

type CustomerModelUsage struct {
	ModelName    string `json:"model_name"`
	Requests     int64  `json:"requests"`
	Tokens       int64  `json:"tokens"`
	AmountMicros Micros `json:"amount_micros"`
}

type CustomerCharge struct {
	RequestID         string    `json:"request_id"`
	ModelName         string    `json:"model_name"`
	CustomerGroup     string    `json:"customer_group"`
	PromptTokens      int64     `json:"prompt_tokens"`
	CachedInputTokens int64     `json:"cached_input_tokens"`
	CacheWriteTokens  int64     `json:"cache_write_input_tokens"`
	OutputTokens      int64     `json:"output_tokens"`
	ReasoningTokens   int64     `json:"reasoning_tokens"`
	AmountMicros      Micros    `json:"amount_micros"`
	Currency          string    `json:"currency"`
	CreatedAt         time.Time `json:"created_at"`
}

type CustomerFailure struct {
	RequestID  string    `json:"request_id"`
	ModelName  string    `json:"model_name"`
	Endpoint   string    `json:"endpoint"`
	Status     string    `json:"status"`
	HTTPStatus int       `json:"http_status"`
	CreatedAt  time.Time `json:"created_at"`
}

func (s *Store) GetWalletByUser(ctx context.Context, tenantID, userID, currency string) (*Wallet, error) {
	if _, err := s.EnsureMonthlyWalletGrant(ctx, tenantID, userID, currency, time.Now().UTC()); err != nil {
		return nil, err
	}
	if tenantID == "" || userID == "" || !currencyPattern.MatchString(currency) {
		return nil, fmt.Errorf("%w: invalid wallet owner or currency", ErrInvalidWalletState)
	}
	wallet, err := scanWallet(s.db.QueryRow(ctx, `
        SELECT id, tenant_id, user_id, currency, balance_micros, reserved_micros,
               version, created_at, updated_at
        FROM billing_wallets
        WHERE tenant_id = $1 AND user_id = $2 AND currency = $3
    `, tenantID, userID, currency))
	if err != nil {
		return nil, err
	}
	return wallet, nil
}

// customerConsumptionSQL is the one request-level source for personal spend.
// Facts preserve metering usage and admission attribution. Prepaid facts need
// their successful charge; the legacy fallback includes only charges with no
// fact at all, so migrated/prepaid history cannot be counted twice.
// $1/$2/$3 always bind tenant, immutable user, and the displayed wallet currency.
const customerConsumptionSQL = userhistory.OwnersCTE + `, customer_consumption AS (
    SELECT f.id, f.request_id, f.model_name,
           COALESCE(c.customer_group, r.customer_group, 'default') AS customer_group,
           f.prompt_tokens, f.cached_input_tokens, f.cache_write_input_tokens,
           f.output_tokens, f.reasoning_tokens,
           f.billable_amount_micros AS amount_micros, f.currency,
           f.occurred_at AS created_at
    FROM billing_usage_facts f
    LEFT JOIN billing_charge_records c ON c.tenant_id=f.tenant_id AND c.request_id=f.request_id
    LEFT JOIN billing_reservations r ON r.tenant_id=f.tenant_id AND r.request_id=f.request_id
    WHERE f.tenant_id=$1 AND f.user_id IN (SELECT user_id FROM user_history) AND f.currency=$3
      AND f.status='settled' AND f.billable_amount_micros IS NOT NULL
      AND (r.id IS NULL OR r.status='settled')
      AND (c.id IS NULL OR c.status='settled')
      AND (f.billing_mode='metering' OR c.status='settled')
    UNION ALL
    SELECT c.id, c.request_id, c.model_name, c.customer_group,
           c.prompt_tokens, c.cached_input_tokens, c.cache_write_input_tokens,
           c.output_tokens, c.reasoning_tokens, c.amount_micros, c.currency, c.created_at
    FROM billing_charge_records c
    JOIN billing_wallets w ON w.tenant_id=c.tenant_id AND w.id=c.wallet_id
    LEFT JOIN billing_reservations r ON r.tenant_id=c.tenant_id AND r.request_id=c.request_id
    WHERE c.tenant_id=$1 AND w.user_id IN (SELECT user_id FROM user_history) AND w.currency=$3 AND c.currency=$3
      AND c.status='settled' AND (r.id IS NULL OR r.status='settled')
      AND NOT EXISTS (SELECT 1 FROM billing_usage_facts f
                      WHERE f.tenant_id=c.tenant_id AND f.request_id=c.request_id)
)
`

func (s *Store) CustomerSummary(ctx context.Context, tenantID, userID string, since time.Time, limit int) (*CustomerSummary, error) {
	if tenantID == "" || userID == "" {
		return nil, ErrInvalidWalletState
	}
	if since.IsZero() {
		since = time.Now().UTC().AddDate(0, 0, -30)
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	currency, err := s.BillingCurrencyForTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	wallet, err := s.FindWalletForUser(ctx, tenantID, userID, currency)
	if err != nil {
		return nil, err
	}
	if wallet == nil {
		wallet = &Wallet{TenantID: tenantID, UserID: userID, Currency: currency}
	}
	customerGroup, err := s.ResolveCustomerGroup(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	result := &CustomerSummary{Wallet: wallet, CustomerGroup: customerGroup, Daily: []CustomerDailyUsage{}, Models: []CustomerModelUsage{}, Charges: []CustomerCharge{}, Failures: []CustomerFailure{}, GeneratedAt: time.Now().UTC()}
	limits, err := s.GetCustomerLimitSummary(ctx, tenantID, userID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	result.Limits = limits
	err = s.db.QueryRow(ctx, customerConsumptionSQL+`
        SELECT COUNT(*), COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(cached_input_tokens),0),
               COALESCE(SUM(cache_write_input_tokens),0), COALESCE(SUM(output_tokens),0),
               COALESCE(SUM(amount_micros),0)
        FROM customer_consumption
        WHERE created_at >= $4
    `, tenantID, userID, currency, since).Scan(&result.Usage.Requests, &result.Usage.PromptTokens,
		&result.Usage.CachedInputTokens, &result.Usage.CacheWriteTokens, &result.Usage.OutputTokens, &result.Usage.AmountMicros)
	if err != nil {
		return nil, fmt.Errorf("customer billing summary: %w", err)
	}

	err = s.db.QueryRow(ctx, userhistory.OwnersCTE+`
  SELECT COUNT(*),COALESCE(SUM(prompt_tokens+output_tokens),0),COALESCE(SUM(cached_input_tokens),0),COALESCE(SUM(cache_write_input_tokens),0)
  FROM billing_usage_facts WHERE tenant_id=$1 AND user_id IN(SELECT user_id FROM user_history)
  AND occurred_at>=$3 AND (status='unpriced' OR(status='settled' AND billable_amount_micros IS NULL))
 `, tenantID, userID, since).Scan(&result.Usage.UnpricedRequests, &result.Usage.UnpricedTokens, &result.Usage.UnpricedCachedInputTokens, &result.Usage.UnpricedCacheWriteTokens)
	if err != nil {
		return nil, fmt.Errorf("customer unpriced usage: %w", err)
	}
	daily, err := s.db.Query(ctx, customerConsumptionSQL+`
        SELECT TO_CHAR(DATE_TRUNC('day', created_at AT TIME ZONE $5),'YYYY-MM-DD'),
               COUNT(*), COALESCE(SUM(prompt_tokens + output_tokens),0), COALESCE(SUM(amount_micros),0)
        FROM customer_consumption
        WHERE created_at >= $4
        GROUP BY 1 ORDER BY 1
    `, tenantID, userID, currency, since, billingTimeZone())
	if err != nil {
		return nil, fmt.Errorf("customer billing daily: %w", err)
	}
	defer daily.Close()
	for daily.Next() {
		var item CustomerDailyUsage
		if err := daily.Scan(&item.Date, &item.Requests, &item.Tokens, &item.AmountMicros); err != nil {
			return nil, err
		}
		result.Daily = append(result.Daily, item)
	}
	if err := daily.Err(); err != nil {
		return nil, err
	}

	models, err := s.db.Query(ctx, customerConsumptionSQL+`
        SELECT model_name, COUNT(*), COALESCE(SUM(prompt_tokens + output_tokens),0), COALESCE(SUM(amount_micros),0)
        FROM customer_consumption
        WHERE created_at >= $4
        GROUP BY model_name ORDER BY 4 DESC, 1 ASC LIMIT 20
    `, tenantID, userID, currency, since)
	if err != nil {
		return nil, fmt.Errorf("customer billing models: %w", err)
	}
	defer models.Close()
	for models.Next() {
		var item CustomerModelUsage
		if err := models.Scan(&item.ModelName, &item.Requests, &item.Tokens, &item.AmountMicros); err != nil {
			return nil, err
		}
		result.Models = append(result.Models, item)
	}
	if err := models.Err(); err != nil {
		return nil, err
	}

	charges, err := s.db.Query(ctx, customerConsumptionSQL+`
        SELECT request_id, model_name, customer_group, prompt_tokens, cached_input_tokens,
               cache_write_input_tokens, output_tokens, reasoning_tokens, amount_micros, currency, created_at
        FROM customer_consumption WHERE created_at >= $4
        ORDER BY created_at DESC, id DESC LIMIT $5
    `, tenantID, userID, currency, since, limit)
	if err != nil {
		return nil, fmt.Errorf("customer billing charges: %w", err)
	}
	defer charges.Close()
	for charges.Next() {
		var item CustomerCharge
		if err := charges.Scan(&item.RequestID, &item.ModelName, &item.CustomerGroup, &item.PromptTokens, &item.CachedInputTokens, &item.CacheWriteTokens, &item.OutputTokens, &item.ReasoningTokens, &item.AmountMicros, &item.Currency, &item.CreatedAt); err != nil {
			return nil, err
		}
		result.Charges = append(result.Charges, item)
	}
	if err := charges.Err(); err != nil {
		return nil, err
	}

	failures, err := s.db.Query(ctx, userhistory.AuditOwnersCTE+`
        SELECT l.request_id, COALESCE(m.model_name,''), l.endpoint_type, l.request_status,
               COALESCE(l.upstream_status_code,0), l.created_at
        FROM request_logs l LEFT JOIN models m ON m.id=l.model_id
        WHERE l.tenant_id=$1 AND l.user_id IN (SELECT user_id FROM user_history) AND l.created_at >= $3
          AND l.request_status NOT IN ('received','success')
        ORDER BY l.created_at DESC, l.id DESC LIMIT $4
    `, tenantID, userID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("customer billing failures: %w", err)
	}
	defer failures.Close()
	for failures.Next() {
		var item CustomerFailure
		if err := failures.Scan(&item.RequestID, &item.ModelName, &item.Endpoint, &item.Status, &item.HTTPStatus, &item.CreatedAt); err != nil {
			return nil, err
		}
		result.Failures = append(result.Failures, item)
	}
	if err := failures.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
