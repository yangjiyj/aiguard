package billing

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrFixedCostOverlap = errors.New("channel fixed cost effective periods overlap")
var ErrFixedCostNotFound = errors.New("channel fixed cost not found")

type ChannelFixedCost struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ProviderID    string    `json:"provider_id"`
	ProviderName  string    `json:"provider_name,omitempty"`
	Currency      string    `json:"currency"`
	AmountMicros  int64     `json:"amount_micros"`
	Period        string    `json:"period"`
	EffectiveFrom string    `json:"effective_from"`
	EffectiveTo   *string   `json:"effective_to,omitempty"`
	Note          string    `json:"note"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type CostChannel struct {
	ProviderID   string `json:"provider_id"`
	ProviderName string `json:"provider_name"`
}

func (s *Store) ListCostChannels(ctx context.Context, tenantID string) ([]CostChannel, error) {
	rows, err := s.db.Query(ctx, `SELECT id,name FROM providers WHERE tenant_id=$1 AND status<>'deleted' ORDER BY name,id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CostChannel{}
	for rows.Next() {
		var c CostChannel
		if err = rows.Scan(&c.ProviderID, &c.ProviderName); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) validateCostCurrency(ctx context.Context, q employeeSettingsQuerier, tenantID, currency string) error {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)`, tenantID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrInvalidPrice
	}
	currencyForTenant, err := s.billingCurrencyForTenant(ctx, q, tenantID)
	if err != nil {
		return err
	}
	if currency != currencyForTenant {
		return ErrAllowanceCurrency
	}
	return nil
}

func (s *Store) ListChannelFixedCosts(ctx context.Context, tenantID string) ([]ChannelFixedCost, error) {
	rows, err := s.db.Query(ctx, `SELECT c.id,c.tenant_id,c.provider_id,p.name,c.currency,c.amount_micros,c.period,c.effective_from::text,c.effective_to::text,c.note,COALESCE(c.created_by,''),c.created_at,c.updated_at FROM billing_channel_fixed_costs c JOIN providers p ON p.id=c.provider_id AND p.tenant_id=c.tenant_id WHERE c.tenant_id=$1 ORDER BY p.name,c.effective_from DESC,c.id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ChannelFixedCost{}
	for rows.Next() {
		var c ChannelFixedCost
		if err := rows.Scan(&c.ID, &c.TenantID, &c.ProviderID, &c.ProviderName, &c.Currency, &c.AmountMicros, &c.Period, &c.EffectiveFrom, &c.EffectiveTo, &c.Note, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) SaveChannelFixedCost(ctx context.Context, tenantID string, c ChannelFixedCost) (*ChannelFixedCost, error) {
	from, err := time.Parse("2006-01-02", c.EffectiveFrom)
	if err != nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(c.ProviderID) == "" || c.AmountMicros < 0 || (c.Currency != "CNY" && c.Currency != "USD") || len(c.Note) > 4000 || (c.Period != "month" && c.Period != "year") {
		return nil, ErrInvalidPrice
	}
	if c.EffectiveTo != nil {
		to, err := time.Parse("2006-01-02", *c.EffectiveTo)
		if err != nil || !to.After(from) {
			return nil, ErrInvalidPrice
		}
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Same lock as employee settings/price saves prevents concurrent denomination changes.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "allowance-settings:"+tenantID); err != nil {
		return nil, err
	}
	if err = s.validateCostCurrency(ctx, tx, tenantID, c.Currency); err != nil {
		return nil, err
	}
	if c.ID == "" {
		c.ID = "fixed_cost_" + uuid.NewString()
	} else {
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_channel_fixed_costs WHERE tenant_id=$1 AND id=$2)`, tenantID, c.ID).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			return nil, ErrFixedCostNotFound
		}
	}
	c.TenantID = tenantID
	err = tx.QueryRow(ctx, `INSERT INTO billing_channel_fixed_costs(id,tenant_id,provider_id,currency,amount_micros,period,effective_from,effective_to,note,created_by) SELECT $1::varchar,$2::varchar,$3::varchar,$4::varchar,$5::bigint,$6::varchar,$7::date,$8::date,$9::text,NULLIF($10::varchar,'') FROM providers WHERE id=$3 AND tenant_id=$2 AND status<>'deleted' ON CONFLICT(id) DO UPDATE SET provider_id=EXCLUDED.provider_id,currency=EXCLUDED.currency,amount_micros=EXCLUDED.amount_micros,period=EXCLUDED.period,effective_from=EXCLUDED.effective_from,effective_to=EXCLUDED.effective_to,note=EXCLUDED.note,updated_at=NOW() WHERE billing_channel_fixed_costs.tenant_id=EXCLUDED.tenant_id RETURNING created_at,updated_at,COALESCE(created_by,'')`, c.ID, tenantID, c.ProviderID, c.Currency, c.AmountMicros, c.Period, c.EffectiveFrom, c.EffectiveTo, c.Note, c.CreatedBy).Scan(&c.CreatedAt, &c.UpdatedAt, &c.CreatedBy)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23P01" {
		return nil, ErrFixedCostOverlap
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidPrice
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) DeleteChannelFixedCost(ctx context.Context, tenantID, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM billing_channel_fixed_costs WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrFixedCostNotFound
	}
	return nil
}

// ProrateChannelFixedCost uses calendar months in the tenant's billing timezone,
// clips both effective and reporting intervals, and rounds once to micros.
// Annual amounts are allocated as one twelfth per natural month.
func ProrateChannelFixedCost(c ChannelFixedCost, start, end time.Time, loc *time.Location) (int64, error) {
	if loc == nil {
		loc = time.UTC
	}
	from, err := time.ParseInLocation("2006-01-02", c.EffectiveFrom, loc)
	if err != nil {
		return 0, ErrInvalidPrice
	}
	if start.Before(from) {
		start = from
	}
	if c.EffectiveTo != nil {
		to, err := time.ParseInLocation("2006-01-02", *c.EffectiveTo, loc)
		if err != nil {
			return 0, ErrInvalidPrice
		}
		if end.After(to) {
			end = to
		}
	}
	if !end.After(start) {
		return 0, nil
	}
	if c.AmountMicros < 0 || (c.Period != "month" && c.Period != "year") {
		return 0, ErrInvalidPrice
	}
	total := new(big.Rat)
	for cursor := start.In(loc); cursor.Before(end); {
		month := time.Date(cursor.Year(), cursor.Month(), 1, 0, 0, 0, 0, loc)
		next := month.AddDate(0, 1, 0)
		stop := next
		if end.Before(stop) {
			stop = end
		}
		// Convert local clock to UTC before measuring days to keep a civil day
		// equal to one day across daylight saving boundaries.
		civil := func(t time.Time) time.Time {
			t = t.In(loc)
			return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
		}
		numerator := new(big.Int).Mul(big.NewInt(c.AmountMicros), big.NewInt(civil(stop).Sub(civil(cursor)).Nanoseconds()))
		denominator := big.NewInt(civil(next).Sub(civil(month)).Nanoseconds())
		if c.Period == "year" {
			denominator.Mul(denominator, big.NewInt(12))
		}
		total.Add(total, new(big.Rat).SetFrac(numerator, denominator))
		cursor = stop
	}
	rounded := new(big.Int).Quo(new(big.Int).Add(total.Num(), new(big.Int).Quo(total.Denom(), big.NewInt(2))), total.Denom())
	if !rounded.IsInt64() {
		return 0, fmt.Errorf("fixed cost overflow: %w", ErrInvalidPrice)
	}
	return rounded.Int64(), nil
}
