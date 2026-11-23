package billing

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

type UpstreamRate struct {
	ProviderID       string          `json:"provider_id"`
	ProviderName     string          `json:"provider_name,omitempty"`
	ModelName        string          `json:"model_name"`
	Currency         string          `json:"currency"`
	InputMicros      Micros          `json:"input_per_million_micros"`
	CachedMicros     Micros          `json:"cached_input_per_million_micros"`
	CacheWriteMicros Micros          `json:"cache_write_per_million_micros"`
	OutputMicros     Micros          `json:"output_per_million_micros"`
	Extensions       PriceExtensions `json:"extensions"`
	UpdatedAt        time.Time       `json:"updated_at,omitempty"`
}

type UpstreamModel struct {
	ProviderID   string `json:"provider_id"`
	ProviderName string `json:"provider_name"`
	ModelName    string `json:"model_name"`
}

func (s *Store) ListUpstreamModels(ctx context.Context, tenantID string) ([]UpstreamModel, error) {
	rows, err := s.db.Query(ctx, `SELECT p.id,p.name,m.model_name FROM providers p JOIN models m ON m.provider_id=p.id WHERE p.tenant_id=$1 AND p.status<>'deleted' ORDER BY p.name,m.model_name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []UpstreamModel{}
	for rows.Next() {
		var item UpstreamModel
		if err = rows.Scan(&item.ProviderID, &item.ProviderName, &item.ModelName); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r UpstreamRate) direct() DirectPrice {
	return DirectPrice{InputPerMillionMicros: r.InputMicros, CachedInputPerMillionMicros: r.CachedMicros, CacheWritePerMillionMicros: r.CacheWriteMicros, OutputPerMillionMicros: r.OutputMicros, HasCachedInputPrice: true, HasCacheWritePrice: true, Extensions: r.Extensions}
}

func (s *Store) ListUpstreamRates(ctx context.Context, tenantID string) ([]UpstreamRate, error) {
	rows, err := s.db.Query(ctx, `SELECT r.provider_id,COALESCE(p.name,''),r.model_name,r.currency,r.price_json,r.updated_at FROM billing_upstream_rates r JOIN providers p ON p.id=r.provider_id AND p.tenant_id=r.tenant_id WHERE r.tenant_id=$1 ORDER BY p.name,r.model_name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []UpstreamRate{}
	for rows.Next() {
		var item UpstreamRate
		var blob []byte
		if err = rows.Scan(&item.ProviderID, &item.ProviderName, &item.ModelName, &item.Currency, &blob, &item.UpdatedAt); err != nil {
			return nil, err
		}
		var rates UpstreamRate
		if err = json.Unmarshal(blob, &rates); err != nil {
			return nil, err
		}
		item.InputMicros = rates.InputMicros
		item.CachedMicros = rates.CachedMicros
		item.CacheWriteMicros = rates.CacheWriteMicros
		item.OutputMicros = rates.OutputMicros
		item.Extensions = rates.Extensions
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) SaveUpstreamRate(ctx context.Context, tenantID string, v UpstreamRate) error {
	if v.ModelName == "" || v.ProviderID == "" || (v.Currency != "CNY" && v.Currency != "USD") {
		return ErrInvalidPrice
	}
	if err := validateDirectPrice(v.direct()); err != nil {
		return err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "allowance-settings:"+tenantID); err != nil {
		return err
	}
	if err := s.validateCostCurrency(ctx, tx, tenantID, v.Currency); err != nil {
		return err
	}
	blob, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO billing_upstream_rates(tenant_id,provider_id,model_name,currency,price_json) SELECT $1::varchar,$2::varchar,$3::varchar,$4::varchar,$5::jsonb FROM providers p WHERE p.id=$2 AND p.tenant_id=$1 AND EXISTS(SELECT 1 FROM models m WHERE m.provider_id=$2 AND m.model_name=$3) ON CONFLICT(tenant_id,provider_id,model_name) DO UPDATE SET currency=EXCLUDED.currency,price_json=EXCLUDED.price_json,updated_at=NOW()`, tenantID, v.ProviderID, v.ModelName, v.Currency, blob)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrInvalidPrice
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteUpstreamRate(ctx context.Context, tenantID, providerID, modelName string) error {
	if tenantID == "" || providerID == "" || modelName == "" {
		return ErrInvalidPrice
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM billing_upstream_rates WHERE tenant_id=$1 AND provider_id=$2 AND model_name=$3`, tenantID, providerID, modelName)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrPriceNotFound
	}
	return nil
}

// ComputeUpstreamCost runs in the fact insertion transaction. Unknown or
// differently denominated costs remain NULL and historical facts never change.
func ComputeUpstreamCost(ctx context.Context, tx pgx.Tx, tenantID, providerID, modelID, modelName, currency string, usage Usage) (*Micros, error) {
	if modelID != "" {
		// Procurement rates name the routed provider's real model, while the
		// billable name may be a public alias and model_label is display-only.
		// An invalid identity is unknown; do not fall back to an unrelated rate.
		err := tx.QueryRow(ctx, `SELECT m.model_name FROM models m JOIN providers p ON p.id=m.provider_id WHERE m.id=$1 AND m.provider_id=$2 AND p.tenant_id=$3`, modelID, providerID, tenantID).Scan(&modelName)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
	var blob []byte
	err := tx.QueryRow(ctx, `SELECT price_json FROM billing_upstream_rates WHERE tenant_id=$1 AND provider_id=$2 AND model_name=$3 AND currency=$4`, tenantID, providerID, modelName, currency).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rate UpstreamRate
	if err = json.Unmarshal(blob, &rate); err != nil {
		return nil, err
	}
	charge, err := CalculateDirectCharge(usage, rate.direct())
	if err != nil {
		return nil, err
	}
	return &charge.TotalMicros, nil
}
