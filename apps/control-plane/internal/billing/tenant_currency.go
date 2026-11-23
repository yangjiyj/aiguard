package billing

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

// BillingCurrencyForTenant reads the denomination without changing settings or
// creating wallets. An explicit setting wins; legacy installations may infer
// it from currently effective default prices or financially provisioned wallets.
func (s *Store) BillingCurrencyForTenant(ctx context.Context, tenantID string) (string, error) {
	return s.billingCurrencyForTenant(ctx, s.db, tenantID)
}

func (s *Store) billingCurrencyForTenant(ctx context.Context, q employeeSettingsQuerier, tenantID string) (string, error) {
	var currency string
	err := q.QueryRow(ctx, `SELECT currency FROM billing_employee_settings WHERE tenant_id=$1`, tenantID).Scan(&currency)
	if err == nil {
		return currency, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	var distinct int64
	err = q.QueryRow(ctx, `SELECT COUNT(DISTINCT currency),COALESCE(MIN(currency),'') FROM (
  SELECT DISTINCT ON(model_name) currency FROM billing_model_prices
  WHERE tenant_id=$1 AND customer_group='default' AND status='active' AND effective_at<=NOW() AND (expires_at IS NULL OR expires_at>NOW())
  ORDER BY model_name,effective_at DESC,version DESC
 ) current_prices`, tenantID).Scan(&distinct, &currency)
	if err != nil {
		return "", err
	}
	if distinct > 1 {
		return "", ErrMixedCurrency
	}
	if distinct == 1 {
		return currency, nil
	}
	err = q.QueryRow(ctx, `SELECT COUNT(DISTINCT w.currency),COALESCE(MIN(w.currency),'') FROM billing_wallets w WHERE w.tenant_id=$1 AND `+fundedWalletPredicate, tenantID).Scan(&distinct, &currency)
	if err != nil {
		return "", err
	}
	if distinct > 1 {
		return "", ErrMixedCurrency
	}
	if distinct == 1 {
		return currency, nil
	}
	return s.DefaultCurrency(), nil
}
