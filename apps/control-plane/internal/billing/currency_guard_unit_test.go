package billing

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// 只提供租户设置读取；任何钱包访问或写入都会使单测失败。
type currencyGuardDB struct {
	billingDB
	tx *currencyGuardTx
}

func (d currencyGuardDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) { return d.tx, nil }
func (d currencyGuardDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return currencyGuardRow{d.tx.currency}
}

type currencyGuardTx struct {
	pgx.Tx
	t          *testing.T
	currency   string
	rolledBack bool
}

func (x *currencyGuardTx) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	if query != `SELECT currency FROM billing_employee_settings WHERE tenant_id=$1` {
		x.t.Fatalf("币种不一致时不应访问钱包：%s", query)
	}
	return currencyGuardRow{x.currency}
}
func (x *currencyGuardTx) Exec(_ context.Context, query string, _ ...any) (pgconn.CommandTag, error) {
	if query != `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))` {
		x.t.Fatalf("币种不一致时不应写资金：%s", query)
	}
	return pgconn.NewCommandTag("SELECT 1"), nil
}
func (x *currencyGuardTx) Rollback(context.Context) error { x.rolledBack = true; return nil }

type currencyGuardRow struct{ currency string }

func (r currencyGuardRow) Scan(dest ...any) error { *dest[0].(*string) = r.currency; return nil }

func TestAnalyticsCurrencyUsesTenantUnlessExplicitlySelected(t *testing.T) {
	s := &Store{db: currencyGuardDB{tx: &currencyGuardTx{currency: "USD"}}}
	for _, tc := range []struct{ input, want string }{{"", "USD"}, {"CNY", "CNY"}, {"usd", "USD"}} {
		got, err := s.analyticsFilterCurrency(context.Background(), AnalyticsFilter{TenantID: "tenant", Currency: tc.input})
		if err != nil || got.Currency != tc.want {
			t.Fatalf("输入=%q 结果=%+v 错误=%v", tc.input, got, err)
		}
	}
}

func TestReservationRejectsStaleCurrencyBeforeAnyWalletSideEffect(t *testing.T) {
	tx := &currencyGuardTx{t: t, currency: "USD"}
	s := &Store{db: currencyGuardDB{tx: tx}}
	price := &ModelPrice{ID: "old-price", TenantID: "tenant", ModelName: "model", CustomerGroup: DefaultCustomerGroup, Currency: "CNY"}
	reservation, wallet, err := s.ReservePriced(context.Background(), "tenant", "wallet", "request", 100, price)
	if !errors.Is(err, ErrPriceCurrencyMismatch) || reservation != nil || wallet != nil || !tx.rolledBack {
		t.Fatalf("应无副作用地拒绝旧报价：%+v %+v %v 回滚=%v", reservation, wallet, err, tx.rolledBack)
	}
}
