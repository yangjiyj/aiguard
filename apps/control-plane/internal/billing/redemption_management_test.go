package billing

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"strings"
	"testing"
	"time"
)

func TestRedemptionManagementPaginationFiltersAndSingleUseLedger(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	codes, err := s.CreateRedemptionCodes(ctx, NewRedemptionBatch{TenantID: tenant, Label: "acceptance-batch", AmountMicros: 200, Count: 5, CreatedBy: user})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.ListRedemptionCodePage(ctx, tenant, RedemptionFilter{Page: 1, PageSize: 2, Label: "acceptance-batch"})
	if err != nil || len(first.Items) != 2 || first.Total != 5 {
		t.Fatalf("page=%+v err=%v", first, err)
	}
	second, err := s.ListRedemptionCodePage(ctx, tenant, RedemptionFilter{Page: 2, PageSize: 2, Label: "acceptance-batch"})
	if err != nil || len(second.Items) != 2 || first.Items[0].ID == second.Items[0].ID {
		t.Fatal("server pagination repeated first page")
	}
	wallet, amount, err := s.RedeemCode(ctx, tenant, user, codes[0].Code)
	if err != nil || amount != 200 || wallet.BalanceMicros != 200 {
		t.Fatalf("credit failed=%v", err)
	}
	if _, _, err = s.RedeemCode(ctx, tenant, user, codes[0].Code); !errors.Is(err, ErrRedemptionUsed) {
		t.Fatal("second redemption accepted")
	}
	redeemed, err := s.ListRedemptionCodePage(ctx, tenant, RedemptionFilter{Status: "redeemed", Redeemer: user})
	if err != nil || redeemed.Total != 1 || redeemed.Items[0].RedeemedAt == nil || redeemed.Items[0].RedeemedBy != user {
		t.Fatal("redeemer/time filter failed")
	}
	detail, err := s.RedemptionDetail(ctx, tenant, codes[0].ID)
	if err != nil || detail.LedgerID == "" || detail.WalletID != wallet.ID || detail.AmountMicros != 200 {
		t.Fatal("missing exact redemption ledger detail")
	}
	var uses, ledger int
	if err = db.QueryRow(ctx, "SELECT count(*) FROM billing_redemption_uses WHERE tenant_id=$1 AND code_id=$2", tenant, codes[0].ID).Scan(&uses); err != nil || uses != 1 {
		t.Fatal("single use record missing")
	}
	if err = db.QueryRow(ctx, "SELECT count(*) FROM billing_ledger_entries WHERE tenant_id=$1 AND idempotency_key=$2", tenant, "redemption:"+codes[0].ID).Scan(&ledger); err != nil || ledger != 1 {
		t.Fatal("single ledger record missing")
	}
	changed, err := s.BatchSetRedemptionStatus(ctx, tenant, []string{codes[1].ID, codes[2].ID}, "disabled")
	if err != nil || changed != 2 {
		t.Fatal("batch disable failed")
	}
	if err = s.SetRedemptionCodeStatus(ctx, tenant, codes[3].ID, "voided"); err != nil {
		t.Fatal(err)
	}
	if err = s.SetRedemptionCodeStatus(ctx, tenant, codes[3].ID, "active"); !errors.Is(err, ErrRedemptionInvalid) {
		t.Fatal("voided code reactivated")
	}
	if _, err = db.Exec(ctx, "UPDATE billing_redemption_codes SET expires_at=now()-interval '1 second' WHERE id=$1", codes[4].ID); err != nil {
		t.Fatal(err)
	}
	expired, err := s.ListRedemptionCodePage(ctx, tenant, RedemptionFilter{Status: "expired"})
	if err != nil || expired.Total != 1 {
		t.Fatal("expired filter missing")
	}
	outside := time.Now().Add(time.Hour)
	filtered, err := s.ListRedemptionCodePage(ctx, tenant, RedemptionFilter{From: &outside})
	if err != nil || filtered.Total != 0 {
		t.Fatal("time filter missing")
	}
	other, err := s.ListRedemptionCodePage(ctx, "foreign-tenant", RedemptionFilter{})
	if err != nil || other.Total != 0 {
		t.Fatal("cross tenant list leaked")
	}
	if _, err = s.RedemptionDetail(ctx, "foreign-tenant", codes[0].ID); !errors.Is(err, ErrRedemptionInvalid) {
		t.Fatal("cross tenant detail leaked")
	}
	raw, _ := json.Marshal(redeemed)
	for _, code := range codes {
		if strings.Contains(string(raw), code.Code) {
			t.Fatal("list exposed plaintext")
		}
	}
}

func TestRedemptionManagementSupportsFullUnicodeBatchLabel(t *testing.T) {
	s, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	label := strings.Repeat("燧", 80)
	if _, err := s.CreateRedemptionCodes(ctx, NewRedemptionBatch{TenantID: tenant, Label: label, AmountMicros: 200, Count: 1, CreatedBy: user}); err != nil {
		t.Fatal(err)
	}
	page, err := s.ListRedemptionCodePage(ctx, tenant, RedemptionFilter{Label: label})
	if err != nil || page.Total != 1 {
		t.Fatalf("unicode batch filter rejected: %v", err)
	}
	count := 0
	if err = s.WalkRedemptionHints(ctx, tenant, label, func(hint, status string) error { count++; return nil }); err != nil || count != 1 {
		t.Fatalf("unicode batch export rejected: %v", err)
	}
}

func TestRedemptionVoidedCannotBeReactivatedByLegacyDatabaseUpdate(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	codes, err := s.CreateRedemptionCodes(ctx, NewRedemptionBatch{TenantID: tenant, Label: "legacy-rollback-probe", AmountMicros: 200, Count: 1, CreatedBy: user})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetRedemptionCodeStatus(ctx, tenant, codes[0].ID, "voided"); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, "UPDATE billing_redemption_codes SET status='active' WHERE tenant_id=$1 AND id=$2", tenant, codes[0].ID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatal("legacy database write reactivated voided code")
	}
	if _, _, err = s.RedeemCode(ctx, tenant, user, codes[0].Code); !errors.Is(err, ErrRedemptionUsed) {
		t.Fatal("voided code remained redeemable")
	}
}
