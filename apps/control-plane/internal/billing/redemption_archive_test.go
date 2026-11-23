package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRedemptionArchivePreservesMoneyAndHidesAllReadPaths(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	expires := time.Now().In(time.FixedZone("CST", 8*3600)).Add(48 * time.Hour).Truncate(time.Second)
	codes, err := s.CreateRedemptionCodes(ctx, NewRedemptionBatch{TenantID: tenant, Label: "archive-regression", AmountMicros: 200, Count: 2, CreatedBy: user, ExpiresAt: &expires})
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := s.RedeemCode(ctx, tenant, user, codes[0].Code)
	if err != nil {
		t.Fatal(err)
	}
	var ledgerBefore int
	if err = db.QueryRow(ctx, "SELECT count(*) FROM billing_ledger_entries WHERE tenant_id=$1", tenant).Scan(&ledgerBefore); err != nil {
		t.Fatal(err)
	}
	for _, code := range codes {
		if _, err = s.ArchiveRedemptionCode(ctx, "foreign", code.ID, user, ""); !errors.Is(err, ErrRedemptionInvalid) {
			t.Fatal("cross-tenant archive accepted")
		}
		event, e := s.ArchiveRedemptionCode(ctx, tenant, code.ID, user, "127.0.0.1")
		if e != nil || event.ID == "" {
			t.Fatalf("archive: %v", e)
		}
		if _, e = s.RedemptionDetail(ctx, tenant, code.ID); !errors.Is(e, ErrRedemptionInvalid) {
			t.Fatal("archived detail visible")
		}
		if _, e = s.RevealRedemptionCode(ctx, tenant, code.ID); !errors.Is(e, ErrRedemptionInvalid) {
			t.Fatal("archived credential revealed")
		}
		if e = s.SetRedemptionCodeStatus(ctx, tenant, code.ID, "active"); !errors.Is(e, ErrRedemptionInvalid) {
			t.Fatal("archived code reactivated")
		}
		if _, _, e = s.RedeemCode(ctx, tenant, user, code.Code); !errors.Is(e, ErrRedemptionInvalid) {
			t.Fatal("archived code redeemed")
		}
		if _, e = db.Exec(ctx, "UPDATE billing_redemption_codes SET archived_at=NULL,status='active' WHERE id=$1", code.ID); e == nil {
			t.Fatal("legacy write restored code")
		}
	}
	page, err := s.ListRedemptionCodePage(ctx, tenant, RedemptionFilter{})
	if err != nil || page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("archived pagination: %+v %v", page, err)
	}
	legacy, err := s.ListRedemptionCodes(ctx, tenant, 20)
	if err != nil || len(legacy) != 0 {
		t.Fatal("legacy list visible")
	}
	count := 0
	if err = s.WalkRedemptionHints(ctx, tenant, "archive-regression", func(string, string) error { count++; return nil }); err != nil || count != 0 {
		t.Fatal("export visible")
	}
	after, err := s.GetWallet(ctx, tenant, before.ID)
	if err != nil || after.BalanceMicros != before.BalanceMicros || after.Version != before.Version {
		t.Fatal("archive changed money")
	}
	var ledgerAfter, uses, audits int
	db.QueryRow(ctx, "SELECT count(*) FROM billing_ledger_entries WHERE tenant_id=$1", tenant).Scan(&ledgerAfter)
	db.QueryRow(ctx, "SELECT count(*) FROM billing_redemption_uses WHERE tenant_id=$1", tenant).Scan(&uses)
	db.QueryRow(ctx, "SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND action_type='billing.redemption.delete'", tenant).Scan(&audits)
	if ledgerBefore != ledgerAfter || uses != 1 || audits != 2 {
		t.Fatalf("retained history: ledger %d/%d uses %d audit %d", ledgerBefore, ledgerAfter, uses, audits)
	}
	var status string
	var storedExpiry time.Time
	if err = db.QueryRow(ctx, "SELECT status,expires_at FROM billing_redemption_codes WHERE id=$1", codes[0].ID).Scan(&status, &storedExpiry); err != nil || status != "redeemed" || !storedExpiry.Equal(expires) {
		t.Fatal("redeemed state/timezone lost")
	}
}

func TestBillingCustomersExcludeDeletedUsersButKeepTheirAssets(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := s.CreditUserWallet(ctx, tenant, user, "retained-money", 99999970, user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, "UPDATE users SET status='deleted',username='__deleted_user_'||id WHERE id=$1", user); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, "INSERT INTO users(id,tenant_id,username,status) VALUES($1,$2,'current-user','active'),($3,$2,'disabled-user','disabled')", user+"-current", tenant, user+"-disabled"); err != nil {
		t.Fatal(err)
	}
	legacy, err := s.ListAdminCustomers(ctx, tenant, 100)
	if err != nil || len(legacy) != 2 {
		t.Fatalf("customer legacy: %+v %v", legacy, err)
	}
	first, cursor, err := s.ListAdminCustomersPage(ctx, tenant, 1, "")
	if err != nil || len(first) != 1 || cursor == "" {
		t.Fatal("pagination lost current users")
	}
	second, tail, err := s.ListAdminCustomersPage(ctx, tenant, 1, cursor)
	if err != nil || len(second) != 1 || tail != "" || second[0].UserID == first[0].UserID {
		t.Fatal("pagination repeats or skips")
	}
	retained, err := s.GetWallet(ctx, tenant, wallet.ID)
	if err != nil || retained.BalanceMicros != 99999970 {
		t.Fatal("deleted user's balance lost")
	}
	ledger, err := s.ListLedgerEntries(ctx, tenant, wallet.ID, 20)
	if err != nil || len(ledger) != 1 {
		t.Fatal("deleted user's ledger lost")
	}
}

func TestRedemptionArchiveAuditFailureRollsBack(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	codes, err := s.CreateRedemptionCodes(ctx, NewRedemptionBatch{TenantID: tenant, Label: "audit-rollback", AmountMicros: 200, Count: 1, CreatedBy: user})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ArchiveRedemptionCode(ctx, tenant, codes[0].ID, "nonexistent-audit-actor", ""); err == nil {
		t.Fatal("archive accepted missing audit actor")
	}
	var status string
	var hidden bool
	if err = db.QueryRow(ctx, "SELECT status,archived_at IS NOT NULL FROM billing_redemption_codes WHERE id=$1", codes[0].ID).Scan(&status, &hidden); err != nil || hidden || status != "active" {
		t.Fatal("audit failure left partial archive")
	}
	if _, _, err = s.RedeemCode(ctx, tenant, user, codes[0].Code); err != nil {
		t.Fatal("audit rollback destroyed credential")
	}
}

func TestRedemptionArchiveSerializesWithRedemption(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	codes, err := s.CreateRedemptionCodes(ctx, NewRedemptionBatch{TenantID: tenant, Label: "archive-race", AmountMicros: 200, Count: 1, CreatedBy: user})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	result := make(chan error, 2)
	go func() { <-start; _, _, e := s.RedeemCode(ctx, tenant, user, codes[0].Code); result <- e }()
	go func() { <-start; _, e := s.ArchiveRedemptionCode(ctx, tenant, codes[0].ID, user, ""); result <- e }()
	close(start)
	for i := 0; i < 2; i++ {
		e := <-result
		if e != nil && !errors.Is(e, ErrRedemptionInvalid) {
			t.Fatal(e)
		}
	}
	var status string
	var hidden bool
	if err = db.QueryRow(ctx, "SELECT status,archived_at IS NOT NULL FROM billing_redemption_codes WHERE id=$1", codes[0].ID).Scan(&status, &hidden); err != nil || !hidden {
		t.Fatal("race lost archive")
	}
	var uses, entries int
	db.QueryRow(ctx, "SELECT count(*) FROM billing_redemption_uses WHERE tenant_id=$1", tenant).Scan(&uses)
	db.QueryRow(ctx, "SELECT count(*) FROM billing_ledger_entries WHERE tenant_id=$1 AND event_type='redemption'", tenant).Scan(&entries)
	expected := 0
	if status == "redeemed" {
		expected = 1
	} else if status != "voided" {
		t.Fatal("unexpected terminal state")
	}
	if uses != expected || entries != expected {
		t.Fatalf("race financial mismatch state %s uses %d ledger %d", status, uses, entries)
	}
}
