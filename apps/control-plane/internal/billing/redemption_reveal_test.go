package billing

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRedemptionEncryptedCopyIsolationAndLegacy(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "fixture-redemption-encryption-secret")
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	codes, err := s.CreateRedemptionCodes(ctx, NewRedemptionBatch{TenantID: tenant, Label: "copy-fixture", AmountMicros: 100, Count: 2, CreatedBy: user})
	if err != nil {
		t.Fatal("create failed")
	}
	code, err := s.RevealRedemptionCode(ctx, tenant, codes[0].ID)
	if err != nil || code != codes[0].Code {
		t.Fatal("admin copy differs")
	}
	if _, err = s.RevealRedemptionCode(ctx, "other-tenant", codes[0].ID); !errors.Is(err, ErrRedemptionInvalid) {
		t.Fatal("tenant isolation failed")
	}
	var stored string
	if err = db.QueryRow(ctx, "SELECT code_ciphertext FROM billing_redemption_codes WHERE id=$1", codes[0].ID).Scan(&stored); err != nil || !strings.HasPrefix(stored, "enc:v1:") || strings.Contains(stored, codes[0].Code) {
		t.Fatal("code not encrypted")
	}
	_, err = db.Exec(ctx, "UPDATE billing_redemption_codes SET code_ciphertext=NULL WHERE id=$1", codes[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevealRedemptionCode(ctx, tenant, codes[1].ID); !errors.Is(err, ErrRedemptionNotRecoverable) {
		t.Fatal("legacy must fail explicitly")
	}
	_, err = db.Exec(ctx, "UPDATE billing_redemption_codes SET code_ciphertext=$1 WHERE id=$2", stored, codes[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevealRedemptionCode(ctx, tenant, codes[1].ID); err == nil {
		t.Fatal("swapped ciphertext accepted")
	}
}
