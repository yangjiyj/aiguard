package billing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrRedemptionInvalid        = errors.New("invalid redemption code")
	ErrRedemptionUsed           = errors.New("redemption code unavailable")
	ErrRedemptionNotRecoverable = errors.New("historic redemption code is not recoverable")
)

type NewRedemptionBatch struct {
	TenantID     string
	Label        string
	AmountMicros Micros
	Count        int
	ExpiresAt    *time.Time
	CreatedBy    string
}

type GeneratedRedemptionCode struct {
	ID           string     `json:"id"`
	Code         string     `json:"code"`
	CodeHint     string     `json:"code_hint"`
	Label        string     `json:"label"`
	AmountMicros Micros     `json:"amount_micros"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

type RedemptionCode struct {
	CopyAvailable      bool       `json:"copy_available"`
	ID                 string     `json:"id"`
	CodeHint           string     `json:"code_hint"`
	Label              string     `json:"label"`
	AmountMicros       Micros     `json:"amount_micros"`
	Status             string     `json:"status"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	CreatedBy          string     `json:"created_by,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	RedeemedAt         *time.Time `json:"redeemed_at,omitempty"`
	CreatedByName      string     `json:"created_by_name,omitempty"`
	RedeemedDepartment string     `json:"redeemed_department,omitempty"`
	RedeemedBy         string     `json:"redeemed_by,omitempty"`
}

func normalizeRedemptionCode(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, " ", "")
	return value
}

func redemptionHash(value string) string {
	sum := sha256.Sum256([]byte(normalizeRedemptionCode(value)))
	return hex.EncodeToString(sum[:])
}

func newRedemptionCode(prefix string) (string, string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	raw := strings.ToUpper(hex.EncodeToString(bytes))
	code := prefix + "-" + raw[0:8] + "-" + raw[8:16] + "-" + raw[16:24] + "-" + raw[24:32]
	return code, code[:12] + "..." + code[len(code)-5:], nil
}

func (s *Store) CreateRedemptionCodes(ctx context.Context, input NewRedemptionBatch) ([]GeneratedRedemptionCode, error) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.Label = strings.TrimSpace(input.Label)
	if input.TenantID == "" || input.Label == "" || len([]rune(input.Label)) > 80 || input.AmountMicros <= 0 || input.Count < 1 || input.Count > 500 {
		return nil, ErrInvalidCustomerLimit
	}
	if input.ExpiresAt != nil {
		expires := input.ExpiresAt.UTC()
		if !expires.After(time.Now().UTC()) {
			return nil, ErrInvalidCustomerLimit
		}
		input.ExpiresAt = &expires
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin redemption batch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result := make([]GeneratedRedemptionCode, 0, input.Count)
	for len(result) < input.Count {
		code, hint, err := newRedemptionCode(s.redemptionPrefix)
		if err != nil {
			return nil, fmt.Errorf("generate redemption code: %w", err)
		}
		item := GeneratedRedemptionCode{
			ID: "redeem_" + uuid.NewString(), Code: code, CodeHint: hint,
			Label: input.Label, AmountMicros: input.AmountMicros, ExpiresAt: input.ExpiresAt,
		}
		envelope, _ := json.Marshal(struct {
			TenantID string `json:"tenant"`
			ID       string `json:"id"`
			Code     string `json:"code"`
		}{input.TenantID, item.ID, code})
		ciphertext, _, err := secrets.EncryptProviderSecret(string(envelope))
		if err != nil {
			return nil, fmt.Errorf("encrypt redemption code: %w", err)
		}
		var createdAt time.Time
		err = tx.QueryRow(ctx, `
			INSERT INTO billing_redemption_codes
				(id, tenant_id, code_hash, code_hint, label, amount_micros, expires_at, created_by, code_ciphertext)
			VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9)
			RETURNING created_at
		`, item.ID, input.TenantID, redemptionHash(code), hint, input.Label, input.AmountMicros, input.ExpiresAt, input.CreatedBy, ciphertext).Scan(&createdAt)
		if isUniqueViolation(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("create redemption code: %w", err)
		}
		result = append(result, item)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit redemption batch: %w", err)
	}
	return result, nil
}

func (s *Store) ListRedemptionCodes(ctx context.Context, tenantID string, limit int) ([]RedemptionCode, error) {
	if tenantID == "" {
		return nil, ErrInvalidCustomerLimit
	}
	limit = billingLimit(limit, 100, 500)
	rows, err := s.db.Query(ctx, `
		SELECT c.id, c.code_hint, c.label, c.amount_micros, c.status, c.expires_at,
			COALESCE(c.created_by,''), c.created_at, c.redeemed_at, COALESCE(u.username,'')
		FROM billing_redemption_codes c
		LEFT JOIN billing_redemption_uses r ON r.tenant_id=c.tenant_id AND r.code_id=c.id
		LEFT JOIN users u ON u.tenant_id=r.tenant_id AND u.id=r.user_id
		WHERE c.tenant_id=$1 AND c.archived_at IS NULL ORDER BY c.created_at DESC, c.id DESC LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list redemption codes: %w", err)
	}
	defer rows.Close()
	items := []RedemptionCode{}
	for rows.Next() {
		var item RedemptionCode
		if err := rows.Scan(&item.ID, &item.CodeHint, &item.Label, &item.AmountMicros, &item.Status,
			&item.ExpiresAt, &item.CreatedBy, &item.CreatedAt, &item.RedeemedAt, &item.RedeemedBy); err != nil {
			return nil, fmt.Errorf("scan redemption code: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) SetRedemptionCodeStatus(ctx context.Context, tenantID, id, status string) error {
	if tenantID == "" || id == "" || (status != "active" && status != "disabled" && status != "voided") {
		return ErrInvalidCustomerLimit
	}
	result, err := s.db.Exec(ctx, `
		UPDATE billing_redemption_codes SET status=$3
		WHERE tenant_id=$1 AND id=$2 AND archived_at IS NULL AND status IN ('active','disabled')
	`, tenantID, id, status)
	if err != nil {
		return fmt.Errorf("update redemption code status: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrRedemptionInvalid
	}
	return nil
}

func ensureWalletTx(ctx context.Context, tx pgx.Tx, tenantID, userID, currency string) (*Wallet, error) {
	wallet, err := scanWallet(tx.QueryRow(ctx, `
		INSERT INTO billing_wallets (id, tenant_id, user_id, currency)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (tenant_id, user_id, currency) DO UPDATE SET updated_at=billing_wallets.updated_at
		RETURNING id, tenant_id, user_id, currency, balance_micros, reserved_micros, version, created_at, updated_at
	`, "wallet_"+uuid.NewString(), tenantID, userID, currency))
	if err != nil {
		return nil, fmt.Errorf("ensure redemption wallet: %w", err)
	}
	return wallet, nil
}

func (s *Store) RedeemCode(ctx context.Context, tenantID, userID, code string) (*Wallet, Micros, error) {
	if tenantID == "" || userID == "" || normalizeRedemptionCode(code) == "" {
		return nil, 0, ErrRedemptionInvalid
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("begin redemption: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id, status string
	var amount Micros
	var expiresAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, status, amount_micros, expires_at
		FROM billing_redemption_codes WHERE tenant_id=$1 AND code_hash=$2 AND archived_at IS NULL FOR UPDATE
	`, tenantID, redemptionHash(code)).Scan(&id, &status, &amount, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, ErrRedemptionInvalid
	}
	if err != nil {
		return nil, 0, fmt.Errorf("lock redemption code: %w", err)
	}
	if status != "active" {
		return nil, 0, ErrRedemptionUsed
	}
	if expiresAt != nil && !expiresAt.After(time.Now().UTC()) {
		return nil, 0, ErrRedemptionUsed
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "allowance-settings:"+tenantID); err != nil {
		return nil, 0, err
	}
	currency, err := s.billingCurrencyForTenant(ctx, tx, tenantID)
	if err != nil {
		return nil, 0, err
	}
	var mismatch bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_wallets w WHERE w.tenant_id=$1 AND w.user_id=$2 AND w.currency<>$3 AND `+fundedWalletPredicate+`)`, tenantID, userID, currency).Scan(&mismatch); err != nil {
		return nil, 0, err
	}
	if mismatch {
		return nil, 0, ErrAllowanceCurrency
	}
	wallet, err := ensureWalletTx(ctx, tx, tenantID, userID, currency)
	if err != nil {
		return nil, 0, err
	}
	nextBalance, err := addMicros(wallet.BalanceMicros, amount)
	if err != nil {
		return nil, 0, err
	}
	wallet, err = updateWallet(ctx, tx, wallet, WalletState{BalanceMicros: nextBalance, ReservedMicros: wallet.ReservedMicros})
	if err != nil {
		return nil, 0, err
	}
	now := time.Now().UTC()
	result, err := tx.Exec(ctx, `
		UPDATE billing_redemption_codes SET status='redeemed', redeemed_at=$3
		WHERE tenant_id=$1 AND id=$2 AND status='active'
	`, tenantID, id, now)
	if err != nil {
		return nil, 0, fmt.Errorf("redeem code status: %w", err)
	}
	if result.RowsAffected() != 1 {
		return nil, 0, ErrRedemptionUsed
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO billing_redemption_uses (id, tenant_id, code_id, user_id, wallet_id, amount_micros, redeemed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, "redeem_use_"+uuid.NewString(), tenantID, id, userID, wallet.ID, amount, now); err != nil {
		return nil, 0, fmt.Errorf("record redemption use: %w", err)
	}
	if err := insertLedger(ctx, tx, ledgerInsert{
		TenantID: tenantID, WalletID: wallet.ID, EventType: "redemption",
		BalanceDelta: amount, BalanceAfter: wallet.BalanceMicros, ReservedAfter: wallet.ReservedMicros,
		IdempotencyKey: "redemption:" + id, ActorType: "customer", ActorID: userID,
	}); err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("commit redemption: %w", err)
	}
	return wallet, amount, nil
}

// RevealRedemptionCode is used only by the platform administration handler.
func (s *Store) RevealRedemptionCode(ctx context.Context, tenant, id string) (string, error) {
	if tenant == "" || id == "" || len(id) > 128 {
		return "", ErrRedemptionInvalid
	}
	var ciphertext, hash string
	err := s.db.QueryRow(ctx, "SELECT COALESCE(code_ciphertext,''),code_hash FROM billing_redemption_codes WHERE tenant_id=$1 AND id=$2 AND archived_at IS NULL", tenant, id).Scan(&ciphertext, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrRedemptionInvalid
	}
	if err != nil {
		return "", err
	}
	if ciphertext == "" {
		return "", ErrRedemptionNotRecoverable
	}
	if !strings.HasPrefix(ciphertext, "enc:v1:") {
		return "", errors.New("invalid encrypted redemption envelope")
	}
	value, err := secrets.DecryptProviderSecret(ciphertext)
	if err != nil {
		return "", errors.New("redemption decryption unavailable")
	}
	var envelope struct {
		TenantID string `json:"tenant"`
		ID       string `json:"id"`
		Code     string `json:"code"`
	}
	if json.Unmarshal([]byte(value), &envelope) != nil || envelope.TenantID != tenant || envelope.ID != id || envelope.Code == "" || redemptionHash(envelope.Code) != hash {
		return "", errors.New("redemption envelope does not match")
	}
	return envelope.Code, nil
}
