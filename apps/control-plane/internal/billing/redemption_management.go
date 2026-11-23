package billing

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"time"
	"unicode/utf8"
)

type RedemptionFilter struct {
	Page     int
	PageSize int
	Status   string
	Label    string
	Redeemer string
	// Keyword 按兑换码提示位（code_hint）模糊检索，方便管理员凭完整码片段定位某一张码。
	Keyword  string
	From     *time.Time
	To       *time.Time
}
type RedemptionPage struct {
	Items    []RedemptionCode
	Total    int
	Page     int
	PageSize int
}

const redemptionStatusSQL = `CASE WHEN c.status IN ('active','disabled') AND c.expires_at<=now() THEN 'expired' ELSE c.status END`
const redemptionJoins = ` FROM billing_redemption_codes c
 LEFT JOIN billing_redemption_uses used ON used.tenant_id=c.tenant_id AND used.code_id=c.id
 LEFT JOIN users u ON u.tenant_id=used.tenant_id AND u.id=used.user_id
 LEFT JOIN teams department ON department.tenant_id=u.tenant_id AND department.id=u.department_id
 LEFT JOIN users creator ON creator.tenant_id=c.tenant_id AND creator.id=c.created_by `
const redemptionWhere = ` WHERE c.tenant_id=$1 AND c.archived_at IS NULL AND ($2::text='' OR ` + redemptionStatusSQL + `=$2)
 AND ($3::text='' OR c.label=$3) AND ($4::text='' OR COALESCE(u.username,'') ILIKE '%'||$4||'%' OR COALESCE(department.name,'') ILIKE '%'||$4||'%')
 AND ($7::text='' OR c.code_hint ILIKE '%'||$7||'%')
 AND ($5::timestamptz IS NULL OR c.created_at>=$5) AND ($6::timestamptz IS NULL OR c.created_at<=$6) `

func (s *Store) ListRedemptionCodePage(ctx context.Context, tenant string, f RedemptionFilter) (RedemptionPage, error) {
	out := RedemptionPage{Items: []RedemptionCode{}}
	if tenant == "" || utf8.RuneCountInString(f.Label) > 80 || len(f.Redeemer) > 256 || len(f.Keyword) > 64 || f.Page < 0 || f.Page > 1000000 || f.PageSize < 0 || f.PageSize > 500 || (f.From != nil && f.To != nil && f.From.After(*f.To)) {
		return out, ErrInvalidCustomerLimit
	}
	switch f.Status {
	case "", "active", "disabled", "redeemed", "expired", "voided":
	default:
		return out, ErrInvalidCustomerLimit
	}
	if f.Page == 0 {
		f.Page = 1
	}
	if f.PageSize == 0 {
		f.PageSize = 20
	}
	out.Page = f.Page
	out.PageSize = f.PageSize
	args := []any{tenant, f.Status, f.Label, f.Redeemer, f.From, f.To, f.Keyword}
	if err := s.db.QueryRow(ctx, "SELECT count(*)"+redemptionJoins+redemptionWhere, args...).Scan(&out.Total); err != nil {
		return out, fmt.Errorf("count redemption codes: %w", err)
	}
	query := `SELECT c.id,c.code_hint,c.label,c.amount_micros,` + redemptionStatusSQL + `,c.expires_at,COALESCE(c.created_by,''),c.created_at,c.redeemed_at,COALESCE(u.username,''),COALESCE(creator.username,c.created_by,''),COALESCE(department.name,''),COALESCE(c.code_ciphertext,'')<>''` + redemptionJoins + redemptionWhere + ` ORDER BY c.created_at DESC,c.id DESC LIMIT $8 OFFSET $9`
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var item RedemptionCode
		if err = rows.Scan(&item.ID, &item.CodeHint, &item.Label, &item.AmountMicros, &item.Status, &item.ExpiresAt, &item.CreatedBy, &item.CreatedAt, &item.RedeemedAt, &item.RedeemedBy, &item.CreatedByName, &item.RedeemedDepartment, &item.CopyAvailable); err != nil {
			return out, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}
func (s *Store) BatchSetRedemptionStatus(ctx context.Context, tenant string, ids []string, status string) (int64, error) {
	if tenant == "" || len(ids) == 0 || len(ids) > 500 || (status != "disabled" && status != "voided") {
		return 0, ErrInvalidCustomerLimit
	}
	for _, id := range ids {
		if id == "" || len(id) > 64 {
			return 0, ErrInvalidCustomerLimit
		}
	}
	result, err := s.db.Exec(ctx, `UPDATE billing_redemption_codes SET status=$3 WHERE tenant_id=$1 AND id=ANY($2::text[]) AND archived_at IS NULL AND status IN ('active','disabled')`, tenant, ids, status)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

type RedemptionDetails struct {
	ID           string     `json:"id"`
	CodeHint     string     `json:"code_hint"`
	Status       string     `json:"status"`
	AmountMicros Micros     `json:"amount_micros"`
	RedeemedBy   string     `json:"redeemed_by"`
	Department   string     `json:"department"`
	RedeemedAt   *time.Time `json:"redeemed_at,omitempty"`
	WalletID     string     `json:"wallet_id"`
	LedgerID     string     `json:"ledger_id"`
}

func (s *Store) RedemptionDetail(ctx context.Context, tenant, id string) (*RedemptionDetails, error) {
	if tenant == "" || id == "" {
		return nil, ErrRedemptionInvalid
	}
	var item RedemptionDetails
	err := s.db.QueryRow(ctx, `SELECT c.id,c.code_hint,`+redemptionStatusSQL+`,c.amount_micros,COALESCE(u.username,''),COALESCE(department.name,''),c.redeemed_at,COALESCE(used.wallet_id,''),COALESCE(l.id,'')`+redemptionJoins+` LEFT JOIN billing_ledger_entries l ON l.tenant_id=c.tenant_id AND l.idempotency_key='redemption:'||c.id AND l.event_type='redemption'
 WHERE c.tenant_id=$1 AND c.id=$2 AND c.archived_at IS NULL`, tenant, id).Scan(&item.ID, &item.CodeHint, &item.Status, &item.AmountMicros, &item.RedeemedBy, &item.Department, &item.RedeemedAt, &item.WalletID, &item.LedgerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRedemptionInvalid
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}
func (s *Store) WalkRedemptionHints(ctx context.Context, tenant, batch string, write func(string, string) error) error {
	if tenant == "" || batch == "" || utf8.RuneCountInString(batch) > 80 {
		return ErrInvalidCustomerLimit
	}
	rows, err := s.db.Query(ctx, `SELECT c.code_hint,`+redemptionStatusSQL+` FROM billing_redemption_codes c WHERE c.tenant_id=$1 AND c.label=$2 AND c.archived_at IS NULL ORDER BY c.created_at,c.id`, tenant, batch)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var hint, status string
		if err = rows.Scan(&hint, &status); err != nil {
			return err
		}
		if err = write(hint, status); err != nil {
			return err
		}
	}
	return rows.Err()
}
