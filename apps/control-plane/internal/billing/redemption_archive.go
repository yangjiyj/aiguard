package billing

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RedemptionArchiveAudit is returned after its audit and mutation commit together.
type RedemptionArchiveAudit struct {
	ID     string
	Detail map[string]any
}

// ArchiveRedemptionCode preserves redeemed value, use records and immutable ledger entries.
// Unused codes become terminally voided under the same row lock used by redemption.
func (s *Store) ArchiveRedemptionCode(ctx context.Context, tenant, id, actor, ip string) (*RedemptionArchiveAudit, error) {
	if tenant == "" || id == "" || actor == "" {
		return nil, ErrRedemptionInvalid
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM billing_redemption_codes WHERE tenant_id=$1 AND id=$2 AND archived_at IS NULL FOR UPDATE`, tenant, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRedemptionInvalid
	}
	if err != nil {
		return nil, err
	}
	next := status
	if next != "redeemed" {
		next = "voided"
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_redemption_codes SET archived_at=now(),archived_by=$3,status=$4,code_ciphertext=NULL WHERE tenant_id=$1 AND id=$2`, tenant, id, actor, next); err != nil {
		return nil, err
	}
	event := &RedemptionArchiveAudit{ID: uuid.NewString(), Detail: map[string]any{"tenant_id": tenant, "previous_status": status, "status": next, "actor_user_id": actor, "ip_address": ip, "action_type": "billing.redemption.delete", "redemption_id": id}}
	payload, _ := json.Marshal(event.Detail)
	if _, err = tx.Exec(ctx, `INSERT INTO audit_operations(id,tenant_id,user_id,action_type,action_detail,target_type,target_id,ip_address) VALUES($1,$2,$3,'billing.redemption.delete',$4::jsonb,'billing_redemption_code',$5,$6)`, event.ID, tenant, actor, payload, id, ip); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return event, nil
}
