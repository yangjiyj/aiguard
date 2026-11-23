package repository

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CommittedOperationAudit struct {
	TenantID string
	AuditOperation
}
type operationAuditContextKey struct{}
type operationAuditContext struct {
	ip      string
	sink    func(CommittedOperationAudit)
	pending map[pgx.Tx][]CommittedOperationAudit
}

func WithOperationAudit(ctx context.Context, ip string, sink func(CommittedOperationAudit)) context.Context {
	return context.WithValue(ctx, operationAuditContextKey{}, &operationAuditContext{ip: ip, sink: sink, pending: map[pgx.Tx][]CommittedOperationAudit{}})
}
func operationAuditIP(ctx context.Context) string {
	if a, ok := ctx.Value(operationAuditContextKey{}).(*operationAuditContext); ok {
		return a.ip
	}
	return ""
}
func queueOperationAudit(ctx context.Context, tx pgx.Tx, event CommittedOperationAudit) {
	if a, ok := ctx.Value(operationAuditContextKey{}).(*operationAuditContext); ok {
		a.pending[tx] = append(a.pending[tx], event)
	}
}
func writeTransactionalOperationAudit(ctx context.Context, tx pgx.Tx, tenant, actor, action, targetType, targetID string, detail map[string]any) error {
	ip := operationAuditIP(ctx)
	id := uuid.NewString()
	payload, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_operations(id,tenant_id,user_id,action_type,action_detail,target_type,target_id,ip_address) VALUES($1,$2,NULLIF($3,''),$4,$5::jsonb,$6,$7,$8)`, id, tenant, actor, action, payload, targetType, targetID, ip)
	if err != nil {
		return err
	}
	queueOperationAudit(ctx, tx, CommittedOperationAudit{TenantID: tenant, AuditOperation: AuditOperation{ID: id, UserID: actor, ActionType: action, ActionDetail: detail, TargetType: targetType, TargetID: targetID, IPAddress: ip}})
	return nil
}
func commitWithOperationAudit(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if a, ok := ctx.Value(operationAuditContextKey{}).(*operationAuditContext); ok {
		events := a.pending[tx]
		delete(a.pending, tx)
		if a.sink != nil {
			for _, event := range events {
				a.sink(event)
			}
		}
	}
	return nil
}
