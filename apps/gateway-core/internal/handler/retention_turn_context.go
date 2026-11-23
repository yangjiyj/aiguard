package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionturn"
	"log"
)

type retentionTurnContextWriter interface {
	WriteRetentionTurnContext(context.Context, *modelrouter.RequestEnvelope, []byte)
}

func (w *RealAuditWriter) WriteRetentionTurnContext(ctx context.Context, envelope *modelrouter.RequestEnvelope, patch []byte) {
	if w == nil || envelope == nil || envelope.TenantID == "" || envelope.RequestID == "" {
		return
	}
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	scope := retentionartifact.NormalizeEnvironmentScope(envelope.EnvironmentScope)
	if _, err := w.db.Exec(ctx, retentionturn.UpdateSQL, envelope.TenantID, envelope.RequestID, scope, string(patch)); err != nil {
		log.Printf("Failed to write API turn correlation: %v", err)
	}
}

// Correlation is a small update to the synchronously ensured request row.
// Keep it available when production enables asynchronous evidence and billing.
func (w *AsyncAuditWriter) WriteRetentionTurnContext(ctx context.Context, envelope *modelrouter.RequestEnvelope, patch []byte) {
	if w == nil {
		return
	}
	if writer, ok := w.syncWriter.(retentionTurnContextWriter); ok {
		writer.WriteRetentionTurnContext(ctx, envelope, patch)
	}
}
func (w *BillingAuditWriter) WriteRetentionTurnContext(ctx context.Context, envelope *modelrouter.RequestEnvelope, patch []byte) {
	if w == nil {
		return
	}
	if writer, ok := w.inner.(retentionTurnContextWriter); ok {
		writer.WriteRetentionTurnContext(ctx, envelope, patch)
	}
}
