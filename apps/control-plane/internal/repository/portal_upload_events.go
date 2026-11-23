package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/userhistory"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PortalUploadEvent 是门户上传留痕记录（轻量，无 chat 流外键耦合）。
type PortalUploadEvent struct {
	ID           string
	TenantID     string
	UserID       string
	Filename     string
	MimeType     string
	Size         int64
	SHA256       string
	ReferenceKey string
	Model        string
	ActionTaken  string
	FindingsJSON json.RawMessage
	CreatedAt    time.Time
}

type PortalUploadEventRepository struct {
	db *pgxpool.Pool
}

func NewPortalUploadEventRepository(db *pgxpool.Pool) *PortalUploadEventRepository {
	return &PortalUploadEventRepository{db: db}
}

func (r *PortalUploadEventRepository) Insert(ctx context.Context, e PortalUploadEvent) error {
	if e.ID == "" || e.TenantID == "" || e.UserID == "" || e.Filename == "" || e.SHA256 == "" {
		return fmt.Errorf("portal upload event missing required fields")
	}
	created := e.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	findings := e.FindingsJSON
	if len(findings) == 0 {
		findings = []byte("{}")
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO portal_upload_events (id, tenant_id, user_id, filename, mime_type, size, sha256, reference_key, model, action_taken, findings_json, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, COALESCE(NULLIF($12::timestamptz, '0001-01-01 00:00:00 UTC'), NOW()))`,
		e.ID, e.TenantID, e.UserID, e.Filename, e.MimeType, e.Size, e.SHA256, e.ReferenceKey, e.Model, e.ActionTaken, findings, created)
	return err
}

func (r *PortalUploadEventRepository) ListByUser(ctx context.Context, tenantID, userID string, limit, offset int) ([]PortalUploadEvent, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var total int
	if err := r.db.QueryRow(ctx, userhistory.AuditOwnersCTE+`SELECT COUNT(*) FROM portal_upload_events WHERE tenant_id = $1 AND user_id IN (SELECT user_id FROM user_history)`, tenantID, userID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(ctx, userhistory.AuditOwnersCTE+`
		SELECT id, tenant_id, user_id, filename, mime_type, size, sha256, reference_key, model, action_taken, findings_json, created_at
		FROM portal_upload_events
		WHERE tenant_id = $1 AND user_id IN (SELECT user_id FROM user_history)
		ORDER BY created_at DESC,id DESC
		LIMIT $3 OFFSET $4`, tenantID, userID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []PortalUploadEvent
	for rows.Next() {
		var e PortalUploadEvent
		if err := rows.Scan(&e.ID, &e.TenantID, &e.UserID, &e.Filename, &e.MimeType, &e.Size, &e.SHA256, &e.ReferenceKey, &e.Model, &e.ActionTaken, &e.FindingsJSON, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

type PortalLegacyUploadPosition struct {
	ID        string    `json:"id"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}
type PortalLegacyUploadIndex struct {
	ID            string `json:"id"`
	Matched       bool   `json:"matched"`
	GatewayBefore int    `json:"gateway_before"`
}

// LegacyIndex reads ranks and hash coverage for portal-only history. Gateway
// upload events themselves are never deduplicated or rewritten.
func (r *PortalUploadEventRepository) LegacyIndex(ctx context.Context, tenant, user string, items []PortalLegacyUploadPosition) ([]PortalLegacyUploadIndex, error) {
	raw, err := json.Marshal(items)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, userhistory.AuditOwnersCTE+`, owned_uploads AS(
 SELECT id,sha256,created_at FROM portal_upload_events WHERE tenant_id=$1 AND user_id IN(SELECT user_id FROM user_history))
 SELECT item.id,EXISTS(SELECT 1 FROM owned_uploads g WHERE g.sha256=item.sha256),
 (SELECT COUNT(*) FROM owned_uploads g WHERE (g.created_at,g.id)>(item.created_at,item.id))
 FROM jsonb_to_recordset($3::jsonb) AS item(id text,sha256 text,created_at timestamptz)`, tenant, user, raw)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PortalLegacyUploadIndex{}
	for rows.Next() {
		var item PortalLegacyUploadIndex
		if err = rows.Scan(&item.ID, &item.Matched, &item.GatewayBefore); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
