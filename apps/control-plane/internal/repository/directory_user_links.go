package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type DirectoryUserLink struct {
	ID                string
	TenantID          string
	DirectorySourceID string
	ExternalObjectID  string
	SourceDN          string
	UserID            string
	LastSeenAt        time.Time
}

func (r *DirectorySourceRepository) BindDirectoryUser(ctx context.Context, link DirectoryUserLink) error {
	if link.TenantID == "" || link.DirectorySourceID == "" || link.ExternalObjectID == "" || link.UserID == "" {
		return errors.New("directory user link fields are required")
	}
	if link.ID == "" {
		link.ID = "dul_" + uuid.NewString()[:8]
	}
	_, err := r.db.Exec(ctx, `INSERT INTO directory_user_links (
		id, tenant_id, directory_source_id, external_object_id, source_dn, user_id
	) VALUES ($1,$2,$3,$4,$5,$6)
	ON CONFLICT (tenant_id, directory_source_id, external_object_id) DO UPDATE SET
		source_dn=EXCLUDED.source_dn, user_id=EXCLUDED.user_id,
		last_seen_at=now(), updated_at=now()`,
		link.ID, link.TenantID, link.DirectorySourceID, link.ExternalObjectID, link.SourceDN, link.UserID)
	if err != nil {
		return fmt.Errorf("bind directory user: %w", err)
	}
	return nil
}
func (r *DirectorySourceRepository) GetBoundUser(ctx context.Context, tenantID, sourceID, externalObjectID string) (*User, error) {
	user, err := scanUser(r.db.QueryRow(ctx, `
		SELECT u.id, u.tenant_id, u.username, u.email, u.phone, u.password_hash, u.must_change_password, u.role, u.status, u.external_subject
		FROM directory_user_links l JOIN users u ON u.id=l.user_id
		WHERE l.tenant_id=$1 AND l.directory_source_id=$2 AND l.external_object_id=$3`, tenantID, sourceID, externalObjectID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get bound directory user: %w", err)
	}
	return user, nil
}
