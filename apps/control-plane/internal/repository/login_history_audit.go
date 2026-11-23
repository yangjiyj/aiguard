package repository

import (
	"context"
	"fmt"
	"time"
)

// LoginHistoryAuditEntry is one login attempt as seen by the auditor
// (W4 separation of duties: login history belongs to the audit duty).
type LoginHistoryAuditEntry struct {
	LoginHistoryEntry
	Username string
	TenantID string
}

// LoginHistoryAuditFilter narrows the tenant-wide login history listing.
type LoginHistoryAuditFilter struct {
	// TenantID limits results to one tenant; empty means every tenant
	// (only used for callers in the system tenant).
	TenantID string
	UserID   string
	Since    *time.Time
	Until    *time.Time
	Limit    int
	Offset   int
}

// ListForAudit returns login attempts across users, newest first, plus the
// total matching count. Kept in its own file so it does not touch the login
// write path owned by another work stream.
func (r *UserLoginHistoryRepository) ListForAudit(ctx context.Context, f LoginHistoryAuditFilter) ([]*LoginHistoryAuditEntry, int, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	const where = `
		WHERE ($1 = '' OR u.tenant_id = $1)
		  AND ($2 = '' OR h.user_id = $2)
		  AND ($3::timestamptz IS NULL OR h.logged_at >= $3)
		  AND ($4::timestamptz IS NULL OR h.logged_at < $4)`
	args := []interface{}{f.TenantID, f.UserID, f.Since, f.Until}

	var total int
	if err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM user_login_history h
		JOIN users u ON u.id = h.user_id`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count login history: %w", err)
	}

	rows, err := r.db.Query(ctx, `
		SELECT h.id, h.user_id, h.logged_at, COALESCE(h.ip, ''), COALESCE(h.user_agent, ''),
		       h.success, COALESCE(h.failure_reason, ''), u.username, u.tenant_id
		FROM user_login_history h
		JOIN users u ON u.id = h.user_id`+where+`
		ORDER BY h.logged_at DESC, h.id DESC
		LIMIT $5 OFFSET $6`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list login history: %w", err)
	}
	defer rows.Close()

	entries := []*LoginHistoryAuditEntry{}
	for rows.Next() {
		e := &LoginHistoryAuditEntry{}
		if err := rows.Scan(&e.ID, &e.UserID, &e.LoggedAt, &e.IP, &e.UserAgent,
			&e.Success, &e.FailureReason, &e.Username, &e.TenantID); err != nil {
			return nil, 0, fmt.Errorf("scan login history: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}
