package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertInboxItem represents a row in the alert_inbox table.
type AlertInboxItem struct {
	ID        string         `json:"id"`
	TenantID  string         `json:"tenant_id"`
	Severity  string         `json:"severity"` // info | warning | high | critical
	Type      string         `json:"type"`
	Title     string         `json:"title"`
	BodyJSON  map[string]any `json:"body_json"`
	TargetURL string         `json:"target_url,omitempty"`
	ReadAt    *time.Time     `json:"read_at,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// AlertInboxRepository handles alert_inbox database operations.
type AlertInboxRepository struct {
	db *pgxpool.Pool
}

// NewAlertInboxRepository creates a new AlertInboxRepository.
func NewAlertInboxRepository(db *pgxpool.Pool) *AlertInboxRepository {
	return &AlertInboxRepository{db: db}
}

// Insert persists a new alert inbox item.
func (r *AlertInboxRepository) Insert(ctx context.Context, item *AlertInboxItem) error {
	bodyBytes, err := json.Marshal(item.BodyJSON)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, `
		INSERT INTO alert_inbox (id, tenant_id, severity, type, title, body_json, target_url, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, item.ID, item.TenantID, item.Severity, item.Type, item.Title,
		string(bodyBytes), item.TargetURL, time.Now().UTC())
	return err
}

// UpsertByGroup folds an event onto an existing UNREAD alert that shares
// groupKey, or inserts a new alert when none exists. It returns created=true
// only when a new row was inserted.
//
// Dedup scope is the UNREAD queue: once an operator reads/acknowledges an alert
// it drops out of the group, so the next recurrence opens a fresh alert (the
// issue resurfaced after being triaged). On a repeat it bumps occurrence_count,
// refreshes last_seen_at, re-floats the row (created_at = now, so it returns to
// the top of the newest-first inbox), escalates severity to the max seen, and
// refreshes title/target/body to the latest occurrence's details — preserving
// the original first_seen_at. All bookkeeping lives in body_json, so there is no
// schema migration and the behaviour is fully reversible by disabling dedup.
//
// The read-then-write is not wrapped in a transaction: the bridge processes a
// batch sequentially in a single goroutine, so concurrent inserts for the same
// group key do not occur in practice. A duplicate row from a rare race would
// simply be folded on the following cycle.
func (r *AlertInboxRepository) UpsertByGroup(ctx context.Context, item *AlertInboxItem, groupKey string) (bool, error) {
	incomingCount, hasIncomingCount := item.BodyJSON["occurrence_count"]
	now := time.Now().UTC()

	var existingID, existingSeverity, existingTitle, existingType, existingTargetURL, existingBodyStr string
	err := r.db.QueryRow(ctx, `
		SELECT id, severity, title, type, COALESCE(target_url, ''), body_json
		FROM alert_inbox
		WHERE tenant_id = $1 AND read_at IS NULL AND body_json->>'group_key' = $2
		ORDER BY created_at DESC
		LIMIT 1
	`, item.TenantID, groupKey).Scan(&existingID, &existingSeverity, &existingTitle, &existingType, &existingTargetURL, &existingBodyStr)

	if errors.Is(err, pgx.ErrNoRows) {
		body := item.BodyJSON
		if body == nil {
			body = map[string]any{}
		}
		body["group_key"] = groupKey
		body["occurrence_count"] = 1
		if hasIncomingCount {
			body["occurrence_count"] = incomingCount
		}
		body["first_seen_at"] = now.Format(time.RFC3339)
		body["last_seen_at"] = now.Format(time.RFC3339)
		bodyBytes, mErr := json.Marshal(body)
		if mErr != nil {
			return false, mErr
		}
		_, iErr := r.db.Exec(ctx, `
			INSERT INTO alert_inbox (id, tenant_id, severity, type, title, body_json, target_url, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, item.ID, item.TenantID, item.Severity, item.Type, item.Title,
			string(bodyBytes), item.TargetURL, now)
		if iErr != nil {
			return false, iErr
		}
		return true, nil
	}
	if err != nil {
		return false, err
	}

	// Repeat occurrence: fold onto the existing unread row.
	var existingBody map[string]any
	if existingBodyStr != "" {
		_ = json.Unmarshal([]byte(existingBodyStr), &existingBody)
	}
	if existingBody == nil {
		existingBody = map[string]any{}
	}

	count := 1
	switch n := existingBody["occurrence_count"].(type) {
	case float64:
		count = int(n)
	case int:
		count = n
	}
	firstSeen, _ := existingBody["first_seen_at"].(string)
	if firstSeen == "" {
		firstSeen = now.Format(time.RFC3339)
	}

	replaceRepresentative := severityRank(item.Severity) >= severityRank(existingSeverity)
	representativeTitle := item.Title
	representativeType := item.Type
	representativeTargetURL := item.TargetURL
	body := item.BodyJSON
	if !replaceRepresentative {
		body = existingBody
		representativeTitle = existingTitle
		representativeType = existingType
		representativeTargetURL = existingTargetURL
	}
	if body == nil {
		body = map[string]any{}
	}
	// Counters describe the latest group state, independently of the retained
	// highest-severity representative evidence.
	for _, key := range []string{"distinct_occurrences", "affected_users", "last_calc_at", "group_first_seen_at", "group_last_seen_at"} {
		if value, ok := item.BodyJSON[key]; ok {
			body[key] = value
		}
	}
	body["group_key"] = groupKey
	body["occurrence_count"] = count + 1
	if hasIncomingCount {
		body["occurrence_count"] = incomingCount
	}
	body["first_seen_at"] = firstSeen
	body["last_seen_at"] = now.Format(time.RFC3339)
	bodyBytes, mErr := json.Marshal(body)
	if mErr != nil {
		return false, mErr
	}

	_, uErr := r.db.Exec(ctx, `
		UPDATE alert_inbox
		SET severity = $1, type = $2, title = $3, body_json = $4, target_url = $5, created_at = $6
		WHERE id = $7
	`, maxSeverity(existingSeverity, item.Severity), representativeType, representativeTitle,
		string(bodyBytes), representativeTargetURL, now, existingID)
	if uErr != nil {
		return false, uErr
	}
	return false, nil
}

// severityRank orders inbox severities so the highest seen for a group wins.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "warning", "medium":
		return 2
	case "info", "low":
		return 1
	}
	return 0
}

// maxSeverity returns whichever of a, b ranks higher (a on a tie).
func maxSeverity(a, b string) string {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

// MarkRead sets read_at = now for the given alert.
// 带租户过滤（越权修复）：只允许标记本租户的告警，拿到别家 alert id 也只是 no-op。
func (r *AlertInboxRepository) MarkRead(ctx context.Context, tenantID, id string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE alert_inbox SET read_at = $1 WHERE id = $2 AND tenant_id = $3`,
		time.Now().UTC(), id, tenantID,
	)
	return err
}

// ListUnread returns unread alerts for the tenant, newest first.
func (r *AlertInboxRepository) ListUnread(ctx context.Context, tenantID string, limit int) ([]*AlertInboxItem, error) {
	q := `
		SELECT id, tenant_id, severity, type, title, body_json,
		       COALESCE(target_url, '') AS target_url, read_at, created_at
		FROM alert_inbox
		WHERE tenant_id = $1 AND read_at IS NULL
		ORDER BY created_at DESC
	`
	args := []interface{}{tenantID}
	if limit > 0 {
		q += " LIMIT $2"
		args = append(args, limit)
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlertInboxItems(rows)
}

// List returns all alerts (read + unread) for the tenant, newest first.
func (r *AlertInboxRepository) List(ctx context.Context, tenantID string, limit int) ([]*AlertInboxItem, error) {
	q := `
		SELECT id, tenant_id, severity, type, title, body_json,
		       COALESCE(target_url, '') AS target_url, read_at, created_at
		FROM alert_inbox
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`
	args := []interface{}{tenantID}
	if limit > 0 {
		q += " LIMIT $2"
		args = append(args, limit)
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlertInboxItems(rows)
}

// CountUnread returns the number of unread alerts for the tenant.
func (r *AlertInboxRepository) CountUnread(ctx context.Context, tenantID string) (int, error) {
	var count int
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM alert_inbox WHERE tenant_id = $1 AND read_at IS NULL`,
		tenantID,
	).Scan(&count)
	return count, err
}

// scanAlertInboxItems scans pgx rows into an AlertInboxItem slice.
func scanAlertInboxItems(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}) ([]*AlertInboxItem, error) {
	var out []*AlertInboxItem
	for rows.Next() {
		var item AlertInboxItem
		var bodyStr string
		if err := rows.Scan(
			&item.ID, &item.TenantID, &item.Severity, &item.Type,
			&item.Title, &bodyStr, &item.TargetURL, &item.ReadAt, &item.CreatedAt,
		); err != nil {
			return nil, err
		}
		if bodyStr != "" {
			_ = json.Unmarshal([]byte(bodyStr), &item.BodyJSON)
		}
		out = append(out, &item)
	}
	return out, rows.Err()
}
