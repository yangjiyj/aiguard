package alert

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// InboxService wraps AlertInboxRepository with business logic.
type InboxService struct {
	repo *repository.AlertInboxRepository
}

// NewInboxService creates a new InboxService.
func NewInboxService(repo *repository.AlertInboxRepository) *InboxService {
	return &InboxService{repo: repo}
}

// Push inserts a new alert into the inbox for the given tenant.
func (s *InboxService) Push(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL string) error {
	return s.repo.Insert(ctx, &repository.AlertInboxItem{
		ID:        fmt.Sprintf("alert_%s", uuid.New().String()[:8]),
		TenantID:  tenantID,
		Severity:  severity,
		Type:      typ,
		Title:     title,
		BodyJSON:  body,
		TargetURL: targetURL,
	})
}

// UpsertByGroup folds an alert onto an existing UNREAD alert sharing groupKey
// (bumping its occurrence count and re-floating it) or, if none exists, opens a
// new alert. It returns created=true only when a new alert row was inserted, so
// callers can fire external notifications exactly once per distinct issue rather
// than once per recurrence. The bookkeeping (group_key, occurrence_count,
// first_seen_at, last_seen_at) lives inside body_json — no schema change.
func (s *InboxService) UpsertByGroup(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL, groupKey string) (bool, error) {
	return s.repo.UpsertByGroup(ctx, &repository.AlertInboxItem{
		ID:        fmt.Sprintf("alert_%s", uuid.New().String()[:8]),
		TenantID:  tenantID,
		Severity:  severity,
		Type:      typ,
		Title:     title,
		BodyJSON:  body,
		TargetURL: targetURL,
	}, groupKey)
}

// MarkRead marks a single alert as read.
// 带租户过滤（越权修复）：调用方必须传入当前用户所属租户。
func (s *InboxService) MarkRead(ctx context.Context, tenantID, id string) error {
	return s.repo.MarkRead(ctx, tenantID, id)
}

// Unread returns all unread alerts for the tenant (up to 50).
func (s *InboxService) Unread(ctx context.Context, tenantID string) ([]*repository.AlertInboxItem, error) {
	return s.repo.ListUnread(ctx, tenantID, 50)
}
