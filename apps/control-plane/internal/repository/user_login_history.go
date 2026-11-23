package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 登录事件类型（user_login_history.event，迁移 880）。
const (
	LoginEventLogin  = "login"
	LoginEventLogout = "logout"
	LoginEventLocked = "locked"
)

// LoginHistoryEntry represents a user_login_history row
type LoginHistoryEntry struct {
	ID                int64
	UserID            string
	LoggedAt          time.Time
	IP                string
	UserAgent         string
	Success           bool
	FailureReason     string
	Event             string
	AttemptedUsername string
}

// LoginAttempt 是一次待落库的登录/登出/锁定事件。UserID 为空表示账号不存在。
type LoginAttempt struct {
	UserID            string
	AttemptedUsername string
	IP                string
	UserAgent         string
	Success           bool
	FailureReason     string
	Event             string
}

// UserLoginHistoryRepository handles user_login_history operations
type UserLoginHistoryRepository struct {
	db *pgxpool.Pool
}

// NewUserLoginHistoryRepository creates a new repository
func NewUserLoginHistoryRepository(db *pgxpool.Pool) *UserLoginHistoryRepository {
	return &UserLoginHistoryRepository{db: db}
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// Record writes one login-related event. Column widths follow migration 044/880.
func (r *UserLoginHistoryRepository) Record(ctx context.Context, a LoginAttempt) error {
	event := a.Event
	if event == "" {
		event = LoginEventLogin
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO user_login_history (user_id, logged_at, ip, user_agent, success, failure_reason, event, attempted_username)
		VALUES ($1, NOW(), $2, $3, $4, $5, $6, $7)
	`, nilIfEmpty(a.UserID), truncateRunes(a.IP, 64), truncateRunes(a.UserAgent, 512), a.Success,
		nilIfEmpty(truncateRunes(a.FailureReason, 128)), truncateRunes(event, 32), nilIfEmpty(truncateRunes(a.AttemptedUsername, 255)))
	if err != nil {
		return fmt.Errorf("insert login history: %w", err)
	}
	return nil
}

// Insert records a login attempt (kept for existing callers).
func (r *UserLoginHistoryRepository) Insert(ctx context.Context, userID, ip, userAgent string, success bool, failureReason string) error {
	return r.Record(ctx, LoginAttempt{UserID: userID, IP: ip, UserAgent: userAgent, Success: success, FailureReason: failureReason})
}

// ListByUser returns recent login history for a user (newest first)
func (r *UserLoginHistoryRepository) ListByUser(ctx context.Context, userID string, limit int) ([]*LoginHistoryEntry, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.db.Query(ctx, `
		SELECT id, COALESCE(user_id, ''), logged_at, COALESCE(ip, ''), COALESCE(user_agent, ''), success,
		       COALESCE(failure_reason, ''), COALESCE(event, 'login'), COALESCE(attempted_username, '')
		FROM user_login_history
		WHERE user_id = $1
		ORDER BY logged_at DESC, id DESC
		LIMIT $2
	`, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("list login history: %w", err)
	}
	defer rows.Close()

	var entries []*LoginHistoryEntry
	for rows.Next() {
		e := &LoginHistoryEntry{}
		if err := rows.Scan(&e.ID, &e.UserID, &e.LoggedAt, &e.IP, &e.UserAgent, &e.Success, &e.FailureReason, &e.Event, &e.AttemptedUsername); err != nil {
			return nil, fmt.Errorf("scan login history: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// UpdateUserLastLogin updates the users.last_login_at field
func (r *UserLoginHistoryRepository) UpdateUserLastLogin(ctx context.Context, userID string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1
	`, userID)
	if err != nil {
		return fmt.Errorf("update last_login_at: %w", err)
	}
	return nil
}

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
