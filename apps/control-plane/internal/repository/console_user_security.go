package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConsoleUserSecurity 是控制台账号的登录安全字段（迁移 880），与 users 表同行但单独读写，
// 避免改动 UserRepository 的公共扫描列。
type ConsoleUserSecurity struct {
	PasswordChangedAt *time.Time
	TOTPSecretEnc     string
	TOTPEnabled       bool
}

type ConsoleUserSecurityRepository struct {
	db *pgxpool.Pool
}

func NewConsoleUserSecurityRepository(db *pgxpool.Pool) *ConsoleUserSecurityRepository {
	return &ConsoleUserSecurityRepository{db: db}
}

func (r *ConsoleUserSecurityRepository) Get(ctx context.Context, userID string) (ConsoleUserSecurity, error) {
	var s ConsoleUserSecurity
	var secret *string
	err := r.db.QueryRow(ctx, `SELECT password_changed_at, totp_secret_enc, totp_enabled FROM users WHERE id = $1`, userID).
		Scan(&s.PasswordChangedAt, &secret, &s.TOTPEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("get console user security: %w", err)
	}
	if secret != nil {
		s.TOTPSecretEnc = *secret
	}
	return s, nil
}

// RecentHashes returns the most recent previous password hashes (newest first).
func (r *ConsoleUserSecurityRepository) RecentHashes(ctx context.Context, userID string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := r.db.Query(ctx, `SELECT password_hash FROM user_password_history WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("list password history: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Record stores a superseded password hash and trims history to keep entries.
func (r *ConsoleUserSecurityRepository) Record(ctx context.Context, userID, passwordHash string, keep int) error {
	if passwordHash == "" {
		return nil
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO user_password_history (user_id, password_hash) VALUES ($1, $2)`, userID, passwordHash); err != nil {
		return fmt.Errorf("insert password history: %w", err)
	}
	if keep < 1 {
		keep = 1
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_password_history WHERE user_id = $1 AND id NOT IN (
		SELECT id FROM user_password_history WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2)`, userID, keep); err != nil {
		return fmt.Errorf("trim password history: %w", err)
	}
	return tx.Commit(ctx)
}

func (r *ConsoleUserSecurityRepository) MarkPasswordChanged(ctx context.Context, userID string) error {
	_, err := r.db.Exec(ctx, `UPDATE users SET password_changed_at = NOW(), updated_at = NOW() WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("mark password changed: %w", err)
	}
	return nil
}

// SetTOTP stores the encrypted secret and enabled flag. Empty secret disables TOTP.
func (r *ConsoleUserSecurityRepository) SetTOTP(ctx context.Context, userID, secretEnc string, enabled bool) error {
	_, err := r.db.Exec(ctx, `UPDATE users SET totp_secret_enc = NULLIF($2, ''), totp_enabled = $3, updated_at = NOW() WHERE id = $1`, userID, secretEnc, enabled)
	if err != nil {
		return fmt.Errorf("set totp: %w", err)
	}
	return nil
}
