package localidentity

// 本地身份（Keycloak）孤儿用户清理的持久化重试队列。
//
// 删除用户的顺序是：解析 subject -> Keycloak 禁用 -> 删 users 行 -> 吊销会话 -> 删除 Keycloak 用户。
// 最后一步失败时账号已禁用、无法登录，但 Keycloak 里仍留着孤儿用户，必须持续重试直到删掉。
// users 行此时已经不存在，所以不能再靠 users.status 记账；这里是独立于 users 的队列（迁移 983）。
//
// 安全：队列里的 subject 用 secrets 包加密（与 provider 密钥同一套密钥和算法），没有明文；
// 指纹 sha256(tenant|subject) 用于审计关联。错误只记稳定的错误码，不记 Keycloak 返回的原文。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

const (
	CleanupStatusPending   = "pending"
	CleanupStatusDone      = "done"
	CleanupStatusExhausted = "exhausted"

	// DefaultCleanupMaxAttempts 与退避配合：基础 30 秒，每次翻倍，封顶 1 小时。
	// 12 次约覆盖 30s,1m,2m,4m,8m,16m,32m,1h,1h,1h,1h,1h，总计约 6 小时。
	DefaultCleanupMaxAttempts = 12
	cleanupBackoffBase        = 30 * time.Second
	cleanupBackoffCap         = time.Hour
	// CleanupExhaustedRetryInterval：耗尽后不放弃，按此间隔低频续试，保证清理最终有终点。
	CleanupExhaustedRetryInterval = 24 * time.Hour
	// cleanupEnqueueGrace：删除请求先预登记再同步删除，给同步路径留出时间，避免 worker 并发处理同一行。
	cleanupEnqueueGrace = 2 * time.Minute
)

// CleanupItem 是一条待清理的 Keycloak 用户（已解密）。Subject 只在内存中短暂存在。
type CleanupItem struct {
	ID          string
	TenantID    string
	UserID      string
	Subject     string
	Fingerprint string
	Attempts    int
	MaxAttempts int
}

// CleanupQueue 是队列的存储抽象，Postgres 实现见 PostgresCleanupQueue；测试可以用桩。
type CleanupQueue interface {
	// Enqueue 登记一个待清理的 subject；同一租户同一 subject 重复入队只刷新，不产生多条。
	Enqueue(ctx context.Context, tenantID, userID, actorID, subject string, now time.Time) error
	// ClaimDue 取出到期的待处理行（行级锁、SKIP LOCKED，多副本不会重复处理）。
	ClaimDue(ctx context.Context, now time.Time, limit int) ([]CleanupItem, error)
	// MarkDone 标记清理完成。
	MarkDone(ctx context.Context, id string, now time.Time) error
	// MarkRetry 记录一次失败并安排下次重试；返回 exhausted=true 表示已达最大次数（之后转入每日低频续试）。
	MarkRetry(ctx context.Context, id, errorCode string, now time.Time) (exhausted bool, err error)
	// MarkDoneBySubject 在请求内同步删除成功时，把预登记的队列行直接标记完成。
	MarkDoneBySubject(ctx context.Context, tenantID, subject string, now time.Time) error
}

// SubjectFingerprint 是 sha256(tenant|subject) 的十六进制，用于审计与对账关联，不可反推出 subject。
func SubjectFingerprint(tenantID, subject string) string {
	sum := sha256.Sum256([]byte(tenantID + "|" + subject))
	return hex.EncodeToString(sum[:])
}

// CleanupBackoff 返回第 attempts 次失败后的等待时间（指数退避，封顶 1 小时）。attempts 从 1 起算。
func CleanupBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := cleanupBackoffBase
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= cleanupBackoffCap {
			return cleanupBackoffCap
		}
	}
	return d
}

type PostgresCleanupQueue struct{ db *pgxpool.Pool }

func NewPostgresCleanupQueue(db *pgxpool.Pool) *PostgresCleanupQueue {
	return &PostgresCleanupQueue{db: db}
}

func (q *PostgresCleanupQueue) Enqueue(ctx context.Context, tenantID, userID, actorID, subject string, now time.Time) error {
	subject = strings.TrimSpace(subject)
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(userID) == "" || subject == "" {
		return ErrInvalidInput
	}
	ciphertext, _, err := secrets.EncryptProviderSecret(subject)
	if err != nil {
		return fmt.Errorf("encrypt cleanup subject: %w", err)
	}
	_, err = q.db.Exec(ctx, `
		INSERT INTO local_identity_cleanup_queue
			(id, tenant_id, user_id, subject_ciphertext, subject_fingerprint, status, attempts, max_attempts, next_attempt_at, actor_id, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,'pending',0,$6,$7,$8,$7,$7)
		ON CONFLICT (tenant_id, subject_fingerprint) DO UPDATE
		SET status='pending', attempts=0, next_attempt_at=EXCLUDED.next_attempt_at,
		    subject_ciphertext=EXCLUDED.subject_ciphertext, updated_at=EXCLUDED.updated_at, completed_at=NULL
	`, "lic-"+uuid.NewString(), tenantID, userID, ciphertext, SubjectFingerprint(tenantID, subject),
		DefaultCleanupMaxAttempts, now.Add(cleanupEnqueueGrace), actorID)
	if err != nil {
		return fmt.Errorf("enqueue local identity cleanup: %w", err)
	}
	return nil
}

func (q *PostgresCleanupQueue) ClaimDue(ctx context.Context, now time.Time, limit int) ([]CleanupItem, error) {
	if limit <= 0 {
		limit = 20
	}
	tx, err := q.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin cleanup claim: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, user_id, subject_ciphertext, subject_fingerprint, attempts, max_attempts
		FROM local_identity_cleanup_queue
		WHERE status IN ('pending','exhausted') AND next_attempt_at <= $1
		ORDER BY next_attempt_at
		LIMIT $2
		FOR UPDATE SKIP LOCKED
	`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("claim cleanup rows: %w", err)
	}
	type raw struct {
		item       CleanupItem
		ciphertext string
	}
	var claimed []raw
	for rows.Next() {
		var r raw
		if err := rows.Scan(&r.item.ID, &r.item.TenantID, &r.item.UserID, &r.ciphertext, &r.item.Fingerprint, &r.item.Attempts, &r.item.MaxAttempts); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan cleanup row: %w", err)
		}
		claimed = append(claimed, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cleanup rows: %w", err)
	}
	// 先把这批行的下次尝试时间往后推一个短租约，防止别的副本在本批处理期间重复领取；
	// 处理结果（MarkDone / MarkRetry）会覆盖它。
	for _, r := range claimed {
		if _, err := tx.Exec(ctx, `UPDATE local_identity_cleanup_queue SET next_attempt_at=$2, updated_at=$3 WHERE id=$1`,
			r.item.ID, now.Add(2*time.Minute), now); err != nil {
			return nil, fmt.Errorf("lease cleanup row: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit cleanup claim: %w", err)
	}
	items := make([]CleanupItem, 0, len(claimed))
	for _, r := range claimed {
		subject, err := secrets.DecryptProviderSecret(r.ciphertext)
		if err != nil || strings.TrimSpace(subject) == "" {
			// 无法解密（密钥轮换/损坏）：不能重试出结果，直接按失败记一次，最终耗尽并告警。
			_, _ = q.MarkRetry(ctx, r.item.ID, "decrypt_failed", now)
			continue
		}
		r.item.Subject = subject
		items = append(items, r.item)
	}
	return items, nil
}

func (q *PostgresCleanupQueue) MarkDone(ctx context.Context, id string, now time.Time) error {
	_, err := q.db.Exec(ctx, `
		UPDATE local_identity_cleanup_queue
		SET status='done', completed_at=$2, updated_at=$2, last_error_code=''
		WHERE id=$1
	`, id, now)
	if err != nil {
		return fmt.Errorf("mark cleanup done: %w", err)
	}
	return nil
}

func (q *PostgresCleanupQueue) MarkDoneBySubject(ctx context.Context, tenantID, subject string, now time.Time) error {
	_, err := q.db.Exec(ctx, `
		UPDATE local_identity_cleanup_queue
		SET status='done', completed_at=$3, updated_at=$3, last_error_code=''
		WHERE tenant_id=$1 AND subject_fingerprint=$2 AND status<>'done'
	`, tenantID, SubjectFingerprint(tenantID, strings.TrimSpace(subject)), now)
	if err != nil {
		return fmt.Errorf("mark cleanup done by subject: %w", err)
	}
	return nil
}

func (q *PostgresCleanupQueue) MarkRetry(ctx context.Context, id, errorCode string, now time.Time) (bool, error) {
	var attempts, maxAttempts int
	err := q.db.QueryRow(ctx, `
		UPDATE local_identity_cleanup_queue
		SET attempts=attempts+1, last_error_code=$2, updated_at=$3
		WHERE id=$1
		RETURNING attempts, max_attempts
	`, id, errorCode, now).Scan(&attempts, &maxAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("record cleanup failure: %w", err)
	}
	if attempts >= maxAttempts {
		// 只在首次达到上限时报告 exhausted（触发一次告警）；之后保持 exhausted 并按天续试。
		var prev string
		_ = q.db.QueryRow(ctx, `SELECT status FROM local_identity_cleanup_queue WHERE id=$1`, id).Scan(&prev)
		_, err = q.db.Exec(ctx, `UPDATE local_identity_cleanup_queue SET status='exhausted', next_attempt_at=$3, updated_at=$2 WHERE id=$1`,
			id, now, now.Add(CleanupExhaustedRetryInterval))
		if err != nil {
			return true, fmt.Errorf("mark cleanup exhausted: %w", err)
		}
		return prev != CleanupStatusExhausted, nil
	}
	_, err = q.db.Exec(ctx, `UPDATE local_identity_cleanup_queue SET next_attempt_at=$2 WHERE id=$1`, id, now.Add(CleanupBackoff(attempts)))
	if err != nil {
		return false, fmt.Errorf("schedule cleanup retry: %w", err)
	}
	return false, nil
}

// CleanupWorker 周期性地从队列取出到期的行，调用 Keycloak 删除用户。
type CleanupWorker struct {
	Queue  CleanupQueue
	Client Client
	// OnExhausted 在一条清理达到最大重试次数时调用（告警 / 写审计）。传入的是指纹，不是 subject。
	OnExhausted func(ctx context.Context, item CleanupItem)
	// OnDone 在清理成功时调用（写审计）。
	OnDone func(ctx context.Context, item CleanupItem)
	Now    func() time.Time
	Batch  int
}

func (w *CleanupWorker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now().UTC()
}

// RunOnce 处理一轮到期的行，返回成功清理的条数。
func (w *CleanupWorker) RunOnce(ctx context.Context) (int, error) {
	if w == nil || w.Queue == nil || w.Client == nil {
		return 0, nil
	}
	now := w.now()
	items, err := w.Queue.ClaimDue(ctx, now, w.Batch)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, item := range items {
		// 重试时再禁用一次：上次可能是禁用成功、删除失败，也可能禁用被人为重新启用，保证账号不可登录。
		_ = w.Client.SetEnabled(ctx, item.Subject, false)
		if err := w.Client.DeleteUser(ctx, item.Subject); err != nil {
			exhausted, markErr := w.Queue.MarkRetry(ctx, item.ID, cleanupErrorCode(err), w.now())
			if markErr == nil && exhausted && w.OnExhausted != nil {
				w.OnExhausted(ctx, item)
			}
			continue
		}
		if err := w.Queue.MarkDone(ctx, item.ID, w.now()); err != nil {
			continue
		}
		done++
		if w.OnDone != nil {
			w.OnDone(ctx, item)
		}
	}
	return done, nil
}

// Run 以固定间隔循环调用 RunOnce，直到 ctx 取消。
func (w *CleanupWorker) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		_, _ = w.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// cleanupErrorCode 把客户端错误映射成稳定的错误码，绝不带 Keycloak 返回的原文。
func cleanupErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrRejected):
		return "rejected"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout"
	default:
		return "error"
	}
}

// RecordCleanupExhausted 在清理达到最大重试次数时写一条操作审计（只含用户 ID 与 subject 指纹，不含 subject）。
func (q *PostgresCleanupQueue) RecordCleanupExhausted(ctx context.Context, item CleanupItem) error {
	detail := fmt.Sprintf(`{"user_id":%q,"subject_fingerprint":%q,"attempts":%d,"reason":"cleanup_attempts_exhausted"}`,
		item.UserID, item.Fingerprint, item.Attempts+1)
	_, err := q.db.Exec(ctx, `
		INSERT INTO audit_operations (id, tenant_id, user_id, action_type, action_detail, target_type, target_id, ip_address)
		VALUES ($1, $2, NULL, 'local_identity.cleanup_exhausted', $3::jsonb, 'user', $4, '')
	`, "lic-audit-"+uuid.NewString(), item.TenantID, detail, item.UserID)
	if err != nil {
		return fmt.Errorf("record cleanup exhausted audit: %w", err)
	}
	return nil
}
