package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PreviewAction 与迁移 137 的 directory_sync_preview_entries.action CHECK 对齐。
const (
	PreviewActionCreate   = "create"
	PreviewActionUpdate   = "update"
	PreviewActionRestore  = "restore"
	PreviewActionDisable  = "disable"
	PreviewActionSkip     = "skip"
	PreviewActionConflict = "conflict"
)

// PreviewStatus 与迁移 137 的 directory_sync_previews.status CHECK 对齐。
const (
	PreviewStatusRunning   = "running"
	PreviewStatusSucceeded = "succeeded"
	PreviewStatusFailed    = "failed"
	PreviewStatusActivated = "activated"
	PreviewStatusExpired   = "expired"
)

// DirectorySyncPreview 对应 directory_sync_previews 表，预览头记录。
// 安全：本结构只保存脱敏计数字段，绝不保存 Bind Password / 完整敏感属性。
type DirectorySyncPreview struct {
	ID                string
	TenantID          string
	DirectorySourceID string
	SourceVersion     int
	ConfigDigest      string
	Status            string
	ScannedCount      int
	CreatedCount      int
	UpdatedCount      int
	DisabledCount     int
	ConflictCount     int
	UnassignedCount   int
	ErrorCode         string
	ActorUserID       string
	ExpiresAt         time.Time
	ActivatedAt       *time.Time
	ActivatedRunID    string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// DirectorySyncPreviewEntry 对应 directory_sync_preview_entries 表。
// 安全：只存脱敏字段 + content_digest（内容哈希），不保存目录密码或完整敏感属性。
type DirectorySyncPreviewEntry struct {
	ID                   string
	TenantID             string
	PreviewID            string
	ExternalSubject      string
	ContentDigest        string
	Action               string
	Username             string
	DisplayName          string
	DepartmentMatchType  string
	DepartmentMatchValue string
	ResolutionStatus     string
	ErrorCode            string
	CreatedAt            time.Time
}

// DirectorySyncRun 对应 directory_sync_runs 表（迁移 135 建立），承载同步历史。
type DirectorySyncRun struct {
	ID                string
	TenantID          string
	DirectorySourceID string
	SourceVersion     int
	RunKind           string
	Status            string
	StartedAt         time.Time
	FinishedAt        *time.Time
	ScannedCount      int
	CreatedCount      int
	UpdatedCount      int
	RestoredCount     int
	DisabledCount     int
	ConflictCount     int
	SkippedCount      int
	ErrorCode         string
	ActorUserID       string
}

var ErrPreviewNotFound = errors.New("directory sync preview not found")
var ErrPreviewAlreadyActivated = errors.New("directory sync preview already activated")
var ErrSyncRunNotFound = errors.New("directory sync run not found")

// directorySyncDBTX 被 pgxpool.Pool 与 pgx.Tx 同时实现，使级联写可注入事务。
type directorySyncDBTX interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// DirectorySyncPreviewRepository 读写预览/历史读模型。
type DirectorySyncPreviewRepository struct{ db *pgxpool.Pool }

func NewDirectorySyncPreviewRepository(db *pgxpool.Pool) *DirectorySyncPreviewRepository {
	return &DirectorySyncPreviewRepository{db: db}
}

// BeginTx 开启一个事务供级联写原子提交/回滚。调用方负责 Commit/Rollback。
func (r *DirectorySyncPreviewRepository) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}

// RunInTx 在单事务内执行 fn，返回 fn 的结果；fn 返错自动回滚，否则提交。
// 用于 I-1：激活路径的汇总写（MarkDirectoryUserDisabled + SnapshotDirectoryUserLinks +
// FinalizeSyncRun + MarkPreviewActivated）必须原子。
func (r *DirectorySyncPreviewRepository) RunInTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := r.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin directory sync transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit directory sync transaction: %w", err)
	}
	return nil
}

// txDBTX 把 pgx.Tx 适配为 directorySyncDBTX（pgx.Tx 本身就满足该接口）。
func txDBTX(tx pgx.Tx) directorySyncDBTX { return tx }

const previewColumns = `id, tenant_id, directory_source_id, source_version, config_digest,
    status, scanned_count, created_count, updated_count, disabled_count, conflict_count,
    unassigned_count, error_code, actor_user_id, expires_at, activated_at, activated_run_id,
    created_at, updated_at`

func scanPreview(row pgx.Row) (*DirectorySyncPreview, error) {
	var p DirectorySyncPreview
	var activatedAt sql.NullTime
	var activatedRunID sql.NullString
	if err := row.Scan(
		&p.ID, &p.TenantID, &p.DirectorySourceID, &p.SourceVersion, &p.ConfigDigest,
		&p.Status, &p.ScannedCount, &p.CreatedCount, &p.UpdatedCount, &p.DisabledCount,
		&p.ConflictCount, &p.UnassignedCount, &p.ErrorCode, &p.ActorUserID,
		&p.ExpiresAt, &activatedAt, &activatedRunID, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if activatedAt.Valid {
		value := activatedAt.Time
		p.ActivatedAt = &value
	}
	if activatedRunID.Valid {
		p.ActivatedRunID = activatedRunID.String
	}
	return &p, nil
}

const syncRunColumns = `id, tenant_id, directory_source_id, source_version, run_kind, status,
    started_at, finished_at, scanned_count, created_count, updated_count, restored_count,
    disabled_count, conflict_count, skipped_count, error_code, actor_user_id`

func scanSyncRun(row pgx.Row) (*DirectorySyncRun, error) {
	var r DirectorySyncRun
	var finishedAt sql.NullTime
	if err := row.Scan(
		&r.ID, &r.TenantID, &r.DirectorySourceID, &r.SourceVersion, &r.RunKind, &r.Status,
		&r.StartedAt, &finishedAt, &r.ScannedCount, &r.CreatedCount, &r.UpdatedCount,
		&r.RestoredCount, &r.DisabledCount, &r.ConflictCount, &r.SkippedCount,
		&r.ErrorCode, &r.ActorUserID,
	); err != nil {
		return nil, err
	}
	if finishedAt.Valid {
		value := finishedAt.Time
		r.FinishedAt = &value
	}
	return &r, nil
}

// CreatePreview 在事务内建预览头记录（status=running），返回带 ID 的对象。
func (r *DirectorySyncPreviewRepository) CreatePreview(ctx context.Context, preview *DirectorySyncPreview) error {
	if preview == nil || preview.TenantID == "" || preview.DirectorySourceID == "" {
		return errors.New("directory sync preview tenant/source required")
	}
	if preview.ID == "" {
		preview.ID = "dsp_" + uuid.NewString()[:12]
	}
	if preview.ExpiresAt.IsZero() {
		preview.ExpiresAt = time.Now().Add(24 * time.Hour)
	}
	if err := r.db.QueryRow(ctx, `
		INSERT INTO directory_sync_previews (
			id, tenant_id, directory_source_id, source_version, config_digest,
			status, actor_user_id, expires_at
		) VALUES ($1,$2,$3,$4,$5,'running',$6,$7)
		RETURNING created_at, updated_at`,
		preview.ID, preview.TenantID, preview.DirectorySourceID, preview.SourceVersion,
		preview.ConfigDigest, preview.ActorUserID, preview.ExpiresAt,
	).Scan(&preview.CreatedAt, &preview.UpdatedAt); err != nil {
		return fmt.Errorf("create directory sync preview: %w", err)
	}
	preview.Status = PreviewStatusRunning
	return nil
}

// AppendPreviewEntry 在事务内追加一条脱敏预览条目（含 content_digest，不含密码）。
func (r *DirectorySyncPreviewRepository) AppendPreviewEntry(ctx context.Context, entry *DirectorySyncPreviewEntry) error {
	if entry == nil || entry.TenantID == "" || entry.PreviewID == "" || entry.ExternalSubject == "" {
		return errors.New("directory sync preview entry required fields missing")
	}
	if entry.ID == "" {
		entry.ID = "dspe_" + uuid.NewString()[:12]
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO directory_sync_preview_entries (
			id, tenant_id, preview_id, external_subject, content_digest, action,
			username, display_name, department_match_type, department_match_value,
			resolution_status, error_code
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (preview_id, external_subject) DO UPDATE SET
			content_digest=EXCLUDED.content_digest, action=EXCLUDED.action,
			username=EXCLUDED.username, display_name=EXCLUDED.display_name,
			department_match_type=EXCLUDED.department_match_type,
			department_match_value=EXCLUDED.department_match_value,
			resolution_status=EXCLUDED.resolution_status,
			error_code=EXCLUDED.error_code`,
		entry.ID, entry.TenantID, entry.PreviewID, entry.ExternalSubject, entry.ContentDigest,
		entry.Action, entry.Username, entry.DisplayName, entry.DepartmentMatchType,
		entry.DepartmentMatchValue, entry.ResolutionStatus, entry.ErrorCode,
	)
	if err != nil {
		return fmt.Errorf("append directory sync preview entry: %w", err)
	}
	return nil
}

// FinalizePreview 把预览头从 running 推进到 succeeded/failed 并写回计数。
func (r *DirectorySyncPreviewRepository) FinalizePreview(ctx context.Context, tenantID, previewID, status string, counts PreviewCounts, errorCode string) error {
	ct, err := r.db.Exec(ctx, `
		UPDATE directory_sync_previews SET
			status=$3, scanned_count=$4, created_count=$5, updated_count=$6,
			disabled_count=$7, conflict_count=$8, unassigned_count=$9,
			error_code=$10, updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND status='running'`,
		tenantID, previewID, status, counts.Scanned, counts.Created, counts.Updated,
		counts.Disabled, counts.Conflict, counts.Unassigned, errorCode,
	)
	if err != nil {
		return fmt.Errorf("finalize directory sync preview: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrPreviewNotFound
	}
	return nil
}

// PreviewCounts 汇总预览/激活计数，用于 FinalizePreview / SyncRun 写回。
type PreviewCounts struct {
	Scanned    int
	Created    int
	Updated    int
	Disabled   int
	Conflict   int
	Unassigned int
	Restored   int
	Skipped    int
}

// GetPreview 取预览头（租户隔离）。
func (r *DirectorySyncPreviewRepository) GetPreview(ctx context.Context, tenantID, previewID string) (*DirectorySyncPreview, error) {
	preview, err := scanPreview(r.db.QueryRow(ctx, `SELECT `+previewColumns+` FROM directory_sync_previews WHERE tenant_id=$1 AND id=$2`, tenantID, previewID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return preview, err
}

// ListPreviewEntries 列出预览下的全部脱敏条目（按 external_subject 排序保证稳定）。
func (r *DirectorySyncPreviewRepository) ListPreviewEntries(ctx context.Context, tenantID, previewID string) ([]DirectorySyncPreviewEntry, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, preview_id, external_subject, content_digest, action,
			username, display_name, department_match_type, department_match_value,
			resolution_status, error_code, created_at
		FROM directory_sync_preview_entries
		WHERE tenant_id=$1 AND preview_id=$2
		ORDER BY external_subject`, tenantID, previewID)
	if err != nil {
		return nil, fmt.Errorf("list directory sync preview entries: %w", err)
	}
	defer rows.Close()
	var out []DirectorySyncPreviewEntry
	for rows.Next() {
		var e DirectorySyncPreviewEntry
		if err := rows.Scan(&e.ID, &e.TenantID, &e.PreviewID, &e.ExternalSubject, &e.ContentDigest,
			&e.Action, &e.Username, &e.DisplayName, &e.DepartmentMatchType, &e.DepartmentMatchValue,
			&e.ResolutionStatus, &e.ErrorCode, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// MarkPreviewActivated 把预览推进到 activated 并绑定 run_id；若已激活则返回当前 run（幂等）。
func (r *DirectorySyncPreviewRepository) MarkPreviewActivated(ctx context.Context, tenantID, previewID, runID string) (string, error) {
	return markPreviewActivatedWith(ctx, r.db, tenantID, previewID, runID)
}

// MarkPreviewActivatedTx 同 MarkPreviewActivated，但纳入调用方事务（I-1 级联写原子性）。
func (r *DirectorySyncPreviewRepository) MarkPreviewActivatedTx(ctx context.Context, tx pgx.Tx, tenantID, previewID, runID string) (string, error) {
	return markPreviewActivatedWith(ctx, tx, tenantID, previewID, runID)
}

func markPreviewActivatedWith(ctx context.Context, db directorySyncDBTX, tenantID, previewID, runID string) (string, error) {
	var existingRun string
	err := db.QueryRow(ctx, `
		UPDATE directory_sync_previews SET
			status=CASE WHEN status='activated' THEN status ELSE 'activated' END,
			activated_at=COALESCE(activated_at, now()),
			activated_run_id=COALESCE(activated_run_id, $3),
			updated_at=now()
		WHERE tenant_id=$1 AND id=$2
		RETURNING activated_run_id`, tenantID, previewID, runID).Scan(&existingRun)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrPreviewNotFound
		}
		return "", fmt.Errorf("mark directory sync preview activated: %w", err)
	}
	return existingRun, nil
}

// ClaimPreviewForActivation 用状态机 CAS 抢占预览激活权（I-2 并发安全）。
//
// 语义：原子地把 status='succeeded' 且 activated_run_id IS NULL 的预览的
// activated_run_id 设为 runID。只有第一个并发请求能拿到非空 RETURNING
// （winningRunID == runID 表示本请求抢到；空表示已被别的请求抢，调用方应
// 走幂等分支）。注意：此时 status 仍是 'succeeded'，真正的 status='activated'
// 推进在汇总写事务提交时由 MarkPreviewActivatedTx 完成。
//
// 返回 (winningRunID, claimed, error)：claimed=true 表示本请求赢得抢占。
func (r *DirectorySyncPreviewRepository) ClaimPreviewForActivation(ctx context.Context, tx pgx.Tx, tenantID, previewID, runID string) (string, bool, error) {
	var winningRun sql.NullString
	err := tx.QueryRow(ctx, `
		UPDATE directory_sync_previews
		SET activated_run_id = $3, updated_at = now()
		WHERE tenant_id=$1 AND id=$2 AND status='succeeded' AND activated_run_id IS NULL
		RETURNING activated_run_id`, tenantID, previewID, runID).Scan(&winningRun)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// WHERE 不满足：已被并发抢或状态非 succeeded。读当前 activated_run_id 供幂等。
			existing, lookupErr := r.GetPreview(ctx, tenantID, previewID)
			if lookupErr != nil {
				return "", false, fmt.Errorf("lookup activated preview after lost claim: %w", lookupErr)
			}
			if existing == nil {
				return "", false, ErrPreviewNotFound
			}
			return existing.ActivatedRunID, false, nil
		}
		return "", false, fmt.Errorf("claim directory sync preview: %w", err)
	}
	if !winningRun.Valid {
		return "", false, nil
	}
	return winningRun.String, true, nil
}

// CreateSyncRun 在事务内建一条同步运行记录（status=running），返回带 ID 的对象。
func (r *DirectorySyncPreviewRepository) CreateSyncRun(ctx context.Context, run *DirectorySyncRun) error {
	return createSyncRunWith(ctx, r.db, run)
}

// CreateSyncRunTx 同 CreateSyncRun，但纳入调用方事务（I-1 级联写原子性）。
func (r *DirectorySyncPreviewRepository) CreateSyncRunTx(ctx context.Context, tx pgx.Tx, run *DirectorySyncRun) error {
	return createSyncRunWith(ctx, tx, run)
}

func createSyncRunWith(ctx context.Context, db directorySyncDBTX, run *DirectorySyncRun) error {
	if run == nil || run.TenantID == "" || run.DirectorySourceID == "" {
		return errors.New("directory sync run tenant/source required")
	}
	if run.ID == "" {
		run.ID = "dsr_" + uuid.NewString()[:12]
	}
	if err := db.QueryRow(ctx, `
		INSERT INTO directory_sync_runs (
			id, tenant_id, directory_source_id, source_version, run_kind, status, actor_user_id
		) VALUES ($1,$2,$3,$4,$5,'running',$6)
		RETURNING started_at`,
		run.ID, run.TenantID, run.DirectorySourceID, run.SourceVersion, run.RunKind, run.ActorUserID,
	).Scan(&run.StartedAt); err != nil {
		return fmt.Errorf("create directory sync run: %w", err)
	}
	run.Status = "running"
	return nil
}

// FinalizeSyncRun 把运行从 running 推进到 succeeded/failed 并写回计数。
func (r *DirectorySyncPreviewRepository) FinalizeSyncRun(ctx context.Context, tenantID, runID, status string, counts PreviewCounts, errorCode string) error {
	return finalizeSyncRunWith(ctx, r.db, tenantID, runID, status, counts, errorCode)
}

// FinalizeSyncRunTx 同 FinalizeSyncRun，但纳入调用方事务（I-1 级联写原子性）。
func (r *DirectorySyncPreviewRepository) FinalizeSyncRunTx(ctx context.Context, tx pgx.Tx, tenantID, runID, status string, counts PreviewCounts, errorCode string) error {
	return finalizeSyncRunWith(ctx, tx, tenantID, runID, status, counts, errorCode)
}

func finalizeSyncRunWith(ctx context.Context, db directorySyncDBTX, tenantID, runID, status string, counts PreviewCounts, errorCode string) error {
	ct, err := db.Exec(ctx, `
		UPDATE directory_sync_runs SET
			status=$3, finished_at=now(),
			scanned_count=$4, created_count=$5, updated_count=$6, restored_count=$7,
			disabled_count=$8, conflict_count=$9, skipped_count=$10,
			error_code=$11
		WHERE tenant_id=$1 AND id=$2 AND status='running'`,
		tenantID, runID, status, counts.Scanned, counts.Created, counts.Updated,
		counts.Restored, counts.Disabled, counts.Conflict, counts.Skipped, errorCode,
	)
	if err != nil {
		return fmt.Errorf("finalize directory sync run: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrSyncRunNotFound
	}
	return nil
}

// GetSyncRun 取运行头（租户隔离）。
func (r *DirectorySyncPreviewRepository) GetSyncRun(ctx context.Context, tenantID, runID string) (*DirectorySyncRun, error) {
	run, err := scanSyncRun(r.db.QueryRow(ctx, `SELECT `+syncRunColumns+` FROM directory_sync_runs WHERE tenant_id=$1 AND id=$2`, tenantID, runID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return run, err
}

// ListSyncRuns 列出指定租户的同步运行（最近优先，默认 50 条）。
func (r *DirectorySyncPreviewRepository) ListSyncRuns(ctx context.Context, tenantID string, limit int) ([]DirectorySyncRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.db.Query(ctx, `SELECT `+syncRunColumns+` FROM directory_sync_runs WHERE tenant_id=$1 ORDER BY started_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list directory sync runs: %w", err)
	}
	defer rows.Close()
	var out []DirectorySyncRun
	for rows.Next() {
		run, err := scanSyncRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *run)
	}
	return out, rows.Err()
}

// ListBoundDirectoryUserIDs 列出当前 source 已绑定的 external_object_id（用于增量同步对比）。
func (r *DirectorySyncPreviewRepository) ListBoundDirectoryUserIDs(ctx context.Context, tenantID, sourceID string) (map[string]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT external_object_id, user_id FROM directory_user_links
		WHERE tenant_id=$1 AND directory_source_id=$2`, tenantID, sourceID)
	if err != nil {
		return nil, fmt.Errorf("list bound directory users: %w", err)
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var extID, userID string
		if err := rows.Scan(&extID, &userID); err != nil {
			return nil, err
		}
		out[extID] = userID
	}
	return out, rows.Err()
}

// MarkDirectoryUserDisabled 把已消失的目录账号标记为禁用（status=disabled），
// 但不删除 user 行或审计历史。返回受影响行数。
func (r *DirectorySyncPreviewRepository) MarkDirectoryUserDisabled(ctx context.Context, tenantID string, userIDs []string) (int, error) {
	return markDirectoryUserDisabledWith(ctx, r.db, tenantID, userIDs)
}

// MarkDirectoryUserDisabledTx 同 MarkDirectoryUserDisabled，但纳入调用方事务（I-1）。
func (r *DirectorySyncPreviewRepository) MarkDirectoryUserDisabledTx(ctx context.Context, tx pgx.Tx, tenantID string, userIDs []string) (int, error) {
	return markDirectoryUserDisabledWith(ctx, tx, tenantID, userIDs)
}

func markDirectoryUserDisabledWith(ctx context.Context, db directorySyncDBTX, tenantID string, userIDs []string) (int, error) {
	if len(userIDs) == 0 {
		return 0, nil
	}
	ct, err := db.Exec(ctx, `
		UPDATE users SET status='disabled', updated_at=now()
		WHERE tenant_id=$1 AND id=ANY($2) AND status<>'disabled'`,
		tenantID, userIDs)
	if err != nil {
		return 0, fmt.Errorf("disable directory users: %w", err)
	}
	return int(ct.RowsAffected()), nil
}

// MarkDirectoryUserRestored reactivates only previously-bound directory users
// that are present again in the current full-sync set. New directory users are
// intentionally excluded by the caller and retain their provisioning status.
func (r *DirectorySyncPreviewRepository) MarkDirectoryUserRestored(ctx context.Context, tenantID string, userIDs []string) (int, error) {
	return markDirectoryUserRestoredWith(ctx, r.db, tenantID, userIDs)
}

// MarkDirectoryUserRestoredTx is the transactional form used by full activation.
func (r *DirectorySyncPreviewRepository) MarkDirectoryUserRestoredTx(ctx context.Context, tx pgx.Tx, tenantID string, userIDs []string) (int, error) {
	return markDirectoryUserRestoredWith(ctx, tx, tenantID, userIDs)
}

func markDirectoryUserRestoredWith(ctx context.Context, db directorySyncDBTX, tenantID string, userIDs []string) (int, error) {
	if len(userIDs) == 0 {
		return 0, nil
	}
	ct, err := db.Exec(ctx, `
		UPDATE users SET status='active', updated_at=now()
		WHERE tenant_id=$1 AND id=ANY($2) AND status='disabled'
 AND NOT EXISTS(SELECT 1 FROM user_account_merges m WHERE m.tenant_id=$1 AND m.source_user_id=users.id)`,
		tenantID, userIDs)
	if err != nil {
		return 0, fmt.Errorf("restore directory users: %w", err)
	}
	return int(ct.RowsAffected()), nil
}

// SnapshotDirectoryUserLinks 把当前 source 已绑定 links 的 last_seen_run_id 批量推进到最新 run。
// 仅用于激活成功后刷新"最后一次见到"的时间戳，不创建新 link（新 link 由激活路径按需创建）。
//
// 忽略 RowsAffected（M-5）：seen 集合里的 external_id 在 BindDirectoryUser 失败时
// 已经 return error 中断激活；能走到这里的都已 bind 成功，UPDATE 必然命中。
// 即使个别 id 因并发被 ON CONFLICT 折叠，仅影响 last_seen 时间戳，无数据正确性后果。
func (r *DirectorySyncPreviewRepository) SnapshotDirectoryUserLinks(ctx context.Context, tenantID, sourceID, runID string, seenExternalIDs []string) error {
	return snapshotDirectoryUserLinksWith(ctx, r.db, tenantID, sourceID, runID, seenExternalIDs)
}

// SnapshotDirectoryUserLinksTx 同 SnapshotDirectoryUserLinks，但纳入调用方事务（I-1）。
func (r *DirectorySyncPreviewRepository) SnapshotDirectoryUserLinksTx(ctx context.Context, tx pgx.Tx, tenantID, sourceID, runID string, seenExternalIDs []string) error {
	return snapshotDirectoryUserLinksWith(ctx, tx, tenantID, sourceID, runID, seenExternalIDs)
}

func snapshotDirectoryUserLinksWith(ctx context.Context, db directorySyncDBTX, tenantID, sourceID, runID string, seenExternalIDs []string) error {
	if len(seenExternalIDs) == 0 {
		return nil
	}
	ct, err := db.Exec(ctx, `
		UPDATE directory_user_links SET last_seen_run_id=$4, last_seen_at=now(), updated_at=now()
		WHERE tenant_id=$1 AND directory_source_id=$2 AND external_object_id=ANY($3)`,
		tenantID, sourceID, seenExternalIDs, runID)
	if err != nil {
		return fmt.Errorf("snapshot directory user links: %w", err)
	}
	_ = ct
	return nil
}

// LatestPreview 取租户下最近一次预览（按 created_at 倒序），无则返回 nil。
// 用于身份源总览展示 last_preview_at；只读脱敏字段。
func (r *DirectorySyncPreviewRepository) LatestPreview(ctx context.Context, tenantID string) (*DirectorySyncPreview, error) {
	preview, err := scanPreview(r.db.QueryRow(ctx, `SELECT `+previewColumns+` FROM directory_sync_previews WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 1`, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load latest directory preview: %w", err)
	}
	return preview, nil
}

// LatestSyncRun 取租户下最近一次同步运行（按 started_at 倒序），无则返回 nil。
// 用于身份源总览展示最近一次同步时间与摘要；只读计数字段。
func (r *DirectorySyncPreviewRepository) LatestSyncRun(ctx context.Context, tenantID string) (*DirectorySyncRun, error) {
	run, err := scanSyncRun(r.db.QueryRow(ctx, `SELECT `+syncRunColumns+` FROM directory_sync_runs WHERE tenant_id=$1 ORDER BY started_at DESC LIMIT 1`, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load latest directory sync run: %w", err)
	}
	return run, nil
}
