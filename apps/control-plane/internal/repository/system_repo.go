package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrHeaderContractCollision = errors.New("header conflict audit id collision")

type SystemSetting struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AuditOperation struct {
	ID           string
	UserID       string
	ActionType   string
	ActionDetail map[string]interface{}
	TargetType   string
	TargetID     string
	IPAddress    string
	CreatedAt    time.Time
}

type SystemRepository struct {
	db *pgxpool.Pool
}

func NewSystemRepository(db *pgxpool.Pool) *SystemRepository {
	return &SystemRepository{db: db}
}

func (r *SystemRepository) Get(ctx context.Context, key string) (*SystemSetting, error) {
	query := `SELECT key, value, updated_at FROM system_settings WHERE key = $1`
	row := r.db.QueryRow(ctx, query, key)
	var s SystemSetting
	err := row.Scan(&s.Key, &s.Value, &s.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get setting: %w", err)
	}
	return &s, nil
}

func (r *SystemRepository) GetAll(ctx context.Context) ([]*SystemSetting, error) {
	query := `SELECT key, value, updated_at FROM system_settings ORDER BY key`
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list settings: %w", err)
	}
	defer rows.Close()
	var settings []*SystemSetting
	for rows.Next() {
		var s SystemSetting
		if err := rows.Scan(&s.Key, &s.Value, &s.UpdatedAt); err != nil {
			return nil, err
		}
		settings = append(settings, &s)
	}
	return settings, nil
}

func (r *SystemRepository) Set(ctx context.Context, key, value string) error {
	query := `INSERT INTO system_settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`
	_, err := r.db.Exec(ctx, query, key, value)
	if err != nil {
		return fmt.Errorf("failed to set setting: %w", err)
	}
	return nil
}

// SetMultiple uses one statement so a mode change and its compatibility value
// and attribution are committed together or not at all.
func (r *SystemRepository) SetMultiple(ctx context.Context, settings map[string]string) error {
	if len(settings) == 0 {
		return nil
	}
	payload, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, `INSERT INTO system_settings (key, value, updated_at)
 SELECT key, value, NOW() FROM jsonb_each_text($1::jsonb)
 ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at`, payload)
	if err != nil {
		return fmt.Errorf("failed to set settings: %w", err)
	}
	return nil
}

// CreateAuditOperation inserts an audit log entry
func (r *SystemRepository) CreateAuditOperation(ctx context.Context, op *AuditOperation) error {
	// user_id 是 users(id) 外键：服务身份（如 portal-integration）没有对应 user 行，
	// 空串经 NULLIF 落 NULL 而不是撞外键约束。
	query := `INSERT INTO audit_operations (id, user_id, action_type, action_detail, target_type, target_id, ip_address) VALUES ($1, NULLIF($2,''), $3, $4::jsonb, $5, $6, $7)`
	_, err := r.db.Exec(ctx, query, op.ID, op.UserID, op.ActionType, op.ActionDetail, op.TargetType, op.TargetID, op.IPAddress)
	if err != nil {
		return fmt.Errorf("failed to create audit operation: %w", err)
	}
	return nil
}

// ListAuditOperations returns paginated audit operations
func (r *SystemRepository) ListAuditOperations(ctx context.Context, limit, offset int, userID string) ([]*AuditOperation, int, error) {
	countQuery := `SELECT COUNT(*) FROM audit_operations`
	countArgs := []interface{}{}
	if userID != "" {
		countQuery = `SELECT COUNT(*) FROM audit_operations WHERE user_id = $1`
		countArgs = append(countArgs, userID)
	}
	var total int
	if err := r.db.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count audit operations: %w", err)
	}

	query := `SELECT id, COALESCE(user_id, ''), action_type, COALESCE(action_detail::text, '{}'), COALESCE(target_type, ''), COALESCE(target_id, ''), COALESCE(ip_address, ''), created_at FROM audit_operations ORDER BY created_at DESC LIMIT $1 OFFSET $2`
	queryArgs := []interface{}{limit, offset}
	if userID != "" {
		query = `SELECT id, COALESCE(user_id, ''), action_type, COALESCE(action_detail::text, '{}'), COALESCE(target_type, ''), COALESCE(target_id, ''), COALESCE(ip_address, ''), created_at FROM audit_operations WHERE user_id = $3 ORDER BY created_at DESC LIMIT $1 OFFSET $2`
		queryArgs = append(queryArgs, userID)
	}
	rows, err := r.db.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list audit operations: %w", err)
	}
	defer rows.Close()

	var ops []*AuditOperation
	for rows.Next() {
		var op AuditOperation
		var detailStr, targetType, targetID, ipAddr string
		if err := rows.Scan(&op.ID, &op.UserID, &op.ActionType, &detailStr, &targetType, &targetID, &ipAddr, &op.CreatedAt); err != nil {
			return nil, 0, err
		}
		op.TargetType = targetType
		op.TargetID = targetID
		op.IPAddress = ipAddr
		op.ActionDetail = map[string]interface{}{}
		if detailStr != "" {
			_ = json.Unmarshal([]byte(detailStr), &op.ActionDetail)
		}
		ops = append(ops, &op)
	}
	return ops, total, nil
}

// GetBool returns a boolean setting value
func (r *SystemRepository) GetBool(ctx context.Context, key string) (bool, error) {
	setting, err := r.Get(ctx, key)
	if err != nil {
		return false, err
	}
	if setting == nil {
		return false, nil
	}
	return setting.Value == "true" || setting.Value == "1", nil
}

// CreateHeaderContractConflictOnce is the dedicated idempotent operation row.
func (r *SystemRepository) CreateHeaderContractConflictOnce(ctx context.Context, eventID string, payload map[string]any) error {
	canonical, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tag, err := r.db.Exec(ctx, `INSERT INTO audit_operations
		(id,user_id,action_type,action_detail,target_type,target_id,ip_address)
		VALUES ($1,NULL,'header_contract_conflict',$2::jsonb,'header_contract','','')
		ON CONFLICT (id) DO NOTHING`, eventID, canonical)
	if err != nil {
		return fmt.Errorf("create header conflict audit: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var action, userID, targetType, targetID, ipAddress string
	var existing []byte
	if err := r.db.QueryRow(ctx, `SELECT action_type,action_detail,COALESCE(user_id,''),COALESCE(target_type,''),COALESCE(target_id,''),COALESCE(ip_address,'')
		FROM audit_operations WHERE id=$1`, eventID).Scan(&action, &existing, &userID, &targetType, &targetID, &ipAddress); err != nil {
		return fmt.Errorf("read header conflict audit: %w", err)
	}
	var normalized any
	if err := json.Unmarshal(existing, &normalized); err != nil {
		return ErrHeaderContractCollision
	}
	existingCanonical, err := json.Marshal(normalized)
	if err != nil || action != "header_contract_conflict" || userID != "" || targetType != "header_contract" || targetID != "" || ipAddress != "" ||
		!bytes.Equal(existingCanonical, canonical) {
		return ErrHeaderContractCollision
	}
	return nil
}

// ErrSystemSettingsVersionConflict 表示条件写入时，这批键自读取以来已被别人改过。
var ErrSystemSettingsVersionConflict = errors.New("system settings version conflict")

// GetUpdatedAt 返回给定键的 updated_at；不存在的键不在结果里。
func (r *SystemRepository) GetUpdatedAt(ctx context.Context, keys []string) (map[string]time.Time, error) {
	out := make(map[string]time.Time, len(keys))
	if len(keys) == 0 {
		return out, nil
	}
	rows, err := r.db.Query(ctx, `SELECT key, updated_at FROM system_settings WHERE key = ANY($1)`, keys)
	if err != nil {
		return nil, fmt.Errorf("failed to read settings versions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var at time.Time
		if err := rows.Scan(&k, &at); err != nil {
			return nil, fmt.Errorf("failed to scan settings version: %w", err)
		}
		out[k] = at
	}
	return out, rows.Err()
}

// SetMultipleIfVersion 在同一个事务里条件写入一批键：先对 guardKeys 加行锁并计算它们当前的版本摘要，
// 与调用方读取时拿到的 expectedVersion 比较，不一致返回 ErrSystemSettingsVersionConflict 且什么都不写。
// 版本摘要由 versionOf(updated_at 的映射) 计算，由调用方传入，仓储不关心格式。
// 行锁（FOR UPDATE）保证「检查版本」与「写入」之间没有别人插进来，这是真正的原子比较并交换，而不是读后写。
func (r *SystemRepository) SetMultipleIfVersion(
	ctx context.Context, guardKeys []string, expectedVersion string,
	versionOf func(map[string]time.Time) string, settings map[string]string,
) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin settings update: %w", err)
	}
	defer tx.Rollback(ctx)
	// 先确保受保护的键都存在（空值占位），这样 FOR UPDATE 一定有行可锁，缺失的键也能参与版本比较。
	if _, err := tx.Exec(ctx, `
		INSERT INTO system_settings (key, value, updated_at)
		SELECT k, '', to_timestamp(0) FROM unnest($1::text[]) AS k
		ON CONFLICT (key) DO NOTHING`, guardKeys); err != nil {
		return fmt.Errorf("ensure settings rows: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT key, updated_at FROM system_settings WHERE key = ANY($1) ORDER BY key FOR UPDATE`, guardKeys)
	if err != nil {
		return fmt.Errorf("lock settings rows: %w", err)
	}
	current := make(map[string]time.Time, len(guardKeys))
	for rows.Next() {
		var k string
		var at time.Time
		if err := rows.Scan(&k, &at); err != nil {
			rows.Close()
			return fmt.Errorf("scan locked settings: %w", err)
		}
		if at.Unix() > 0 { // to_timestamp(0) 是「不存在」的占位
			current[k] = at
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate locked settings: %w", err)
	}
	if versionOf(current) != expectedVersion {
		return ErrSystemSettingsVersionConflict
	}
	payload, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO system_settings (key, value, updated_at)
 SELECT key, value, NOW() FROM jsonb_each_text($1::jsonb)
 ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at`, payload); err != nil {
		return fmt.Errorf("failed to set settings: %w", err)
	}
	// 即使这次没有改某个 guard 键，也要推进版本，否则「只改了别的键」的并发写入看不出冲突：
	// 把所有 guard 键的 updated_at 一并刷新到事务时间。
	if _, err := tx.Exec(ctx, `UPDATE system_settings SET updated_at = NOW() WHERE key = ANY($1)`, guardKeys); err != nil {
		return fmt.Errorf("advance settings version: %w", err)
	}
	return tx.Commit(ctx)
}

// GetByKeys 一次查询读出给定的键；不存在的键不在结果里。
func (r *SystemRepository) GetByKeys(ctx context.Context, keys []string) ([]*SystemSetting, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	args := make([]any, len(keys))
	for i, key := range keys {
		args[i] = key
	}
	rows, err := r.db.Query(ctx, systemSettingsByKeysQuery(len(keys)), args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}
	defer rows.Close()
	var settings []*SystemSetting
	for rows.Next() {
		var s SystemSetting
		if err := rows.Scan(&s.Key, &s.Value, &s.UpdatedAt); err != nil {
			return nil, err
		}
		settings = append(settings, &s)
	}
	return settings, rows.Err()
}

func systemSettingsByKeysQuery(n int) string {
	placeholders := make([]string, n)
	for i := range placeholders {
		placeholders[i] = "$" + strconv.Itoa(i+1)
	}
	return "SELECT key, value, updated_at FROM system_settings WHERE key IN (" + strings.Join(placeholders, ", ") + ")"
}
