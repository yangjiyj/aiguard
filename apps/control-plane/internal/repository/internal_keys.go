package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// InternalKey represents an internal API key
type InternalKey struct {
	ModelAllowlist []string
	IsEmployee     bool
	// TrafficClass 由管理员设置（""/evaluation/coding），告警页车道只信这一列。
	TrafficClass string
	ID           string
	TenantID     string
	ProjectID    string
	UserID       string
	Name         string
	KeyHash      string
	KeyPrefix    string
	Scopes       []string
	ExpiresAt    *time.Time
	LastUsedAt   *time.Time
	Status       string
	CreatedAt    time.Time
	// KeyCiphertext 完整密钥 AES-GCM 密文（enc:v1: 前缀）。仅后台受保护 reveal 端点按需解密复制；
	// List/Create 常规响应绝不回传。改造前的老 key 此值为空（原文已丢，不可复原）。
	KeyCiphertext string
}

// InternalKeyRepository handles internal key database operations
type InternalKeyRepository struct {
	db *pgxpool.Pool
}

// NewInternalKeyRepository creates a new internal key repository
func NewInternalKeyRepository(db *pgxpool.Pool) *InternalKeyRepository {
	return &InternalKeyRepository{db: db}
}

// GetByHash retrieves a key by its hash
// user_id 可为 NULL（portal 无归属发放），裸 string Scan 会在 NULL 行报错，必须 COALESCE。
func (r *InternalKeyRepository) GetByHash(ctx context.Context, keyHash string) (*InternalKey, error) {
	query := `
		SELECT id, tenant_id, project_id, COALESCE(user_id,''), key_hash, key_prefix, scopes_json, COALESCE(name,''), expires_at, last_used_at, status, created_at, COALESCE(key_ciphertext,''), model_allowlist
		FROM internal_keys
		WHERE key_hash = $1
	`

	row := r.db.QueryRow(ctx, query, keyHash)
	var key InternalKey
	var scopesJSON []byte
	err := row.Scan(
		&key.ID,
		&key.TenantID,
		&key.ProjectID,
		&key.UserID,
		&key.KeyHash,
		&key.KeyPrefix,
		&scopesJSON,
		&key.Name,
		&key.ExpiresAt,
		&key.LastUsedAt,
		&key.Status,
		&key.CreatedAt,
		&key.KeyCiphertext, &key.ModelAllowlist,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Parse scopes
	if len(scopesJSON) > 0 {
		key.Scopes = parseScopesJSON(scopesJSON)
	}

	return &key, nil
}

// GetByID retrieves a key by id, scoped to a tenant. Returns (nil, nil) if not found.
// reveal 端点专用：拿 key_ciphertext 供后台受保护解密复制；租户隔离防越权查看他人密钥。
func (r *InternalKeyRepository) GetByID(ctx context.Context, tenantID, keyID string) (*InternalKey, error) {
	query := `
		SELECT id, tenant_id, project_id, COALESCE(user_id,''), key_hash, key_prefix, scopes_json, COALESCE(name,''), expires_at, last_used_at, status, created_at, COALESCE(key_ciphertext,''), model_allowlist
		FROM internal_keys
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`

	row := r.db.QueryRow(ctx, query, keyID, tenantID)
	var key InternalKey
	var scopesJSON []byte
	err := row.Scan(
		&key.ID,
		&key.TenantID,
		&key.ProjectID,
		&key.UserID,
		&key.KeyHash,
		&key.KeyPrefix,
		&scopesJSON,
		&key.Name,
		&key.ExpiresAt,
		&key.LastUsedAt,
		&key.Status,
		&key.CreatedAt,
		&key.KeyCiphertext, &key.ModelAllowlist,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get key by id: %w", err)
	}
	key.Scopes = parseScopesJSON(scopesJSON)
	return &key, nil
}

// GetUniqueByPrefix resolves a legacy key reference only when it identifies
// exactly one key inside the tenant. Ambiguous prefixes deliberately look absent.
func (r *InternalKeyRepository) GetUniqueByPrefix(ctx context.Context, tenantID, keyPrefix string) (*InternalKey, error) {
	query := `
		SELECT id, tenant_id, project_id, COALESCE(user_id,''), key_hash, key_prefix, scopes_json, COALESCE(name,''), expires_at, last_used_at, status, created_at, COALESCE(key_ciphertext,''), model_allowlist
		FROM internal_keys candidate
		WHERE candidate.tenant_id = $1 AND candidate.key_prefix = $2 AND candidate.deleted_at IS NULL
		  AND NOT EXISTS (
			SELECT 1 FROM internal_keys sibling
			WHERE sibling.tenant_id = candidate.tenant_id
			  AND sibling.key_prefix = candidate.key_prefix
			  AND sibling.id <> candidate.id
		  )
		LIMIT 1
	`
	row := r.db.QueryRow(ctx, query, tenantID, keyPrefix)
	var key InternalKey
	var scopesJSON []byte
	err := row.Scan(
		&key.ID, &key.TenantID, &key.ProjectID, &key.UserID, &key.KeyHash,
		&key.KeyPrefix, &scopesJSON, &key.Name, &key.ExpiresAt, &key.LastUsedAt,
		&key.Status, &key.CreatedAt, &key.KeyCiphertext, &key.ModelAllowlist,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get unique key by prefix: %w", err)
	}
	key.Scopes = parseScopesJSON(scopesJSON)
	return &key, nil
}

// List retrieves keys for a project within a tenant.
func (r *InternalKeyRepository) List(ctx context.Context, tenantID, projectID string) ([]*InternalKey, error) {
	return listKeysWith(ctx, r.db, tenantID, projectID)
}

type keyQueryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// listKeysWith 列出租户下（可选限定应用）未删除的密钥。projectID 为空表示整个租户。
// 抽出来是为了让 List/ListAll 共用一份扫描，且能用真实 PostgreSQL 直接测试。
func listKeysWith(ctx context.Context, db keyQueryer, tenantID, projectID string) ([]*InternalKey, error) {
	query := `
		SELECT id, tenant_id, project_id, COALESCE(user_id,''), key_hash, key_prefix, scopes_json, COALESCE(name,''), expires_at, last_used_at, status, created_at, COALESCE(key_ciphertext,''), model_allowlist, COALESCE(traffic_class,'')
		FROM internal_keys
		WHERE tenant_id = $1 AND ($2 = '' OR project_id = $2) AND deleted_at IS NULL
		ORDER BY created_at DESC
	`
	rows, err := db.Query(ctx, query, tenantID, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer rows.Close()

	keys := []*InternalKey{}
	for rows.Next() {
		var key InternalKey
		var scopesJSON []byte
		err := rows.Scan(
			&key.ID, &key.TenantID, &key.ProjectID, &key.UserID, &key.KeyHash, &key.KeyPrefix,
			&scopesJSON, &key.Name, &key.ExpiresAt, &key.LastUsedAt, &key.Status, &key.CreatedAt,
			&key.KeyCiphertext, &key.ModelAllowlist, &key.TrafficClass,
		)
		if err != nil {
			return nil, err
		}
		key.Scopes = parseScopesJSON(scopesJSON)
		keys = append(keys, &key)
	}
	return keys, rows.Err()
}

// ListByUser 列出某用户名下的 key（用户详情"密钥"tab 用）。绝不回传 hash/密文由上层 DTO 脱敏。
func (r *InternalKeyRepository) ListByUser(ctx context.Context, tenantID, userID string) ([]*InternalKey, error) {
	query := `
		SELECT id, tenant_id, project_id, COALESCE(user_id,''), key_hash, key_prefix, scopes_json, COALESCE(name,''), expires_at, last_used_at, status, created_at, COALESCE(key_ciphertext,''), model_allowlist, EXISTS(SELECT 1 FROM employee_api_keys m WHERE m.tenant_id=internal_keys.tenant_id AND m.user_id=internal_keys.user_id AND m.key_id=internal_keys.id)
		FROM internal_keys
		WHERE tenant_id = $1 AND user_id = $2 AND deleted_at IS NULL
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys by user: %w", err)
	}
	defer rows.Close()

	keys := []*InternalKey{}
	for rows.Next() {
		var key InternalKey
		var scopesJSON []byte
		err := rows.Scan(
			&key.ID, &key.TenantID, &key.ProjectID, &key.UserID, &key.KeyHash,
			&key.KeyPrefix, &scopesJSON, &key.Name, &key.ExpiresAt, &key.LastUsedAt,
			&key.Status, &key.CreatedAt, &key.KeyCiphertext, &key.ModelAllowlist, &key.IsEmployee,
		)
		if err != nil {
			return nil, err
		}
		key.Scopes = parseScopesJSON(scopesJSON)
		keys = append(keys, &key)
	}
	return keys, nil
}

// Create creates a new internal key
func (r *InternalKeyRepository) Create(ctx context.Context, key *InternalKey, rawKey string) error {
	return createInternalKey(ctx, r.db, key, rawKey)
}

func createInternalKey(ctx context.Context, db identityBindingDBTX, key *InternalKey, rawKey string) error {
	if key.ID == "" {
		key.ID = "key_" + uuid.New().String()[:8]
	}

	// Hash the key
	hash := sha256.Sum256([]byte(rawKey))
	key.KeyHash = hex.EncodeToString(hash[:])
	key.KeyPrefix = rawKey[:8]

	// 完整密钥 AES-GCM 加密（enc:v1:），供后台受保护 reveal 端点按需解密复制。key_hash 鉴权链路不受影响。
	// 加密密钥（JJD_PROVIDER_SECRET_KEY/JJD_MASTER_KEY）未配置时优雅降级：key 照建，密文留空，
	// reveal 返 created_before_encryption 提示重置——不因未配密钥而阻断建 key（与改造前行为一致）。
	// 其余加密错误（理论上不出现）则失败，避免落入不可复原却看似正常的坏态。
	ciphertext, _, encErr := secrets.EncryptProviderSecret(rawKey)
	if encErr != nil && !errors.Is(encErr, secrets.ErrSecretKeyNotConfigured) {
		return fmt.Errorf("failed to encrypt key ciphertext: %w", encErr)
	}
	key.KeyCiphertext = ciphertext

	// user_id 列带外键 REFERENCES users(id)：portal-integration 无归属发放时传空串，
	// 必须经 NULLIF 落 NULL（空串是非 NULL 值，会撞 23503）；读侧对应 COALESCE 规整回空串。
	query := `
		INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, scopes_json, name, expires_at, status, key_ciphertext, model_allowlist)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7, $8, $9, $10, NULLIF($11, ''), COALESCE($12::text[],'{}'))
		RETURNING created_at
	`

	scopesJSON, err := json.Marshal(key.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal scopes: %w", err)
	}

	err = db.QueryRow(ctx, query,
		key.ID,
		key.TenantID,
		key.ProjectID,
		key.UserID,
		key.KeyHash,
		key.KeyPrefix,
		scopesJSON,
		key.Name,
		key.ExpiresAt,
		key.Status,
		key.KeyCiphertext, key.ModelAllowlist,
	).Scan(&key.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}
	return nil
}

// UpdateName 更新密钥备注/名称（租户隔离）。仅改 name 列，不触碰 hash/密文/scopes/状态。
// name 为空串时按 NULLIF 落 NULL，与读侧 COALESCE 规整回空串对齐；限长/控制字符校验在 handler 层。
func (r *InternalKeyRepository) UpdateName(ctx context.Context, tenantID, keyID, name string) error {
	query := `UPDATE internal_keys SET name = NULLIF($1, '') WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL`
	result, err := r.db.Exec(ctx, query, name, keyID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to update key name: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("key not found")
	}
	return nil
}

// ErrKeyNotFound 表示密钥不存在、已删除或不属于该租户。三种情况对调用方不可区分，避免探测其它租户的密钥 id。
var ErrKeyNotFound = errors.New("key not found")

// ErrInvalidTrafficClass 表示流量类别取值不在白名单内。
var ErrInvalidTrafficClass = errors.New("invalid traffic class")

type trafficClassExecer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// SetTrafficClass 设置接入凭据的流量类别（”/evaluation/coding）。告警页车道只信这一列。
// 租户条件和 deleted_at 条件都在 SQL 里，跨租户或已删除的密钥一律 ErrKeyNotFound。
func (r *InternalKeyRepository) SetTrafficClass(ctx context.Context, tenantID, keyID, class string) error {
	return r.setTrafficClass(ctx, r.db, tenantID, keyID, class)
}

func (r *InternalKeyRepository) setTrafficClass(ctx context.Context, db trafficClassExecer, tenantID, keyID, class string) error {
	switch class {
	case "", "evaluation", "coding":
	default:
		return ErrInvalidTrafficClass
	}
	result, err := db.Exec(ctx, `UPDATE internal_keys SET traffic_class = $1 WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL`, class, keyID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to set key traffic class: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrKeyNotFound
	}
	return nil
}

// Revoke revokes a key within a tenant.
func (r *InternalKeyRepository) Revoke(ctx context.Context, tenantID, keyID string) error {
	query := `
		UPDATE internal_keys
		SET status = 'revoked', last_used_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`

	result, err := r.db.Exec(ctx, query, keyID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to revoke key: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("key not found")
	}
	return nil
}

// Delete revokes and hides a key while preserving historical references and audit.
func (r *InternalKeyRepository) Delete(ctx context.Context, tenant, keyID, actor string) error {
	return r.deleteKey(ctx, tenant, keyID, actor, "")
}

// DeleteOwned requires the exact active owner; tenant and owner come from the trusted portal.
func (r *InternalKeyRepository) DeleteOwned(ctx context.Context, tenant, keyID, user string) error {
	if user == "" {
		return pgx.ErrNoRows
	}
	return r.deleteKey(ctx, tenant, keyID, user, user)
}

func (r *InternalKeyRepository) deleteKey(ctx context.Context, tenant, keyID, actor, owner string) error {
	if tenant == "" || keyID == "" || actor == "" {
		return pgx.ErrNoRows
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var currentOwner string
	err = tx.QueryRow(ctx, `SELECT COALESCE(k.user_id,'') FROM internal_keys k
 WHERE k.tenant_id=$1 AND k.id=$2 AND k.deleted_at IS NULL
 AND ($3::text='' OR (k.user_id=$3 AND EXISTS(SELECT 1 FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=k.tenant_id AND u.id=k.user_id AND u.status='active' AND t.status='active')))
 FOR UPDATE OF k`, tenant, keyID, owner).Scan(&currentOwner)
	if errors.Is(err, pgx.ErrNoRows) {
		return pgx.ErrNoRows
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE internal_keys SET status='revoked',deleted_at=now(),key_ciphertext=NULL WHERE tenant_id=$1 AND id=$2`, tenant, keyID); err != nil {
		return err
	}
	action := "delete_key"
	if owner != "" {
		action = "portal_delete_key"
	}
	if err = writeTransactionalOperationAudit(ctx, tx, tenant, actor, action, "key", keyID, map[string]any{"user_id": currentOwner, "key_id": keyID}); err != nil {
		return err
	}
	return commitWithOperationAudit(ctx, tx)
}

// UpdateLastUsed updates the last used timestamp
func (r *InternalKeyRepository) UpdateLastUsed(ctx context.Context, keyID string) error {
	query := `
		UPDATE internal_keys
		SET last_used_at = NOW()
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, keyID)
	if err != nil {
		return fmt.Errorf("failed to update last used: %w", err)
	}
	return nil
}

// IsValid checks if a key is valid (active, not expired)
func (k *InternalKey) IsValid() bool {
	if k.Status != "active" {
		return false
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return false
	}
	return true
}

// ListAll retrieves all keys for a tenant
func (r *InternalKeyRepository) ListAll(ctx context.Context, tenantID string) ([]*InternalKey, error) {
	return listKeysWith(ctx, r.db, tenantID, "")
}

func parseScopesJSON(scopesJSON []byte) []string {
	if len(scopesJSON) == 0 {
		return []string{}
	}
	var scopes []string
	if err := json.Unmarshal(scopesJSON, &scopes); err != nil {
		return []string{}
	}
	return scopes
}

// RevokeOwned locks and validates the exact current owner; revocation and its
// real-user audit commit together. A repeated revoke does not duplicate audit.
func (r *InternalKeyRepository) RevokeOwned(ctx context.Context, tenant, keyID, user string) (bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var active bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2 AND u.status='active' AND t.status='active')", tenant, user).Scan(&active); err != nil {
		return false, err
	}
	if !active {
		return false, nil
	}
	var status string
	err = tx.QueryRow(ctx, "SELECT status FROM internal_keys WHERE tenant_id=$1 AND id=$2 AND user_id=$3 AND deleted_at IS NULL FOR UPDATE", tenant, keyID, user).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if status != "revoked" {
		if _, err = tx.Exec(ctx, "UPDATE internal_keys SET status='revoked' WHERE tenant_id=$1 AND id=$2 AND user_id=$3", tenant, keyID, user); err != nil {
			return false, err
		}
		if err = writeTransactionalOperationAudit(ctx, tx, tenant, user, "portal_revoke_key", "key", keyID, map[string]any{"user_id": user, "key_id": keyID}); err != nil {
			return false, err
		}
	}
	return true, commitWithOperationAudit(ctx, tx)
}

func (r *InternalKeyRepository) IsEmployeeKey(ctx context.Context, tenant, key, user string) (bool, error) {
	var found bool
	err := r.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM employee_api_keys WHERE tenant_id=$1 AND user_id=$2 AND key_id=$3)", tenant, user, key).Scan(&found)
	return found, err
}
func (r *InternalKeyRepository) AuditOwnedKeyReveal(ctx context.Context, tenant, key, user, ciphertext, ip string) (bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, `SELECT k.id FROM internal_keys k JOIN users u ON u.tenant_id=k.tenant_id AND u.id=k.user_id WHERE k.tenant_id=$1 AND k.id=$2 AND k.user_id=$3 AND k.status='active' AND u.status='active' AND k.key_ciphertext=$4 FOR SHARE OF k,u`, tenant, key, user, ciphertext).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err = writeTransactionalOperationAudit(ctx, tx, tenant, user, "portal_customer_reveal_key", "key", key, map[string]any{"user_id": user, "key_id": key}); err != nil {
		return false, err
	}
	return true, commitWithOperationAudit(ctx, tx)
}
