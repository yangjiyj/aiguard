package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ProxyAccessKey 表示正向代理的访问密钥（一租户可签发多把）。
// 明文密钥仅在签发时返回一次，库里只保存 sha256 哈希与 8 位前缀。
type ProxyAccessKey struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	ProxyKeyHash   string     `json:"-"`
	ProxyKeyPrefix string     `json:"proxy_key_prefix"`
	ModelIDs       []string   `json:"model_ids"`
	RPMLimit       int        `json:"rpm_limit"`
	DailyCap       int        `json:"daily_cap"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ProxyAccessKeysRepository 负责 proxy_access_keys 表的读写。
type ProxyAccessKeysRepository struct {
	db *pgxpool.Pool
}

func NewProxyAccessKeysRepository(db *pgxpool.Pool) *ProxyAccessKeysRepository {
	return &ProxyAccessKeysRepository{db: db}
}

// Create 签发一把访问密钥：传入明文 rawKey，仓库内部哈希后入库（明文不落库）。
func (r *ProxyAccessKeysRepository) Create(ctx context.Context, k *ProxyAccessKey, rawKey string) error {
	if k.ID == "" {
		k.ID = "pxk_" + uuid.New().String()[:8]
	}
	hash := sha256.Sum256([]byte(rawKey))
	k.ProxyKeyHash = hex.EncodeToString(hash[:])
	if len(rawKey) >= 8 {
		k.ProxyKeyPrefix = rawKey[:8]
	} else {
		k.ProxyKeyPrefix = rawKey
	}
	if k.RPMLimit == 0 {
		k.RPMLimit = 60
	}
	if k.DailyCap == 0 {
		k.DailyCap = 1000
	}
	if k.Status == "" {
		k.Status = "active"
	}
	if k.ModelIDs == nil {
		k.ModelIDs = []string{}
	}
	modelBytes, _ := json.Marshal(k.ModelIDs)
	query := `INSERT INTO proxy_access_keys
		(id, tenant_id, proxy_key_hash, proxy_key_prefix, model_ids, rpm_limit, daily_cap, expires_at, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING created_at`
	return r.db.QueryRow(ctx, query,
		k.ID, k.TenantID, k.ProxyKeyHash, k.ProxyKeyPrefix, string(modelBytes),
		k.RPMLimit, k.DailyCap, k.ExpiresAt, k.Status,
	).Scan(&k.CreatedAt)
}

// Update 管理动作：调整模型白名单、限额与状态。
// Update 修改一把访问密钥。WHERE 带 tenant_id 防跨租户 IDOR。
func (r *ProxyAccessKeysRepository) Update(ctx context.Context, tenantID, id string, modelIDs []string, rpmLimit, dailyCap int, status string) error {
	if modelIDs == nil {
		modelIDs = []string{}
	}
	modelBytes, _ := json.Marshal(modelIDs)
	query := `UPDATE proxy_access_keys SET model_ids = $1, rpm_limit = $2, daily_cap = $3, status = $4 WHERE id = $5 AND tenant_id = $6`
	_, err := r.db.Exec(ctx, query, string(modelBytes), rpmLimit, dailyCap, status, id, tenantID)
	return err
}

// Delete 删除一把访问密钥（带 tenant_id 防跨租户删除）。
func (r *ProxyAccessKeysRepository) Delete(ctx context.Context, tenantID, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM proxy_access_keys WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

// SetExpiry 设置某把 key 的过期时刻（用于轮换灰度窗口：把旧 key 延后过期）。
// expiresAt 为 nil 时清空过期（永不过期）；非 nil 时写入指定时刻。
func (r *ProxyAccessKeysRepository) SetExpiry(ctx context.Context, id string, expiresAt *time.Time) error {
	_, err := r.db.Exec(ctx, `UPDATE proxy_access_keys SET expires_at = $1 WHERE id = $2`, expiresAt, id)
	return err
}

const proxyAccessKeyColumns = `id, tenant_id, proxy_key_hash, proxy_key_prefix, model_ids, rpm_limit, daily_cap, expires_at, last_used_at, status, created_at`

// Get 按 id 读回一把访问密钥；无行时返回 pgx.ErrNoRows。
func (r *ProxyAccessKeysRepository) Get(ctx context.Context, id string) (*ProxyAccessKey, error) {
	row := r.db.QueryRow(ctx, `SELECT `+proxyAccessKeyColumns+` FROM proxy_access_keys WHERE id = $1`, id)
	return scanProxyAccessKey(row)
}

// ListByTenant 按租户列出访问密钥，最近签发的在前。
func (r *ProxyAccessKeysRepository) ListByTenant(ctx context.Context, tenantID string) ([]*ProxyAccessKey, error) {
	rows, err := r.db.Query(ctx, `SELECT `+proxyAccessKeyColumns+` FROM proxy_access_keys WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProxyAccessKeys(rows)
}

type proxyAccessKeyScanner interface {
	Scan(dest ...any) error
}

func scanProxyAccessKey(row proxyAccessKeyScanner) (*ProxyAccessKey, error) {
	k := &ProxyAccessKey{}
	var modelStr string
	if err := row.Scan(
		&k.ID, &k.TenantID, &k.ProxyKeyHash, &k.ProxyKeyPrefix, &modelStr,
		&k.RPMLimit, &k.DailyCap, &k.ExpiresAt, &k.LastUsedAt, &k.Status, &k.CreatedAt,
	); err != nil {
		return nil, err
	}
	if modelStr != "" {
		_ = json.Unmarshal([]byte(modelStr), &k.ModelIDs)
	}
	if k.ModelIDs == nil {
		k.ModelIDs = []string{}
	}
	return k, nil
}

func scanProxyAccessKeys(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}) ([]*ProxyAccessKey, error) {
	var out []*ProxyAccessKey
	for rows.Next() {
		k, err := scanProxyAccessKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
