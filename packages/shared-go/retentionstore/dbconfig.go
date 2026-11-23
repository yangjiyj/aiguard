package retentionstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

const retentionConfigSingleton = "singleton"

// isUndefinedTableErr 报告 err 是否为 PostgreSQL「表不存在」(SQLSTATE 42P01)。
// 全新装时服务可能早于 migration 启动(离线 deploy 先 up -d 全部服务、再跑 migration-runner),
// 此刻 retention_storage_config 尚未建表。该错误须被视同「无配置」——回退本地默认 / env 根,
// 由调用方的 60s 热重载在迁移完成后接管,绝不能因此阻断留存 store 的初始化。
func isUndefinedTableErr(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

// StorageSettings 是存 DB 的留存存储配置(不含明文 secret)。HasSecret 标记是否已设密钥,
// 供控制台展示用——绝不把明文 secret 回给前端。
type StorageSettings struct {
	Backend     string
	LocalPath   string
	S3Endpoint  string
	S3Bucket    string
	S3AccessKey string
	S3Region    string
	S3Prefix    string
	S3UseSSL    bool
	HasSecret   bool
	UpdatedAt   time.Time
	UpdatedBy   string
}

// ReadSettings 读 DB 配置(不解密 secret)。供控制台展示。表不存在/无行时返回 local 默认。
func ReadSettings(ctx context.Context, db *pgxpool.Pool) (StorageSettings, error) {
	if db == nil {
		return StorageSettings{Backend: BackendLocal, S3UseSSL: true}, nil
	}
	var s StorageSettings
	var secretEnc string
	err := db.QueryRow(ctx, `
		SELECT backend, local_path, s3_endpoint, s3_bucket, s3_access_key, s3_secret_enc, s3_region, s3_prefix, s3_use_ssl, updated_at, updated_by
		FROM retention_storage_config WHERE id = $1
	`, retentionConfigSingleton).Scan(&s.Backend, &s.LocalPath, &s.S3Endpoint, &s.S3Bucket, &s.S3AccessKey, &secretEnc, &s.S3Region, &s.S3Prefix, &s.S3UseSSL, &s.UpdatedAt, &s.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) || isUndefinedTableErr(err) {
		return StorageSettings{Backend: BackendLocal, S3UseSSL: true}, nil
	}
	if err != nil {
		return StorageSettings{}, fmt.Errorf("read retention storage config: %w", err)
	}
	s.HasSecret = strings.TrimSpace(secretEnc) != ""
	return s, nil
}

// LoadConfig 读 DB 配置 + 解密 secret + 合并 env localRoot,返回可直接 NewStore 的 Config。
// db 为空/无行时返回 local(用 localRoot),不阻断留存。
func LoadConfig(ctx context.Context, db *pgxpool.Pool, localRoot string) (Config, error) {
	cfg := Config{Backend: BackendLocal, LocalRoot: localRoot}
	if db == nil {
		return cfg, nil
	}
	var backend, localPath, endpoint, bucket, accessKey, secretEnc, region, prefix string
	var useSSL bool
	err := db.QueryRow(ctx, `
		SELECT backend, local_path, s3_endpoint, s3_bucket, s3_access_key, s3_secret_enc, s3_region, s3_prefix, s3_use_ssl
		FROM retention_storage_config WHERE id = $1
	`, retentionConfigSingleton).Scan(&backend, &localPath, &endpoint, &bucket, &accessKey, &secretEnc, &region, &prefix, &useSSL)
	// 无行 或 表尚未迁移(全新装时服务早于 migration 启动)→ 回退 env 根的 local 配置,由 60s 热重载接管。
	if errors.Is(err, pgx.ErrNoRows) || isUndefinedTableErr(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("load retention storage config: %w", err)
	}
	cfg.Backend = strings.TrimSpace(backend)
	if cfg.Backend == "" {
		cfg.Backend = BackendLocal
	}
	// 挂载目录优先用 DB 配的 local_path(指向 NFS/SMB 挂载点),为空回退 env 根。
	if lp := strings.TrimSpace(localPath); lp != "" {
		cfg.LocalRoot = lp
	}
	secret, derr := secrets.DecryptProviderSecret(secretEnc)
	if derr != nil {
		return cfg, fmt.Errorf("decrypt s3 secret: %w", derr)
	}
	cfg.S3Endpoint, cfg.S3Bucket, cfg.S3AccessKey = endpoint, bucket, accessKey
	cfg.S3SecretKey, cfg.S3Region, cfg.S3Prefix, cfg.S3UseSSL = secret, region, prefix, useSSL
	return cfg, nil
}

// SaveConfig upsert 配置。secretPlaintext=="" 表示保留原 secret(前端不每次回传密钥);
// 非空则加密更新。backend 必须是 local 或 s3。
func SaveConfig(ctx context.Context, db *pgxpool.Pool, s StorageSettings, secretPlaintext, updatedBy string) error {
	if db == nil {
		return fmt.Errorf("db is nil")
	}
	backend := strings.TrimSpace(s.Backend)
	if backend != BackendLocal && backend != BackendS3 {
		return fmt.Errorf("invalid retention backend %q", backend)
	}
	if strings.TrimSpace(secretPlaintext) == "" {
		_, err := db.Exec(ctx, `
			INSERT INTO retention_storage_config (id, backend, local_path, s3_endpoint, s3_bucket, s3_access_key, s3_region, s3_prefix, s3_use_ssl, updated_at, updated_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),$10)
			ON CONFLICT (id) DO UPDATE SET
				backend=$2, local_path=$3, s3_endpoint=$4, s3_bucket=$5, s3_access_key=$6,
				s3_region=$7, s3_prefix=$8, s3_use_ssl=$9, updated_at=now(), updated_by=$10
		`, retentionConfigSingleton, backend, s.LocalPath, s.S3Endpoint, s.S3Bucket, s.S3AccessKey, s.S3Region, s.S3Prefix, s.S3UseSSL, updatedBy)
		return err
	}
	enc, _, err := secrets.EncryptProviderSecret(secretPlaintext)
	if err != nil {
		return fmt.Errorf("encrypt s3 secret: %w", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO retention_storage_config (id, backend, local_path, s3_endpoint, s3_bucket, s3_access_key, s3_secret_enc, s3_region, s3_prefix, s3_use_ssl, updated_at, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now(),$11)
		ON CONFLICT (id) DO UPDATE SET
			backend=$2, local_path=$3, s3_endpoint=$4, s3_bucket=$5, s3_access_key=$6, s3_secret_enc=$7,
			s3_region=$8, s3_prefix=$9, s3_use_ssl=$10, updated_at=now(), updated_by=$11
	`, retentionConfigSingleton, backend, s.LocalPath, s.S3Endpoint, s.S3Bucket, s.S3AccessKey, enc, s.S3Region, s.S3Prefix, s.S3UseSSL, updatedBy)
	return err
}
