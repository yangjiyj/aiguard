package retentionstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const (
	s3MetaRetentionUntil = "Retention-Until"
	s3MetaSHA256         = "Sha256"
	s3MetaTenantID       = "Tenant-Id"
)

// S3Store 把留存对象存到 S3 兼容对象存储(MinIO / NAS 自带 S3 网关 / 云 OSS)。键方案与
// LocalStore 一致;切换前已落本机的旧对象通过可选 localFallback 回退读,保证切换后历史图仍可见。
type S3Store struct {
	client        *minio.Client
	bucket        string
	prefix        string
	localFallback *LocalStore
}

// NewS3Store 按配置建 S3 后端;endpoint 容忍带 http(s):// 前缀。
func NewS3Store(cfg Config) (*S3Store, error) {
	endpoint := strings.TrimSpace(cfg.S3Endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("s3 endpoint is required")
	}
	if strings.TrimSpace(cfg.S3Bucket) == "" {
		return nil, fmt.Errorf("s3 bucket is required")
	}
	secure := cfg.S3UseSSL
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		endpoint, secure = strings.TrimPrefix(endpoint, "https://"), true
	case strings.HasPrefix(endpoint, "http://"):
		endpoint, secure = strings.TrimPrefix(endpoint, "http://"), false
	}
	endpoint = strings.TrimRight(endpoint, "/")
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.S3AccessKey, cfg.S3SecretKey, ""),
		Secure: secure,
		Region: strings.TrimSpace(cfg.S3Region),
	})
	if err != nil {
		return nil, fmt.Errorf("init s3 client: %w", err)
	}
	s := &S3Store{
		client: client,
		bucket: strings.TrimSpace(cfg.S3Bucket),
		prefix: strings.Trim(strings.TrimSpace(cfg.S3Prefix), "/"),
	}
	if root := strings.TrimSpace(cfg.LocalRoot); root != "" {
		if lf, lerr := NewLocalStore(root); lerr == nil {
			s.localFallback = lf
		}
	}
	return s, nil
}

func (s *S3Store) objectName(key string) string {
	if s.prefix == "" {
		return key
	}
	return s.prefix + "/" + key
}

// authorizeKey 复用 LocalStore 的键校验:格式合法 + 键首段租户必须与调用方一致。
func authorizeKey(tenantID, key string) error {
	if strings.TrimSpace(tenantID) == "" {
		return fmt.Errorf("tenant id is required")
	}
	if err := validateObjectKey(key); err != nil {
		return err
	}
	parts := strings.Split(key, "/")
	if parts[0] != safeComponent(tenantID, "tenant") {
		return fmt.Errorf("%w: key tenant does not match caller", ErrObjectAccessDenied)
	}
	return nil
}

func isS3NotFound(err error) bool {
	if err == nil {
		return false
	}
	return minio.ToErrorResponse(err).Code == "NoSuchKey"
}

func (s *S3Store) PutObject(ctx context.Context, input PutObjectInput) (ObjectMetadata, error) {
	if err := checkContext(ctx); err != nil {
		return ObjectMetadata{}, err
	}
	if s == nil || s.client == nil {
		return ObjectMetadata{}, fmt.Errorf("s3 store is nil")
	}
	tenantID := strings.TrimSpace(input.TenantID)
	if tenantID == "" {
		return ObjectMetadata{}, fmt.Errorf("tenant id is required")
	}
	if input.Reader == nil {
		return ObjectMetadata{}, fmt.Errorf("reader is required")
	}
	key := path.Join(
		safeComponent(tenantID, "tenant"),
		safeComponent(input.RequestID, "request"),
		safeComponent(input.Stage, "stage"),
		safeComponent(input.FieldName, "field"),
		uuid.NewString(),
	)
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return ObjectMetadata{}, fmt.Errorf("read retention object: %w", err)
	}
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	contentType := strings.TrimSpace(input.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	meta := map[string]string{s3MetaSHA256: sha, s3MetaTenantID: tenantID}
	if !input.RetentionUntil.IsZero() {
		meta[s3MetaRetentionUntil] = input.RetentionUntil.UTC().Format(time.RFC3339)
	}
	if _, err := s.client.PutObject(ctx, s.bucket, s.objectName(key), bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{
		ContentType:  contentType,
		UserMetadata: meta,
	}); err != nil {
		return ObjectMetadata{}, fmt.Errorf("put s3 object: %w", err)
	}
	return ObjectMetadata{
		Key:             key,
		TenantID:        tenantID,
		RequestID:       strings.TrimSpace(input.RequestID),
		Stage:           strings.TrimSpace(input.Stage),
		FieldName:       strings.TrimSpace(input.FieldName),
		FileName:        strings.TrimSpace(input.FileName),
		ContentType:     contentType,
		Size:            int64(len(data)),
		SHA256:          sha,
		StorageBackend:  "s3",
		RetentionUntil:  input.RetentionUntil.UTC(),
		CreatedAt:       time.Now().UTC(),
		RedactionStatus: "externalized",
	}, nil
}

func (s *S3Store) GetObject(ctx context.Context, tenantID, key string) (Object, error) {
	if err := checkContext(ctx); err != nil {
		return Object{}, err
	}
	if err := authorizeKey(tenantID, key); err != nil {
		return Object{}, err
	}
	obj, err := s.client.GetObject(ctx, s.bucket, s.objectName(key), minio.GetObjectOptions{})
	if err == nil {
		info, statErr := obj.Stat()
		if statErr == nil {
			return Object{Metadata: s3InfoToMetadata(key, tenantID, info), Body: obj}, nil
		}
		obj.Close()
		err = statErr
	}
	// 对象不在 S3 → 回退本机(切换前的老对象仍可见)
	if isS3NotFound(err) {
		if s.localFallback != nil {
			return s.localFallback.GetObject(ctx, tenantID, key)
		}
		return Object{}, ErrObjectNotFound
	}
	return Object{}, fmt.Errorf("get s3 object: %w", err)
}

func (s *S3Store) DeleteObject(ctx context.Context, tenantID, key string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := authorizeKey(tenantID, key); err != nil {
		return err
	}
	if err := s.client.RemoveObject(ctx, s.bucket, s.objectName(key), minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("delete s3 object: %w", err)
	}
	// 老对象可能还在本机,一并清(忽略 not-found)
	if s.localFallback != nil {
		if derr := s.localFallback.DeleteObject(ctx, tenantID, key); derr != nil && derr != ErrObjectNotFound {
			return derr
		}
	}
	return nil
}

// ReapExpired 删除 retention-until 已过期的 S3 对象,并一并 reap 本机回退里的过期对象。
// WORM:无 retention-until 元数据(=永久)的对象绝不删,只清严格过期的。
func (s *S3Store) ReapExpired(ctx context.Context, now time.Time) (int, error) {
	if s == nil || s.client == nil {
		return 0, fmt.Errorf("s3 store is nil")
	}
	cutoff := now.UTC()
	deleted := 0
	listPrefix := ""
	if s.prefix != "" {
		listPrefix = s.prefix + "/"
	}
	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: listPrefix, Recursive: true}) {
		if obj.Err != nil {
			return deleted, fmt.Errorf("list s3 objects: %w", obj.Err)
		}
		if err := checkContext(ctx); err != nil {
			return deleted, err
		}
		stat, err := s.client.StatObject(ctx, s.bucket, obj.Key, minio.StatObjectOptions{})
		if err != nil {
			continue
		}
		raw := stat.UserMetadata[s3MetaRetentionUntil]
		if raw == "" {
			continue // 永久保留,不删
		}
		until, perr := time.Parse(time.RFC3339, raw)
		if perr != nil || !until.UTC().Before(cutoff) {
			continue
		}
		if rmErr := s.client.RemoveObject(ctx, s.bucket, obj.Key, minio.RemoveObjectOptions{}); rmErr == nil {
			deleted++
		}
	}
	if s.localFallback != nil {
		if n, err := s.localFallback.ReapExpired(ctx, now); err == nil {
			deleted += n
		}
	}
	return deleted, nil
}

func s3InfoToMetadata(key, tenantID string, info minio.ObjectInfo) ObjectMetadata {
	m := ObjectMetadata{
		Key:            key,
		TenantID:       tenantID,
		ContentType:    info.ContentType,
		Size:           info.Size,
		SHA256:         info.UserMetadata[s3MetaSHA256],
		StorageBackend: "s3",
		CreatedAt:      info.LastModified.UTC(),
	}
	if raw := info.UserMetadata[s3MetaRetentionUntil]; raw != "" {
		if until, err := time.Parse(time.RFC3339, raw); err == nil {
			m.RetentionUntil = until.UTC()
		}
	}
	return m
}

// Ping 测试连接(供控制台"测试连接"用):确认 bucket 可达。
func (s *S3Store) Ping(ctx context.Context) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("s3 store is nil")
	}
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("reach s3 bucket: %w", err)
	}
	if !exists {
		return fmt.Errorf("s3 bucket %q not found", s.bucket)
	}
	return nil
}
