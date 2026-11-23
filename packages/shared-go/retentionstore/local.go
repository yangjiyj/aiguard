package retentionstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

type LocalStore struct {
	root string
}

func NewLocalStore(root string) (*LocalStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("retention store root is required")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve retention store root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(absRoot, ".tmp"), 0o700); err != nil {
		return nil, fmt.Errorf("create retention store root: %w", err)
	}
	return &LocalStore{root: absRoot}, nil
}

func (s *LocalStore) PutObject(ctx context.Context, input PutObjectInput) (ObjectMetadata, error) {
	if err := checkContext(ctx); err != nil {
		return ObjectMetadata{}, err
	}
	if s == nil {
		return ObjectMetadata{}, fmt.Errorf("retention store is nil")
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
	dataPath, err := s.objectDataPath(tenantID, key)
	if err != nil {
		return ObjectMetadata{}, err
	}
	if err := os.MkdirAll(filepath.Dir(dataPath), 0o700); err != nil {
		return ObjectMetadata{}, fmt.Errorf("create retention object directory: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Join(s.root, ".tmp"), "put-*")
	if err != nil {
		return ObjectMetadata{}, fmt.Errorf("create retention temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	hash := sha256.New()
	written, copyErr := io.Copy(tmp, io.TeeReader(input.Reader, hash))
	closeErr := tmp.Close()
	if copyErr != nil {
		return ObjectMetadata{}, fmt.Errorf("write retention object: %w", copyErr)
	}
	if closeErr != nil {
		return ObjectMetadata{}, fmt.Errorf("close retention temp object: %w", closeErr)
	}
	if err := os.Rename(tmpName, dataPath); err != nil {
		return ObjectMetadata{}, fmt.Errorf("store retention object: %w", err)
	}

	contentType := strings.TrimSpace(input.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	now := time.Now().UTC()
	metadata := ObjectMetadata{
		Key:             key,
		TenantID:        tenantID,
		RequestID:       strings.TrimSpace(input.RequestID),
		Stage:           strings.TrimSpace(input.Stage),
		FieldName:       strings.TrimSpace(input.FieldName),
		FileName:        strings.TrimSpace(input.FileName),
		ContentType:     contentType,
		Size:            written,
		SHA256:          hex.EncodeToString(hash.Sum(nil)),
		StorageBackend:  StorageBackendLocal,
		RetentionUntil:  input.RetentionUntil.UTC(),
		CreatedAt:       now,
		RedactionStatus: "externalized",
	}
	if err := s.writeMetadata(dataPath, metadata); err != nil {
		_ = os.Remove(dataPath)
		return ObjectMetadata{}, err
	}
	return metadata, nil
}

func (s *LocalStore) GetObject(ctx context.Context, tenantID, key string) (Object, error) {
	if err := checkContext(ctx); err != nil {
		return Object{}, err
	}
	dataPath, err := s.objectDataPath(tenantID, key)
	if err != nil {
		return Object{}, err
	}
	metadata, err := s.readMetadata(dataPath)
	if err != nil {
		return Object{}, err
	}
	body, err := os.Open(dataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Object{}, ErrObjectNotFound
		}
		return Object{}, fmt.Errorf("open retention object: %w", err)
	}
	return Object{Metadata: metadata, Body: body}, nil
}

func (s *LocalStore) DeleteObject(ctx context.Context, tenantID, key string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	dataPath, err := s.objectDataPath(tenantID, key)
	if err != nil {
		return err
	}
	dataErr := os.Remove(dataPath)
	metaErr := os.Remove(metadataPath(dataPath))
	if os.IsNotExist(dataErr) && os.IsNotExist(metaErr) {
		return ErrObjectNotFound
	}
	if dataErr != nil && !os.IsNotExist(dataErr) {
		return fmt.Errorf("delete retention object: %w", dataErr)
	}
	if metaErr != nil && !os.IsNotExist(metaErr) {
		return fmt.Errorf("delete retention object metadata: %w", metaErr)
	}
	return nil
}

// ReapExpired 删除 retention_until 已过期的对象(数据文件+sidecar),返回删除的对象数。
// WORM 红线:retention_until 为零值(未设留存期=永久保留)的对象永不删,只清严格超过
// 留存期(retention_until < now)的对象,与 access_content_logs 的 DB 清理同口径。
// 幂等、对并发 reaper/删除安全(忽略 not-exist),单个坏 sidecar 不中断整轮。
func (s *LocalStore) ReapExpired(ctx context.Context, now time.Time) (int, error) {
	if s == nil {
		return 0, fmt.Errorf("retention store is nil")
	}
	cutoff := now.UTC()
	tmpDir := filepath.Join(s.root, ".tmp")
	deleted := 0
	walkErr := filepath.WalkDir(s.root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p == tmpDir {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".json") {
			return nil
		}
		if err := checkContext(ctx); err != nil {
			return err
		}
		raw, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil
		}
		var meta ObjectMetadata
		if json.Unmarshal(raw, &meta) != nil {
			return nil
		}
		// 只清"超过留存期"的对象;零值=永久保留,绝不删。
		if meta.RetentionUntil.IsZero() || !meta.RetentionUntil.UTC().Before(cutoff) {
			return nil
		}
		dataPath := strings.TrimSuffix(p, ".json")
		_ = os.Remove(dataPath)
		if rmErr := os.Remove(p); rmErr == nil || os.IsNotExist(rmErr) {
			deleted++
		}
		return nil
	})
	if walkErr != nil {
		return deleted, fmt.Errorf("reap retention store: %w", walkErr)
	}
	return deleted, nil
}

func (s *LocalStore) writeMetadata(dataPath string, metadata ObjectMetadata) error {
	raw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal retention metadata: %w", err)
	}
	if err := os.WriteFile(metadataPath(dataPath), append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("write retention metadata: %w", err)
	}
	return nil
}

func (s *LocalStore) readMetadata(dataPath string) (ObjectMetadata, error) {
	raw, err := os.ReadFile(metadataPath(dataPath))
	if err != nil {
		if os.IsNotExist(err) {
			return ObjectMetadata{}, ErrObjectNotFound
		}
		return ObjectMetadata{}, fmt.Errorf("read retention metadata: %w", err)
	}
	var metadata ObjectMetadata
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return ObjectMetadata{}, fmt.Errorf("decode retention metadata: %w", err)
	}
	return metadata, nil
}

func (s *LocalStore) objectDataPath(tenantID, key string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("retention store is nil")
	}
	if strings.TrimSpace(tenantID) == "" {
		return "", fmt.Errorf("tenant id is required")
	}
	if err := validateObjectKey(key); err != nil {
		return "", err
	}
	parts := strings.Split(key, "/")
	if parts[0] != safeComponent(tenantID, "tenant") {
		return "", fmt.Errorf("%w: key tenant does not match caller", ErrObjectAccessDenied)
	}
	dataPath := filepath.Join(s.root, filepath.FromSlash(key))
	rel, err := filepath.Rel(s.root, dataPath)
	if err != nil {
		return "", fmt.Errorf("resolve retention object path: %w", err)
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: %s", ErrInvalidObjectKey, key)
	}
	return dataPath, nil
}

func validateObjectKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" || path.IsAbs(key) || filepath.IsAbs(key) || strings.Contains(key, "\\") {
		return fmt.Errorf("%w: %s", ErrInvalidObjectKey, key)
	}
	clean := path.Clean(key)
	if clean != key || clean == "." {
		return fmt.Errorf("%w: %s", ErrInvalidObjectKey, key)
	}
	for _, part := range strings.Split(key, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("%w: %s", ErrInvalidObjectKey, key)
		}
	}
	return nil
}

func metadataPath(dataPath string) string {
	return dataPath + ".json"
}

func safeComponent(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '_', r == '-', r == '.':
			builder.WriteRune(r)
		default:
			builder.WriteByte('_')
		}
	}
	safe := strings.Trim(builder.String(), ".")
	if safe == "" {
		return fallback
	}
	return safe
}
