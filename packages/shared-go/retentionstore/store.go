package retentionstore

import (
	"context"
	"errors"
	"io"
	"time"
)

const StorageBackendLocal = "local"

var (
	ErrObjectNotFound     = errors.New("retention object not found")
	ErrObjectAccessDenied = errors.New("retention object access denied")
	ErrInvalidObjectKey   = errors.New("invalid retention object key")
)

type PutObjectInput struct {
	TenantID       string
	RequestID      string
	Stage          string
	FieldName      string
	FileName       string
	ContentType    string
	RetentionUntil time.Time
	Reader         io.Reader
}

type ObjectMetadata struct {
	Key             string    `json:"object_key"`
	TenantID        string    `json:"tenant_id"`
	RequestID       string    `json:"request_id,omitempty"`
	Stage           string    `json:"stage,omitempty"`
	FieldName       string    `json:"field_name,omitempty"`
	FileName        string    `json:"file_name,omitempty"`
	ContentType     string    `json:"content_type"`
	Size            int64     `json:"size"`
	SHA256          string    `json:"sha256"`
	StorageBackend  string    `json:"storage_backend"`
	RetentionUntil  time.Time `json:"retention_until,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	RedactionStatus string    `json:"redaction_status,omitempty"`
}

type Object struct {
	Metadata ObjectMetadata
	Body     io.ReadCloser
}

type Store interface {
	PutObject(ctx context.Context, input PutObjectInput) (ObjectMetadata, error)
	GetObject(ctx context.Context, tenantID, key string) (Object, error)
	DeleteObject(ctx context.Context, tenantID, key string) error
	// ReapExpired 删除 retention_until 已过期的对象(WORM:零值=永久,绝不删),返回删除数。
	ReapExpired(ctx context.Context, now time.Time) (int, error)
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
