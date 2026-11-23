package retentionstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLocalStoreRejectsCrossTenantAndTraversal(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}

	metadata, err := store.PutObject(context.Background(), PutObjectInput{
		TenantID:       "tenant_a",
		RequestID:      "req_1",
		Stage:          "response",
		FieldName:      "file",
		ContentType:    "text/plain",
		RetentionUntil: time.Now().UTC().Add(time.Hour),
		Reader:         strings.NewReader("secret"),
	})
	if err != nil {
		t.Fatalf("PutObject returned error: %v", err)
	}

	if _, err := store.GetObject(context.Background(), "tenant_b", metadata.Key); !errors.Is(err, ErrObjectAccessDenied) {
		t.Fatalf("cross tenant GetObject error = %v, want ErrObjectAccessDenied", err)
	}
	if _, err := store.GetObject(context.Background(), "tenant_a", "../"+metadata.Key); !errors.Is(err, ErrInvalidObjectKey) {
		t.Fatalf("traversal GetObject error = %v, want ErrInvalidObjectKey", err)
	}
	if err := store.DeleteObject(context.Background(), "tenant_b", metadata.Key); !errors.Is(err, ErrObjectAccessDenied) {
		t.Fatalf("cross tenant DeleteObject error = %v, want ErrObjectAccessDenied", err)
	}
}

func TestLocalStoreDeleteObjectRemovesContent(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}

	metadata, err := store.PutObject(context.Background(), PutObjectInput{
		TenantID:       "tenant_default",
		RequestID:      "req_delete",
		Stage:          "request",
		FieldName:      "payload",
		ContentType:    "application/json",
		RetentionUntil: time.Now().UTC().Add(time.Hour),
		Reader:         strings.NewReader(`{"ok":true}`),
	})
	if err != nil {
		t.Fatalf("PutObject returned error: %v", err)
	}
	if err := store.DeleteObject(context.Background(), "tenant_default", metadata.Key); err != nil {
		t.Fatalf("DeleteObject returned error: %v", err)
	}
	if _, err := store.GetObject(context.Background(), "tenant_default", metadata.Key); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("GetObject after delete error = %v, want ErrObjectNotFound", err)
	}
}
