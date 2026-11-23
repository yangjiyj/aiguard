package retentionstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"
)

func TestLocalStorePutObjectPersistsMetadataAndContent(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}

	retentionUntil := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	metadata, err := store.PutObject(context.Background(), PutObjectInput{
		TenantID:       "tenant_default",
		RequestID:      "req_123",
		Stage:          "request",
		FieldName:      "attachments[0]",
		FileName:       "evidence.png",
		ContentType:    "image/png",
		RetentionUntil: retentionUntil,
		Reader:         strings.NewReader("hello"),
	})
	if err != nil {
		t.Fatalf("PutObject returned error: %v", err)
	}
	if metadata.Key == "" {
		t.Fatal("metadata key should be generated")
	}
	if !strings.Contains(metadata.Key, "tenant_default") || !strings.Contains(metadata.Key, "req_123") {
		t.Fatalf("metadata key should carry tenant and request context, got %q", metadata.Key)
	}
	if metadata.StorageBackend != StorageBackendLocal {
		t.Fatalf("storage backend = %q, want %q", metadata.StorageBackend, StorageBackendLocal)
	}
	if metadata.Size != int64(len("hello")) {
		t.Fatalf("size = %d, want %d", metadata.Size, len("hello"))
	}
	wantHash := sha256.Sum256([]byte("hello"))
	if metadata.SHA256 != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("sha256 = %q", metadata.SHA256)
	}
	if !metadata.RetentionUntil.Equal(retentionUntil) {
		t.Fatalf("retention_until = %s, want %s", metadata.RetentionUntil, retentionUntil)
	}

	object, err := store.GetObject(context.Background(), "tenant_default", metadata.Key)
	if err != nil {
		t.Fatalf("GetObject returned error: %v", err)
	}
	defer object.Body.Close()
	body, err := io.ReadAll(object.Body)
	if err != nil {
		t.Fatalf("ReadAll returned error: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("body = %q, want hello", string(body))
	}
	if object.Metadata.Key != metadata.Key || object.Metadata.TenantID != "tenant_default" {
		t.Fatalf("object metadata mismatch: %#v", object.Metadata)
	}
}
