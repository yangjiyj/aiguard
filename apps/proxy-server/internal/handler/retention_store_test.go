package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

type fakeRetentionStore struct {
	putCalls int
	input    retentionstore.PutObjectInput
	body     string
	err      error
}

func (f *fakeRetentionStore) PutObject(ctx context.Context, input retentionstore.PutObjectInput) (retentionstore.ObjectMetadata, error) {
	f.putCalls++
	f.input = input
	if input.Reader != nil {
		body, _ := io.ReadAll(input.Reader)
		f.body = string(body)
	}
	if f.err != nil {
		return retentionstore.ObjectMetadata{}, f.err
	}
	key := fmt.Sprintf("%s/%s/%s/%s/object-%d", input.TenantID, input.RequestID, input.Stage, input.FieldName, f.putCalls)
	return retentionstore.ObjectMetadata{
		Key:            key,
		TenantID:       input.TenantID,
		RequestID:      input.RequestID,
		Stage:          input.Stage,
		FieldName:      input.FieldName,
		FileName:       input.FileName,
		ContentType:    input.ContentType,
		Size:           int64(len(f.body)),
		SHA256:         "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		StorageBackend: retentionstore.StorageBackendLocal,
		RetentionUntil: input.RetentionUntil,
	}, nil
}

func (f *fakeRetentionStore) GetObject(ctx context.Context, tenantID, key string) (retentionstore.Object, error) {
	return retentionstore.Object{
		Metadata: retentionstore.ObjectMetadata{Key: key, TenantID: tenantID},
		Body:     io.NopCloser(bytes.NewBufferString(f.body)),
	}, nil
}

func (f *fakeRetentionStore) DeleteObject(ctx context.Context, tenantID, key string) error {
	return nil
}

func (f *fakeRetentionStore) ReapExpired(ctx context.Context, now time.Time) (int, error) {
	return 0, nil
}

func TestExternalizeRetainedAttachmentDataStoresBase64AsObjectReference(t *testing.T) {
	store := &fakeRetentionStore{}
	record := ProxyAuditRecord{TenantID: "tenant_default", RequestID: "req_image"}
	retentionUntil := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	items := []retainedAttachmentMetadata{{
		Source:      "json_data_url",
		Stage:       "response",
		FieldName:   "content.image",
		ContentType: "image/png",
		DataBase64:  "aGVsbG8=",
		TextPreview: "hello preview",
	}}

	got := externalizeRetainedAttachmentData(context.Background(), store, record, retentionUntil, items)

	if store.putCalls != 1 {
		t.Fatalf("PutObject calls = %d, want 1", store.putCalls)
	}
	if store.input.TenantID != "tenant_default" || store.input.RequestID != "req_image" || store.input.Stage != "response" || store.input.FieldName != "content.image" {
		t.Fatalf("PutObject input lost trace context: %+v", store.input)
	}
	if store.body != "hello" {
		t.Fatalf("stored body = %q, want hello", store.body)
	}
	if len(got) != 1 {
		t.Fatalf("metadata count = %d, want 1", len(got))
	}
	meta := got[0]
	if meta.DataBase64 != "" {
		t.Fatalf("externalized metadata should not keep data_base64: %+v", meta)
	}
	if meta.ObjectKey == "" || meta.StorageBackend != retentionstore.StorageBackendLocal {
		t.Fatalf("object reference missing: %+v", meta)
	}
	if meta.SHA256 == "" || meta.Size != int64(len("hello")) || meta.ContentType != "image/png" {
		t.Fatalf("object metadata mismatch: %+v", meta)
	}
	if meta.RetentionUntil != retentionUntil.Format(time.RFC3339) {
		t.Fatalf("retention_until = %q", meta.RetentionUntil)
	}
}

func TestExternalizeRetainedAttachmentDataLeavesReferenceOnlyMetadataAlone(t *testing.T) {
	store := &fakeRetentionStore{}
	items := []retainedAttachmentMetadata{{Source: "estuary_content_reference", Stage: "request", ReferenceID: "file_123", ContentType: "reference/file-id"}}

	got := externalizeRetainedAttachmentData(context.Background(), store, ProxyAuditRecord{TenantID: "tenant_default", RequestID: "req_ref"}, time.Now().UTC(), items)

	if store.putCalls != 0 {
		t.Fatalf("reference-only metadata should not call PutObject, got %d calls", store.putCalls)
	}
	if got[0].ReferenceID != "file_123" || got[0].DataBase64 != "" || got[0].ObjectKey != "" {
		t.Fatalf("reference-only metadata changed unexpectedly: %+v", got[0])
	}
}

func TestExternalizeRetainedAttachmentDataScrubsBase64WhenStoreFails(t *testing.T) {
	store := &fakeRetentionStore{err: errors.New("disk full")}
	items := []retainedAttachmentMetadata{{Source: "multipart", Stage: "request", FieldName: "file", FileName: "secret.env", ContentType: "text/plain", DataBase64: "c2VjcmV0"}}

	got := externalizeRetainedAttachmentData(context.Background(), store, ProxyAuditRecord{TenantID: "tenant_default", RequestID: "req_fail"}, time.Now().UTC(), items)

	if got[0].DataBase64 != "" {
		t.Fatalf("failed externalization must not keep raw base64: %+v", got[0])
	}
	if got[0].ObjectKey != "" || !strings.Contains(got[0].RetentionStatus, "failed") {
		t.Fatalf("failed externalization status missing: %+v", got[0])
	}
}
