package retentionartifact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

func testPNG(t *testing.T) []byte {
	t.Helper()
	var body bytes.Buffer
	if err := png.Encode(&body, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}

func TestWriterRetainsOriginalBytesAndSeparatesPreview(t *testing.T) {
	store, err := retentionstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	original := testPNG(t)
	writer := Writer{Store: store, MaxBytes: 1024 * 1024}
	result := writer.Retain(context.Background(), RetainInput{
		TenantID:  "tenant-a",
		RequestID: "request-a",
		Candidate: Candidate{
			Direction:    DirectionInput,
			Kind:         KindImage,
			DisplayName:  "../evidence\x00.png",
			DeclaredMIME: "text/plain",
			Payload:      bytes.NewReader(original),
		},
	})
	if result.Status != RetentionStatusRetained {
		t.Fatalf("status = %q, failure = %q", result.Status, result.FailureCode)
	}
	if result.MediaType != "image/png" || result.DisplayName != "evidence_.png" {
		t.Fatalf("sniffed metadata = %#v", result)
	}
	if result.OriginalObjectKey == "" || result.PreviewObjectKey == "" ||
		result.OriginalObjectKey == result.PreviewObjectKey {
		t.Fatalf("original and preview must be distinct: %#v", result)
	}

	object, err := store.GetObject(context.Background(), "tenant-a", result.OriginalObjectKey)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Body.Close()
	got, err := io.ReadAll(object.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) || object.Metadata.SHA256 != result.OriginalSHA256 {
		t.Fatalf("original mutated: bytes=%v meta=%#v result=%#v", bytes.Equal(got, original), object.Metadata, result)
	}
	preview, err := store.GetObject(context.Background(), "tenant-a", result.PreviewObjectKey)
	if err != nil {
		t.Fatal(err)
	}
	defer preview.Body.Close()
	previewBytes, err := io.ReadAll(preview.Body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(previewBytes, original) || preview.Metadata.ContentType != "image/jpeg" {
		t.Fatalf("preview did not remain a distinct derived object: %#v", preview.Metadata)
	}
}

func TestWriterReportsReferenceFailureAndOversizeWithoutPretendingRetention(t *testing.T) {
	store, err := retentionstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writer := Writer{Store: store, MaxBytes: 3}
	reference := writer.Retain(context.Background(), RetainInput{
		TenantID:  "tenant-a",
		Candidate: Candidate{Direction: DirectionInput, Kind: KindFile, ReferenceID: "file_123"},
	})
	if reference.Status != RetentionStatusReferenceOnly || reference.OriginalObjectKey != "" {
		t.Fatalf("reference result = %#v", reference)
	}
	oversize := writer.Retain(context.Background(), RetainInput{
		TenantID:  "tenant-a",
		Candidate: Candidate{Direction: DirectionInput, Kind: KindFile, Payload: strings.NewReader("four")},
	})
	if oversize.Status != RetentionStatusOversizeUnretained || oversize.OriginalObjectKey != "" {
		t.Fatalf("oversize result = %#v", oversize)
	}
	failed := (Writer{Store: failingStore{}, MaxBytes: 3}).Retain(context.Background(), RetainInput{
		TenantID:  "tenant-a",
		Candidate: Candidate{Direction: DirectionInput, Kind: KindFile, Payload: strings.NewReader("ok")},
	})
	if failed.Status != RetentionStatusFailed || failed.FailureCode != "store_write_failed" {
		t.Fatalf("failed result = %#v", failed)
	}
}

func TestWriterResultDoesNotSerializeObjectKeysOrUnsafeCandidateValues(t *testing.T) {
	result := Result{
		Status:            RetentionStatusFailed,
		OriginalObjectKey: "tenant/request/original",
		PreviewObjectKey:  "tenant/request/preview",
		FailureCode:       "store_write_failed",
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"original", "preview", "object_key"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("serialized result leaked %q: %s", forbidden, encoded)
		}
	}
}

type failingStore struct{}

func (failingStore) PutObject(context.Context, retentionstore.PutObjectInput) (retentionstore.ObjectMetadata, error) {
	return retentionstore.ObjectMetadata{}, errors.New("store unavailable")
}
func (failingStore) GetObject(context.Context, string, string) (retentionstore.Object, error) {
	return retentionstore.Object{}, errors.New("store unavailable")
}
func (failingStore) DeleteObject(context.Context, string, string) error {
	return errors.New("store unavailable")
}
func (failingStore) ReapExpired(context.Context, time.Time) (int, error) {
	return 0, errors.New("store unavailable")
}
