package retentionartifact

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

const defaultMaxBytes int64 = 20 * 1024 * 1024

type RetainInput struct {
	TenantID       string
	RequestID      string
	Provider       string
	RetentionUntil time.Time
	Candidate      Candidate
}

type Writer struct {
	Store    retentionstore.Store
	MaxBytes int64
}

func (w Writer) Retain(ctx context.Context, input RetainInput) Result {
	if input.Candidate.Payload == nil {
		return Result{Status: RetentionStatusReferenceOnly, DisplayName: sanitizeDisplayName(input.Candidate.DisplayName)}
	}
	if err := input.Candidate.Validate(); err != nil {
		return Result{Status: RetentionStatusFailed, FailureCode: "invalid_candidate"}
	}
	if w.Store == nil {
		return Result{Status: RetentionStatusFailed, FailureCode: "store_unavailable"}
	}
	limit := w.MaxBytes
	if limit <= 0 {
		limit = defaultMaxBytes
	}
	original, err := io.ReadAll(io.LimitReader(input.Candidate.Payload, limit+1))
	if err != nil {
		return Result{Status: RetentionStatusFailed, FailureCode: "payload_read_failed"}
	}
	if int64(len(original)) > limit {
		return Result{
			Status:      RetentionStatusOversizeUnretained,
			DisplayName: sanitizeDisplayName(input.Candidate.DisplayName),
		}
	}

	displayName := sanitizeDisplayName(input.Candidate.DisplayName)
	mediaType := sniffMIME(original)
	originalMeta, err := w.Store.PutObject(ctx, retentionstore.PutObjectInput{
		TenantID:       input.TenantID,
		RequestID:      input.RequestID,
		Stage:          "retention-original",
		FieldName:      string(input.Candidate.Direction),
		FileName:       displayName,
		ContentType:    mediaType,
		RetentionUntil: input.RetentionUntil,
		Reader:         bytes.NewReader(original),
	})
	if err != nil {
		return Result{Status: RetentionStatusFailed, FailureCode: "store_write_failed", DisplayName: displayName}
	}

	result := Result{
		Status:            RetentionStatusRetained,
		OriginalSHA256:    originalMeta.SHA256,
		ByteSize:          originalMeta.Size,
		MediaType:         originalMeta.ContentType,
		DisplayName:       displayName,
		OriginalObjectKey: originalMeta.Key,
		StorageBackend:    originalMeta.StorageBackend,
	}
	if input.Candidate.Kind == KindImage {
		if preview, ok := jpegPreview(original); ok {
			previewMeta, previewErr := w.Store.PutObject(ctx, retentionstore.PutObjectInput{
				TenantID:       input.TenantID,
				RequestID:      input.RequestID,
				Stage:          "retention-preview",
				FieldName:      string(input.Candidate.Direction),
				FileName:       previewName(displayName),
				ContentType:    "image/jpeg",
				RetentionUntil: input.RetentionUntil,
				Reader:         bytes.NewReader(preview),
			})
			if previewErr == nil {
				result.PreviewObjectKey = previewMeta.Key
			}
		}
	}
	return result
}

func sniffMIME(data []byte) string {
	if len(data) == 0 {
		return "application/octet-stream"
	}
	return http.DetectContentType(data)
}

func jpegPreview(original []byte) ([]byte, bool) {
	source, _, err := image.Decode(bytes.NewReader(original))
	if err != nil {
		return nil, false
	}
	var preview bytes.Buffer
	if err := jpeg.Encode(&preview, source, &jpeg.Options{Quality: 75}); err != nil {
		return nil, false
	}
	return preview.Bytes(), true
}

func sanitizeDisplayName(name string) string {
	name = strings.TrimSpace(strings.ReplaceAll(name, "\\", "/"))
	name = filepath.Base(name)
	if name == "." || name == "/" || name == "" {
		return "artifact"
	}
	var out strings.Builder
	for _, r := range name {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			out.WriteByte('_')
			continue
		}
		out.WriteRune(r)
	}
	safe := strings.TrimSpace(out.String())
	if safe == "" {
		return "artifact"
	}
	return safe
}

func previewName(name string) string {
	if name == "" {
		return "preview.jpg"
	}
	return strings.TrimSuffix(name, filepath.Ext(name)) + ".preview.jpg"
}

func (w Writer) String() string {
	return fmt.Sprintf("retention artifact writer (%d bytes)", w.MaxBytes)
}
