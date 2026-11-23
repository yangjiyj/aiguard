package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/jpeg"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"

	_ "image/gif"
	_ "image/png"
)

func externalizeRetainedAttachmentData(ctx context.Context, store retentionstore.Store, record ProxyAuditRecord, retentionUntil time.Time, items []retainedAttachmentMetadata) []retainedAttachmentMetadata {
	out := make([]retainedAttachmentMetadata, len(items))
	copy(out, items)
	for i := range out {
		rawBase64 := strings.TrimSpace(out[i].DataBase64)
		if rawBase64 == "" {
			if out[i].DownloadURL != "" && out[i].ObjectKey == "" && out[i].RetentionStatus == "" {
				out[i].RetentionStatus = "reference_only"
			}
			if out[i].Size > maxAttachmentContextBytes && out[i].ObjectKey == "" && out[i].RetentionStatus == "" {
				out[i].RetentionStatus = "oversize_unretained"
			}
			if out[i].ObjectKey == "" && out[i].RetentionStatus == "" {
				out[i].RetentionStatus = "reference_only"
			}
			continue
		}
		out[i].DataBase64 = ""
		if store == nil {
			out[i].RetentionStatus = "externalize_unavailable"
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(rawBase64)
		if err != nil {
			out[i].RetentionStatus = "externalize_failed_decode"
			continue
		}
		metadata, err := store.PutObject(ctx, retentionstore.PutObjectInput{
			TenantID:       record.TenantID,
			RequestID:      record.RequestID,
			Stage:          out[i].Stage,
			FieldName:      out[i].FieldName,
			FileName:       out[i].FileName,
			ContentType:    out[i].ContentType,
			RetentionUntil: retentionUntil,
			Reader:         bytes.NewReader(decoded),
		})
		if err != nil {
			log.Printf("retention object externalize failed request_id=%s tenant_id=%s stage=%s field=%s: %v", record.RequestID, record.TenantID, out[i].Stage, out[i].FieldName, err)
			out[i].RetentionStatus = "externalize_failed"
			continue
		}
		applyObjectMetadata(&out[i], metadata)
	}
	return out
}

const maxFetchedAttachmentBytes = 16 << 20 // 16MB 上限,防超大对象拖垮留证写

var (
	retainedFetchOnce   sync.Once
	retainedFetchClient *http.Client
)

func retainedAttachmentFetchClient() *http.Client {
	retainedFetchOnce.Do(func() {
		retainedFetchClient = &http.Client{
			Transport: NewEgressGuard(nil, nil).HTTPTransport(), // SSRF 安全:挡私网/环回/链路本地
			Timeout:   8 * time.Second,
		}
	})
	return retainedFetchClient
}

// fetchRetainedAttachmentBytes 旁路抓引用式附件(json_file_url/json_image_url)的真字节:
// 走 egress 守卫(防 SSRF)+ 超时 + 大小上限;任何失败返回 nil(留证降级 url_only,不报错)。
// 可用 env RETENTION_FETCH_REFERENCE_BYTES=false 关闭。
func fetchRetainedAttachmentBytes(ctx context.Context, rawURL string) []byte {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("RETENTION_FETCH_REFERENCE_BYTES")), "false") {
		return nil
	}
	u := strings.TrimSpace(rawURL)
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := retainedAttachmentFetchClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxFetchedAttachmentBytes)+1))
	if err != nil || len(body) == 0 || len(body) > maxFetchedAttachmentBytes {
		return nil
	}
	return body
}

func resolveRetainedUploadMetadata(catalog *retainedUploadCatalog, tenant, provider string, items []retainedAttachmentMetadata) []retainedAttachmentMetadata {
	if catalog == nil || len(items) == 0 {
		return items
	}
	out := make([]retainedAttachmentMetadata, 0, len(items))
	seenReferences := map[string]int{}
	for _, item := range items {
		if item.ReferenceID != "" && item.ObjectKey != "" && item.RetentionStatus == "externalized" {
			catalog.put(tenant, provider, item)
		}
		if item.ReferenceID == "" || item.ObjectKey != "" {
			out = append(out, item)
			if item.ReferenceID != "" {
				seenReferences[strings.TrimSpace(item.ReferenceID)] = len(out) - 1
			}
			continue
		}
		uploaded, ok := catalog.get(tenant, provider, item.ReferenceID)
		if !ok {
			out = append(out, item)
			seenReferences[strings.TrimSpace(item.ReferenceID)] = len(out) - 1
			continue
		}
		item = mergeRetainedUploadMetadata(item, uploaded)
		if idx, ok := seenReferences[strings.TrimSpace(item.ReferenceID)]; ok {
			out[idx] = mergeRetainedUploadMetadata(out[idx], item)
			continue
		}
		out = append(out, item)
		seenReferences[strings.TrimSpace(item.ReferenceID)] = len(out) - 1
	}
	return out
}

func mergeRetainedUploadMetadata(base, uploaded retainedAttachmentMetadata) retainedAttachmentMetadata {
	base.ObjectKey = uploaded.ObjectKey
	base.StorageBackend = uploaded.StorageBackend
	base.RetentionUntil = uploaded.RetentionUntil
	base.RetentionStatus = uploaded.RetentionStatus
	if uploaded.FileName != "" {
		base.FileName = uploaded.FileName
	}
	if uploaded.ContentType != "" {
		base.ContentType = uploaded.ContentType
	}
	if uploaded.Size > 0 {
		base.Size = uploaded.Size
	}
	if uploaded.SHA256 != "" {
		base.SHA256 = uploaded.SHA256
	}
	if base.FieldName == "" {
		base.FieldName = uploaded.FieldName
	}
	if base.Source == "" {
		base.Source = uploaded.Source
	}
	if base.Stage == "" {
		base.Stage = uploaded.Stage
	}
	return base
}

func compressRetainedObjectBytes(item *retainedAttachmentMetadata, body []byte) []byte {
	if item == nil || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(item.ContentType)), "image/") {
		return body
	}
	img, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		return body
	}
	resized := resizeImageToMaxSide(img, retainedImageMaxSide())
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, resized, &jpeg.Options{Quality: retainedImageJPEGQuality()}); err != nil || buf.Len() == 0 {
		return body
	}
	item.ContentType = "image/jpeg"
	if strings.TrimSpace(item.FileName) != "" {
		item.FileName = replaceFileExtension(item.FileName, ".jpg")
	}
	return buf.Bytes()
}

func retainedImageMaxSide() int {
	return retentionEnvInt("RETENTION_IMAGE_MAX_SIDE", 1024, 128, 4096)
}

func retainedImageJPEGQuality() int {
	return retentionEnvInt("RETENTION_IMAGE_JPEG_QUALITY", 70, 30, 95)
}

func retentionEnvInt(key string, fallback, min, max int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < min || value > max {
		return fallback
	}
	return value
}

func resizeImageToMaxSide(src image.Image, maxSide int) image.Image {
	bounds := src.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	if maxSide <= 0 || width <= 0 || height <= 0 || (width <= maxSide && height <= maxSide) {
		return src
	}
	newWidth, newHeight := width, height
	if width >= height {
		newWidth = maxSide
		newHeight = maxSide * height / width
	} else {
		newHeight = maxSide
		newWidth = maxSide * width / height
	}
	if newWidth < 1 {
		newWidth = 1
	}
	if newHeight < 1 {
		newHeight = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))
	for y := 0; y < newHeight; y++ {
		sourceY := bounds.Min.Y + y*height/newHeight
		for x := 0; x < newWidth; x++ {
			sourceX := bounds.Min.X + x*width/newWidth
			dst.Set(x, y, src.At(sourceX, sourceY))
		}
	}
	return dst
}

func replaceFileExtension(fileName, ext string) string {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		return fileName
	}
	dot := strings.LastIndex(fileName, ".")
	if dot <= 0 {
		return fileName + ext
	}
	return fileName[:dot] + ext
}

func applyObjectMetadata(item *retainedAttachmentMetadata, metadata retentionstore.ObjectMetadata) {
	if item == nil {
		return
	}
	item.ObjectKey = metadata.Key
	item.StorageBackend = metadata.StorageBackend
	item.SHA256 = metadata.SHA256
	item.Size = metadata.Size
	if strings.TrimSpace(metadata.ContentType) != "" {
		item.ContentType = metadata.ContentType
	}
	if !metadata.RetentionUntil.IsZero() {
		item.RetentionUntil = metadata.RetentionUntil.UTC().Format(time.RFC3339)
	}
	item.RetentionStatus = "externalized"
}
