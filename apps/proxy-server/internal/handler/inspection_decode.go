package handler

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"io"
	"mime"
	"mime/multipart"
	"strings"
)

// Retention previews have a small decoding limit. Inspection must never reuse
// that truncating projection as proof that the complete request was scanned.
func decodeInspectionBody(body []byte, encoding string) ([]byte, error) {
	layers := strings.Split(strings.ToLower(encoding), ",")
	for i := len(layers) - 1; i >= 0; i-- {
		var reader io.Reader
		var close func()
		switch strings.TrimSpace(layers[i]) {
		case "", "identity":
			continue
		case "gzip", "x-gzip":
			r, e := gzip.NewReader(bytes.NewReader(body))
			if e != nil {
				return nil, e
			}
			reader = r
			close = func() { _ = r.Close() }
		case "br":
			reader = brotli.NewReader(bytes.NewReader(body))
		case "zstd":
			r, e := zstd.NewReader(bytes.NewReader(body), zstd.WithDecoderMaxMemory(uint64(inspectionTransportLimit)))
			if e != nil {
				return nil, e
			}
			reader = r
			close = r.Close
		case "deflate":
			r, e := zlib.NewReader(bytes.NewReader(body))
			if e == nil {
				reader = r
				close = func() { _ = r.Close() }
			} else {
				f := flate.NewReader(bytes.NewReader(body))
				reader = f
				close = func() { _ = f.Close() }
			}
		default:
			return nil, fmt.Errorf("unsupported inspection encoding")
		}
		out, e := io.ReadAll(io.LimitReader(reader, inspectionTransportLimit+1))
		if close != nil {
			close()
		}
		if e != nil {
			return nil, e
		}
		if int64(len(out)) > inspectionTransportLimit {
			return nil, fmt.Errorf("decoded inspection capacity")
		}
		body = out
	}
	return body, nil
}
func restoreInspectionAttachmentBytes(extracted *ExtractedContent, body []byte, contentType string) {
	missing := map[string][]int{}
	for i, a := range extracted.Attachments {
		if a.DataBase64 == "" && a.SHA256 != "" {
			missing[a.SHA256] = append(missing[a.SHA256], i)
		}
	}
	if len(missing) == 0 {
		return
	}
	apply := func(raw []byte, encoded string) {
		h := sha256.Sum256(raw)
		for _, i := range missing[hex.EncodeToString(h[:])] {
			if encoded == "" {
				encoded = base64.StdEncoding.EncodeToString(raw)
			}
			extracted.Attachments[i].DataBase64 = encoded
		}
	}
	media, params, _ := mime.ParseMediaType(contentType)
	if strings.HasPrefix(media, "multipart/") {
		reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for {
			part, e := reader.NextPart()
			if e != nil {
				break
			}
			b, e := io.ReadAll(io.LimitReader(part, inspectionTransportLimit+1))
			_ = part.Close()
			if e == nil {
				apply(b, "")
			}
		}
		return
	}
	if json.Valid(body) {
		var value interface{}
		if json.Unmarshal(body, &value) != nil {
			return
		}
		var walk func(interface{})
		walk = func(v interface{}) {
			switch x := v.(type) {
			case map[string]interface{}:
				for _, item := range x {
					walk(item)
				}
			case []interface{}:
				for _, item := range x {
					walk(item)
				}
			case string:
				encoded := x
				if strings.HasPrefix(encoded, "data:") {
					if index := strings.Index(encoded, ","); index >= 0 {
						encoded = encoded[index+1:]
					}
				}
				if len(encoded) > maxAttachmentContextBytes {
					if raw, e := base64.StdEncoding.DecodeString(encoded); e == nil {
						apply(raw, encoded)
					}
				}
			}
		}
		walk(value)
		return
	}
	apply(body, "")
}
