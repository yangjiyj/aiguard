package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
)

// ModelsHandler projects only the existing tenant/user/project/key-authorized
// model list. Its source omits capability facts, so this response deliberately
// makes no generateContent capability claim for embedding/image-only models.
func (h *GeminiIngressHandler) ModelsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		if err := normalizeGeminiCredential(clone); err != nil {
			writeGeminiError(w, 400, err.Error())
			return
		}
		query := r.URL.Query()
		if _, exists := query["key"]; exists {
			query.Del("key")
			r.URL.RawQuery = query.Encode()
			r.RequestURI = r.URL.RequestURI()
			writeGeminiError(w, 400, "API keys in URLs are not supported; use X-Goog-Api-Key or Authorization.")
			return
		}
		for key, values := range query {
			if (key != "pageSize" && key != "pageToken") || len(values) != 1 {
				writeGeminiError(w, 400, "Unsupported Google models query field.")
				return
			}
		}
		size := 1000
		if raw := query.Get("pageSize"); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 || value > 1000 {
				writeGeminiError(w, 400, "pageSize must be between 1 and 1000.")
				return
			}
			size = value
		}
		offset := 0
		if token := query.Get("pageToken"); token != "" {
			raw, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil || len(raw) > 12 {
				writeGeminiError(w, 400, "Invalid pageToken.")
				return
			}
			value, err := strconv.Atoi(string(raw))
			if err != nil || value < 0 {
				writeGeminiError(w, 400, "Invalid pageToken.")
				return
			}
			offset = value
		}
		if h.protectedModels == nil {
			writeGeminiError(w, 503, "Google model catalog is unavailable.")
			return
		}
		original := *r.URL
		clone.URL = &original
		clone.URL.Path = "/v1/models"
		clone.URL.RawPath = ""
		clone.URL.RawQuery = ""
		clone.RequestURI = clone.URL.RequestURI()
		captured := &geminiCapture{header: make(http.Header)}
		h.protectedModels.ServeHTTP(captured, clone)
		if captured.overflow {
			writeGeminiError(w, 502, "Model catalog exceeds bounded buffer.")
			return
		}
		if captured.status >= 400 {
			writeGeminiError(w, captured.status, "Model catalog is unavailable or access was denied.")
			return
		}
		var source struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(captured.body.Bytes(), &source) != nil || source.Data == nil {
			writeGeminiError(w, 502, "Invalid authorized model catalog.")
			return
		}
		if offset > len(source.Data) {
			writeGeminiError(w, 400, "Invalid pageToken.")
			return
		}
		end := offset + min(size, len(source.Data)-offset)
		models := []any{}
		for _, model := range source.Data[offset:end] {
			models = append(models, map[string]any{"name": "models/" + model.ID, "displayName": model.ID})
		}
		result := map[string]any{"models": models}
		if end < len(source.Data) {
			result["nextPageToken"] = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(result)
	}
}
