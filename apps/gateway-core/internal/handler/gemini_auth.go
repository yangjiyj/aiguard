package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// GeminiAuthentication runs the existing data-plane authorization before body
// reads, using its canonical scope path. The authenticated context is retained
// when the original Google URL is restored for the strict protocol translator.
func GeminiAuthentication(authenticate func(http.Handler) http.Handler, next http.Handler, catalog bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		if err := normalizeGeminiCredential(clone); err != nil {
			writeGeminiError(w, 400, err.Error())
			return
		}
		original := *r.URL
		canonical := original
		canonical.Path = "/v1/chat/completions"
		if catalog {
			canonical.Path = "/v1/models"
		}
		canonical.RawPath = ""
		canonical.RawQuery = ""
		clone.URL = &canonical
		clone.RequestURI = canonical.RequestURI()
		restore := http.HandlerFunc(func(w http.ResponseWriter, authed *http.Request) {
			restored := authed.Clone(authed.Context())
			restored.URL = &original
			restored.RequestURI = original.RequestURI()
			next.ServeHTTP(w, restored)
		})
		captured := &geminiAuthResponse{ResponseWriter: w}
		authenticate(restore).ServeHTTP(captured, clone)
		if captured.status >= 400 {
			message := "Gateway authentication or model access was denied."
			var payload struct {
				Error struct {
					Message string `json:"message"`
				}
			}
			if !captured.overflow && json.Unmarshal(captured.errorBody.Bytes(), &payload) == nil && payload.Error.Message != "" {
				message = payload.Error.Message
			}
			writeGeminiError(w, captured.status, message)
		}
	})
}

type geminiAuthResponse struct {
	http.ResponseWriter
	status    int
	errorBody bytes.Buffer
	overflow  bool
}

func (w *geminiAuthResponse) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	if status < 400 {
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *geminiAuthResponse) Write(raw []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	if w.status < 400 {
		return w.ResponseWriter.Write(raw)
	}
	if len(raw) > 65536-w.errorBody.Len() {
		w.overflow = true
		return len(raw), nil
	}
	return w.errorBody.Write(raw)
}
func (w *geminiAuthResponse) Flush() {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	if w.status < 400 {
		if f, ok := w.ResponseWriter.(http.Flusher); ok {
			f.Flush()
		}
	}
}
