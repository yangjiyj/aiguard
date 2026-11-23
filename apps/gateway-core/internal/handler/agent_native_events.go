package handler

import (
	"bytes"
	"io"
	"mime"
	"net/http"
)

const nativeIdentityBodyLimit = 1 << 20

// nativeIdentityEvents forwards the native envelope byte-for-byte. Validation
// and the durable ACK belong to the independent control-plane native ledger.
func (g *AgentEndpointGateway) nativeIdentityEvents(w http.ResponseWriter, r *http.Request, token string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", 405)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "unexpected query", 400)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		http.Error(w, "application/json required", 415)
		return
	}
	if enc := r.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		http.Error(w, "unsupported content encoding", 415)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, nativeIdentityBodyLimit))
	if err != nil {
		http.Error(w, "invalid or oversized body", 413)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.controlURL+"/admin/v1/internal/agent/identity-events", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "native event forwarding unavailable", 502)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-JJDGuard-Internal-Token", g.secret)
	client := *g.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		http.Error(w, "native event forwarding failed", 502)
		return
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		http.Error(w, "native event redirect rejected", 502)
		return
	}
	output, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(output) > 64<<10 {
		http.Error(w, "invalid native event response", 502)
		return
	}
	if typ := response.Header.Get("Content-Type"); typ != "" {
		w.Header().Set("Content-Type", typ)
	}
	if retry := response.Header.Get("Retry-After"); retry != "" {
		w.Header().Set("Retry-After", retry)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(output)
}
