package handler

import (
	"net/http"
	"net/url"
	"strings"
)

const (
	mcpAllowedMethods = "GET, POST, DELETE, OPTIONS"
	mcpAllowedHeaders = "Authorization, Content-Type, MCP-Protocol-Version, MCP-Session-Id, Last-Event-ID"
	mcpExposedHeaders = "MCP-Protocol-Version, MCP-Session-Id"
)

func normalizeMCPOrigin(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", false
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", false
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), true
}

func (h *MCPProxyHandler) SetAllowedOrigins(origins []string) {
	allowed := make(map[string]struct{}, len(origins))
	for _, raw := range origins {
		if origin, ok := normalizeMCPOrigin(raw); ok {
			allowed[origin] = struct{}{}
		}
	}
	h.allowedOrigins = allowed
}

func (h *MCPProxyHandler) mcpOriginAllowed(raw string) (string, bool) {
	origin, ok := normalizeMCPOrigin(raw)
	if !ok {
		return "", false
	}
	_, ok = h.allowedOrigins[origin]
	return origin, ok
}

// OriginMiddleware enforces the MCP Streamable HTTP DNS-rebinding requirement.
// Native clients omit Origin and remain supported. Browser origins are exact-match
// only; an empty allowlist therefore rejects every browser-originated MCP request.
func (h *MCPProxyHandler) OriginMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawOrigin := strings.TrimSpace(r.Header.Get("Origin"))
		if rawOrigin == "" {
			if r.Method == http.MethodOptions {
				writeMCPHTTPError(w, http.StatusBadRequest, "MCP browser preflight is missing Origin")
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		origin, allowed := h.mcpOriginAllowed(rawOrigin)
		if !allowed {
			writeMCPHTTPError(w, http.StatusForbidden, "MCP browser Origin is not allowed")
			return
		}

		w.Header().Add("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", mcpAllowedMethods)
		w.Header().Set("Access-Control-Allow-Headers", mcpAllowedHeaders)
		w.Header().Set("Access-Control-Expose-Headers", mcpExposedHeaders)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
