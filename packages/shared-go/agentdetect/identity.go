package agentdetect

import (
	"encoding/json"
	"net/http"
	"strings"
	"unicode"
)

// IdentityHeaders is an allowlisted audit observation, never an authentication claim.
// Do not retain Authorization, API keys, arbitrary headers, or prompt contents here.
func IdentityHeaders(h http.Header) string {
	d, err := DetectFromHeaders(h)
	if err != nil {
		return "{}"
	}
	name := h.Get("X-JJDGuard-Agent-Name")
	if name == "" {
		name = h.Get("X-Agent-Name")
	}
	rawType := ""
	for _, key := range []string{"X-JJDGuard-Agent-Type", "X-NewAPI-Agent-Type", "X-UAG-Agent-Type", "X-Agent-Type", "X-AI-Agent"} {
		if rawType = h.Get(key); rawType != "" {
			break
		}
	}
	observed := map[string]string{
		"user_agent":     BoundedIdentityValue(h.Get("User-Agent"), 512),
		"declared_name":  BoundedIdentityValue(name, 128),
		"declared_type":  BoundedIdentityValue(rawType, 128),
		"header_source":  d.Source,
		"header_product": d.Product,
		"header_role":    d.Role,
	}
	// Codex 官方客户端的 originator 头参与识别（DetectFromHeaders），一并留存，
	// 以后识别规则再补齐时历史行可以按它重新识别。没有这个头时保持原来的 6 个字段。
	if originator := BoundedIdentityValue(h.Get("Originator"), 128); originator != "" {
		observed["originator"] = originator
	}
	b, _ := json.Marshal(observed)
	return string(b)
}

func BoundedIdentityValue(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	chars := []rune(strings.TrimSpace(s))
	if len(chars) > limit {
		chars = chars[:limit]
	}
	return string(chars)
}
