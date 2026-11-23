package config

import (
	"fmt"
	"net/url"
	"strings"
)

func parseMCPAllowedOrigins(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return []string{}, nil
	}
	origins := make([]string, 0)
	seen := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		parsed, err := url.Parse(strings.TrimSpace(item))
		if err != nil || parsed.Host == "" || parsed.User != nil ||
			parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(parsed.Host, "*") ||
			(!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) ||
			(parsed.Path != "" && parsed.Path != "/") {
			return nil, fmt.Errorf("MCP_ALLOWED_ORIGINS must contain exact http/https origins")
		}
		origin := strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
		if _, exists := seen[origin]; exists {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	return origins, nil
}
