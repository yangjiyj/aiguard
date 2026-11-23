package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func streamingHTTPClientForReverseProxy(base *http.Client, target resolvedEgressTarget) *http.Client {
	client := streamingHTTPClientForResolvedEgress(base, target)
	var baseRedirect func(*http.Request, []*http.Request) error
	if base != nil {
		baseRedirect = base.CheckRedirect
	}
	client.CheckRedirect = restrictedRedirectPolicy(target, baseRedirect)
	return client
}

func restrictedRedirectPolicy(target resolvedEgressTarget, base func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		host := strings.Trim(strings.ToLower(req.URL.Hostname()), "[]")
		port, err := effectiveURLPort(req.URL)
		if err != nil || host != target.Host || port != target.Port {
			return fmt.Errorf("%w: cross-host redirect to %s", errUnsafeEgressTarget, req.URL.Redacted())
		}
		if base != nil {
			return base(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
}

func effectiveURLPort(value *url.URL) (int, error) {
	if value == nil {
		return 0, fmt.Errorf("redirect URL is nil")
	}
	if raw := value.Port(); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return 0, fmt.Errorf("invalid redirect port")
		}
		return port, nil
	}
	switch strings.ToLower(value.Scheme) {
	case "http":
		return 80, nil
	case "https":
		return 443, nil
	default:
		return 0, fmt.Errorf("unsupported redirect scheme")
	}
}
