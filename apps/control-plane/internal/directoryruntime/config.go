package directoryruntime

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
)

const defaultRuntimeURL = "http://chat-idp:8180/sso"

type ConfigInput struct {
	RuntimeURL         string
	AllowedRuntimeURLs string
	ClientID           string
	ClientSecret       string
}

type Config struct {
	RuntimeURL   string
	clientID     string
	clientSecret string
}

func (config Config) String() string {
	return fmt.Sprintf("directoryruntime.Config{RuntimeURL:%q ClientID:%q Credentials:[redacted]}", config.RuntimeURL, config.clientID)
}

func (config Config) GoString() string { return config.String() }

func LoadConfig(input ConfigInput) (Config, error) {
	runtimeURL, err := parseRuntimeURL(input.RuntimeURL, input.AllowedRuntimeURLs)
	if err != nil || strings.TrimSpace(input.ClientID) == "" || strings.TrimSpace(input.ClientSecret) == "" {
		return Config{}, ErrRuntimeUnavailable
	}
	return Config{
		RuntimeURL:   runtimeURL.String(),
		clientID:     strings.TrimSpace(input.ClientID),
		clientSecret: input.ClientSecret,
	}, nil
}

func (config Config) NewClient() (*Client, error) {
	if strings.TrimSpace(config.RuntimeURL) == "" || strings.TrimSpace(config.clientID) == "" || strings.TrimSpace(config.clientSecret) == "" {
		return nil, ErrRuntimeUnavailable
	}
	return newClient(clientOptions{RuntimeURL: config.RuntimeURL, ClientID: config.clientID, ClientSecret: config.clientSecret})
}

func parseRuntimeURL(raw, rawAllowedURLs string) (*url.URL, error) {
	runtimeURL := strings.TrimSpace(raw)
	if runtimeURL == defaultRuntimeURL {
		return url.Parse(runtimeURL)
	}

	parsed, err := parseAllowedHTTPSRuntimeURL(runtimeURL)
	if err != nil {
		return nil, ErrRuntimeUnavailable
	}
	matched := false
	for _, candidate := range strings.Split(rawAllowedURLs, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		allowedURL, allowedErr := parseAllowedHTTPSRuntimeURL(candidate)
		if allowedErr != nil {
			return nil, ErrRuntimeUnavailable
		}
		if runtimeURL == allowedURL.String() {
			matched = true
		}
	}
	if matched {
		return parsed, nil
	}
	return nil, ErrRuntimeUnavailable
}

func parseAllowedHTTPSRuntimeURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, ErrRuntimeUnavailable
	}
	hostname := strings.ToLower(parsed.Hostname())
	if raw == "" || parsed.Scheme != "https" || parsed.Host == "" || hostname == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" ||
		parsed.RawPath != "" || net.ParseIP(hostname) != nil || hostname == "localhost" ||
		strings.HasSuffix(hostname, ".localhost") || (parsed.Path != "" && path.Clean(parsed.Path) != parsed.Path) {
		return nil, ErrRuntimeUnavailable
	}
	return parsed, nil
}
