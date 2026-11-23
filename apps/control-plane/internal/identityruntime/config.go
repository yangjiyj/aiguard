package identityruntime

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
)

const defaultRuntimeURL = "http://chat-idp:8180/sso"

type ConfigInput struct {
	PublicURL              string
	RuntimeURL             string
	AllowedRuntimeURLs     string
	ClientID               string
	ClientSecret           string
	AllowInsecurePublicURL bool
}

type Config struct {
	// PublicURL 是对外 SSO 基址；各身份源回调用 CallbackURLForAlias(PublicURL, alias)。
	PublicURL    string
	RuntimeURL   string
	CallbackURL  string
	IssuerURL    string
	clientID     string
	clientSecret string
}

func (c Config) String() string {
	return fmt.Sprintf("identityruntime.Config{PublicURL:%q RuntimeURL:%q CallbackURL:%q IssuerURL:%q ClientID:%q Credentials:[redacted]}",
		c.PublicURL, c.RuntimeURL, c.CallbackURL, c.IssuerURL, c.clientID)
}

func (c Config) GoString() string {
	return c.String()
}

func LoadConfig(input ConfigInput) (Config, error) {
	publicURL, err := parsePublicURL(input.PublicURL, input.AllowInsecurePublicURL)
	if err != nil {
		return Config{}, err
	}
	runtimeURL, err := parseRuntimeURL(input.RuntimeURL, input.AllowedRuntimeURLs)
	if err != nil {
		return Config{}, err
	}
	if strings.TrimSpace(input.ClientID) == "" || strings.TrimSpace(input.ClientSecret) == "" {
		return Config{}, ErrRuntimeCredentialsRequired
	}
	publicBase := strings.TrimSuffix(publicURL.String(), "/")
	return Config{
		PublicURL:    publicBase,
		RuntimeURL:   strings.TrimSuffix(runtimeURL.String(), "/"),
		CallbackURL:  CallbackURLForAlias(publicBase, ProviderAlias),
		IssuerURL:    publicBase + "/sso/realms/" + RealmName,
		clientID:     input.ClientID,
		clientSecret: input.ClientSecret,
	}, nil
}

func parsePublicURL(raw string, allowInsecure bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrInvalidPublicURL
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, ErrInvalidPublicURL
	}
	if parsed.Scheme != "https" && !(allowInsecure && parsed.Scheme == "http") {
		return nil, ErrInvalidPublicURL
	}
	parsed.Path = ""
	return parsed, nil
}

func parseRuntimeURL(raw, rawAllowedURLs string) (*url.URL, error) {
	runtimeURL := strings.TrimSpace(raw)
	if runtimeURL == defaultRuntimeURL {
		return url.Parse(runtimeURL)
	}
	parsed, err := parseAllowedHTTPSRuntimeURL(runtimeURL)
	if err != nil {
		return nil, ErrInvalidRuntimeTarget
	}
	matched := false
	for _, candidate := range strings.Split(rawAllowedURLs, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		allowedURL, allowedErr := parseAllowedHTTPSRuntimeURL(candidate)
		if allowedErr != nil {
			return nil, ErrInvalidRuntimeTarget
		}
		if runtimeURL == allowedURL.String() {
			matched = true
		}
	}
	if !matched {
		return nil, ErrInvalidRuntimeTarget
	}
	return parsed, nil
}

func parseAllowedHTTPSRuntimeURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, ErrInvalidRuntimeTarget
	}
	hostname := strings.ToLower(parsed.Hostname())
	if raw == "" || parsed.Scheme != "https" || parsed.Host == "" || hostname == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" ||
		parsed.RawPath != "" || net.ParseIP(hostname) != nil || hostname == "localhost" ||
		strings.HasSuffix(hostname, ".localhost") || (parsed.Path != "" && path.Clean(parsed.Path) != parsed.Path) {
		return nil, ErrInvalidRuntimeTarget
	}
	return parsed, nil
}
