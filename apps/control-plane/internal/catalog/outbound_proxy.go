package catalog

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type outboundProxyContextKey struct{}

// WithOutboundProxy carries the already decrypted global customer egress proxy
// through a catalog request without putting it in process-global environment.
func WithOutboundProxy(ctx context.Context, proxyURL string) context.Context {
	return context.WithValue(ctx, outboundProxyContextKey{}, strings.TrimSpace(proxyURL))
}

func outboundProxyURL(ctx context.Context) string {
	value, _ := ctx.Value(outboundProxyContextKey{}).(string)
	return strings.TrimSpace(value)
}

func httpClientWithOutboundProxy(base *http.Client, rawProxyURL string) (*http.Client, error) {
	if strings.TrimSpace(rawProxyURL) == "" {
		return base, nil
	}
	proxy, err := parseConfiguredOutboundProxyURL(rawProxyURL)
	if err != nil {
		return nil, err
	}
	if base == nil {
		base = &http.Client{}
	}
	copyClient := *base
	var transport *http.Transport
	if base.Transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		baseTransport, ok := base.Transport.(*http.Transport)
		if !ok {
			return nil, errors.New("outbound proxy requires an HTTP transport")
		}
		transport = baseTransport.Clone()
	}
	transport.Proxy = http.ProxyURL(proxy)
	copyClient.Transport = transport
	return &copyClient, nil
}

func parseConfiguredOutboundProxyURL(rawProxyURL string) (*url.URL, error) {
	proxy, err := url.Parse(strings.TrimSpace(rawProxyURL))
	if err != nil {
		return nil, errors.New("invalid outbound proxy URL")
	}
	proxy.Scheme = strings.ToLower(proxy.Scheme)
	if proxy.Scheme != "http" && proxy.Scheme != "https" {
		return nil, errors.New("outbound proxy must use HTTP or HTTPS")
	}
	if proxy.Host == "" || (proxy.Path != "" && proxy.Path != "/") || proxy.RawQuery != "" || proxy.Fragment != "" {
		return nil, errors.New("invalid outbound proxy URL")
	}
	return proxy, nil
}
