package catalog

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

// Keep the upstream IP pin even when a configured customer proxy handles CONNECT.
// Only the connection destination changes; Host, TLS SNI and certificate checking
// still use the validated original domain. The proxy cannot re-resolve upstream.
func anthropicPinnedProxyClient(base *http.Transport, target safetarget.Target, rawProxy string) (*http.Client, error) {
	proxy, err := parseConfiguredOutboundProxyURL(rawProxy)
	if err != nil {
		return nil, err
	}
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	transport := base.Clone()
	transport.Proxy = http.ProxyURL(proxy)
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = dialer.DialContext
	transport.DialTLS = nil
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if transport.TLSClientConfig != nil {
		config = transport.TLSClientConfig.Clone()
	}
	config.InsecureSkipVerify = false
	config.ServerName = target.Hostname
	config.MinVersion = tls.VersionTLS12
	transport.TLSClientConfig = config
	// HTTPS proxy uses its own TLS identity; inner TLS still validates upstream.
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		raw, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		proxyTLS := config.Clone()
		proxyTLS.ServerName = proxy.Hostname()
		proxyTLS.NextProtos = []string{"http/1.1"}
		conn := tls.Client(raw, proxyTLS)
		if err = conn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return conn, nil
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &anthropicProxyTransport{transport: transport, target: target}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return safetarget.ErrRedirectNotAllowed }}, nil
}

type anthropicProxyTransport struct {
	transport *http.Transport
	target    safetarget.Target
}

func (t *anthropicProxyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.target.URL == nil || request.URL.Scheme != "https" || request.URL.Host != t.target.URL.Host {
		return nil, errors.New("anthropic proxy target changed")
	}
	pinned := request.Clone(request.Context())
	pinned.URL.Host = t.target.DialAddress
	pinned.Host = t.target.URL.Host
	return t.transport.RoundTrip(pinned)
}
