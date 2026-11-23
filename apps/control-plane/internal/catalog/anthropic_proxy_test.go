package catalog

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

func TestAnthropicProxyPinsCONNECTAndPreservesTLSHostname(t *testing.T) {
	for _, secureProxy := range []bool{false, true} {
		t.Run(fmt.Sprint(secureProxy), func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS.ServerName != "example.com" || r.Host != "example.com" || r.Header.Get("x-api-key") != "fixture-key" {
					t.Errorf("host/TLS/auth not preserved")
				}
				fmt.Fprint(w, `{"object":"list","data":[]}`)
			}))
			defer upstream.Close()
			pinned := upstream.Listener.Addr().String()
			seenConnect := make(chan string, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenConnect <- r.Host
				if r.Method != "CONNECT" || r.Host != pinned {
					t.Errorf("CONNECT was not IP pinned: %s %s", r.Method, r.Host)
					w.WriteHeader(403)
					return
				}
				dest, err := net.Dial("tcp", pinned)
				if err != nil {
					w.WriteHeader(502)
					return
				}
				client, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					dest.Close()
					return
				}
				fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go func() { defer dest.Close(); defer client.Close(); io.Copy(dest, client) }()
				go func() { defer dest.Close(); defer client.Close(); io.Copy(client, dest) }()
			})
			var proxy *httptest.Server
			if secureProxy {
				proxy = httptest.NewUnstartedServer(handler)
				proxy.EnableHTTP2 = true
				proxy.StartTLS()
			} else {
				proxy = httptest.NewServer(handler)
			}
			defer proxy.Close()
			targetURL, _ := url.Parse("https://example.com/v1/models")
			target := safetarget.Target{URL: targetURL, Hostname: "example.com", IP: netip.MustParseAddr("127.0.0.1"), DialAddress: pinned}
			base := upstream.Client().Transport.(*http.Transport)
			base.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
			client, err := anthropicPinnedProxyClient(base, target, proxy.URL)
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequestWithContext(context.Background(), "GET", targetURL.String(), nil)
			req.Header.Set("x-api-key", "fixture-key")
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 200 || <-seenConnect != pinned {
				t.Fatal("proxy request failed or hostname was re-resolved")
			}
		})
	}
}
