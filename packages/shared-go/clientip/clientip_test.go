package clientip

import (
	"net"
	"net/http"
	"testing"
)

func mustParseCIDRs(t *testing.T, raw string) []*net.IPNet {
	t.Helper()
	return parseCIDRs(raw)
}

func req(remoteAddr string, headers map[string]string) *http.Request {
	r := &http.Request{
		RemoteAddr: remoteAddr,
		Header:     http.Header{},
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestClientIPWithTrusted(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		trusted    string
		want       string
	}{
		{
			name:       "no XFF, returns RemoteAddr host",
			remoteAddr: "203.0.113.7:54321",
			headers:    nil,
			trusted:    "",
			want:       "203.0.113.7",
		},
		{
			name:       "spoofed XFF but peer untrusted -> RemoteAddr",
			remoteAddr: "203.0.113.7:54321",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4"},
			trusted:    "10.0.0.0/8",
			want:       "203.0.113.7",
		},
		{
			name:       "spoofed X-Real-IP but peer untrusted -> RemoteAddr",
			remoteAddr: "203.0.113.7:54321",
			headers:    map[string]string{"X-Real-IP": "1.2.3.4"},
			trusted:    "10.0.0.0/8",
			want:       "203.0.113.7",
		},
		{
			name:       "no trusted CIDRs configured -> always RemoteAddr even with XFF",
			remoteAddr: "10.0.0.5:1111",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8"},
			trusted:    "",
			want:       "10.0.0.5",
		},
		{
			name:       "peer trusted, single XFF hop -> that client",
			remoteAddr: "10.0.0.5:1111",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.23"},
			trusted:    "10.0.0.0/8",
			want:       "198.51.100.23",
		},
		{
			name:       "peer trusted, X-Real-IP -> that client",
			remoteAddr: "10.0.0.5:1111",
			headers:    map[string]string{"X-Real-IP": "198.51.100.23"},
			trusted:    "10.0.0.0/8",
			want:       "198.51.100.23",
		},
		{
			name:       "peer trusted, multi-hop with trailing trusted proxies -> rightmost untrusted",
			remoteAddr: "10.0.0.5:1111",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.23, 10.0.0.9, 10.0.0.8"},
			trusted:    "10.0.0.0/8",
			want:       "198.51.100.23",
		},
		{
			name:       "peer trusted, attacker prepends fake hop -> still rightmost untrusted (real client)",
			remoteAddr: "10.0.0.5:1111",
			headers:    map[string]string{"X-Forwarded-For": "9.9.9.9, 198.51.100.23, 10.0.0.9"},
			trusted:    "10.0.0.0/8",
			want:       "198.51.100.23",
		},
		{
			name:       "peer trusted, XFF entirely trusted proxies -> fallback to peer",
			remoteAddr: "10.0.0.5:1111",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.9, 10.0.0.8"},
			trusted:    "10.0.0.0/8",
			want:       "10.0.0.5",
		},
		{
			name:       "peer trusted via bare-IP entry, XFF hop honored",
			remoteAddr: "192.168.1.10:2222",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.23"},
			trusted:    "192.168.1.10",
			want:       "198.51.100.23",
		},
		{
			name:       "RemoteAddr without port (already bare host)",
			remoteAddr: "203.0.113.7",
			headers:    nil,
			trusted:    "",
			want:       "203.0.113.7",
		},
		{
			name:       "IPv6 RemoteAddr, no XFF",
			remoteAddr: "[2001:db8::1]:5555",
			headers:    nil,
			trusted:    "",
			want:       "2001:db8::1",
		},
		{
			name:       "IPv6 peer trusted, XFF hop honored",
			remoteAddr: "[2001:db8::1]:5555",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.23"},
			trusted:    "2001:db8::/32",
			want:       "198.51.100.23",
		},
		{
			name:       "empty/whitespace XFF, peer trusted -> peer",
			remoteAddr: "10.0.0.5:1111",
			headers:    map[string]string{"X-Forwarded-For": "  , "},
			trusted:    "10.0.0.0/8",
			want:       "10.0.0.5",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClientIPWithTrusted(req(tc.remoteAddr, tc.headers), mustParseCIDRs(t, tc.trusted))
			if got != tc.want {
				t.Fatalf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClientIPNilSafe(t *testing.T) {
	if got := ClientIP(nil); got != "" {
		t.Fatalf("ClientIP(nil) = %q, want empty", got)
	}
	if got := ClientIPWithTrusted(nil, nil); got != "" {
		t.Fatalf("ClientIPWithTrusted(nil) = %q, want empty", got)
	}
}

func TestClientIPReadsEnv(t *testing.T) {
	t.Setenv(TrustedProxyEnv, "10.0.0.0/8")
	// peer trusted -> honor XFF
	got := ClientIP(req("10.0.0.5:1111", map[string]string{"X-Forwarded-For": "198.51.100.23"}))
	if got != "198.51.100.23" {
		t.Fatalf("with trusted env, got %q want 198.51.100.23", got)
	}
	// peer untrusted -> RemoteAddr
	got = ClientIP(req("203.0.113.7:9999", map[string]string{"X-Forwarded-For": "1.2.3.4"}))
	if got != "203.0.113.7" {
		t.Fatalf("untrusted peer, got %q want 203.0.113.7", got)
	}
}

func TestClientIPNoEnvNeverTrustsXFF(t *testing.T) {
	t.Setenv(TrustedProxyEnv, "")
	got := ClientIP(req("198.51.100.50:443", map[string]string{
		"X-Forwarded-For": "1.1.1.1",
		"X-Real-IP":       "2.2.2.2",
	}))
	if got != "198.51.100.50" {
		t.Fatalf("no env should ignore XFF, got %q want 198.51.100.50", got)
	}
}
