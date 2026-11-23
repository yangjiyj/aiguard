package httpmw

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedRealIP(t *testing.T) {
	cases := []struct {
		name           string
		remoteAddr     string
		xff            string
		trustedEnv     string
		wantRemoteAddr string
	}{
		{
			name:           "no trusted CIDRs: XFF ignored, RemoteAddr untouched (keeps port)",
			remoteAddr:     "203.0.113.7:54321",
			xff:            "1.2.3.4",
			trustedEnv:     "",
			wantRemoteAddr: "203.0.113.7:54321",
		},
		{
			name:           "untrusted peer: XFF ignored, RemoteAddr untouched",
			remoteAddr:     "203.0.113.7:54321",
			xff:            "1.2.3.4",
			trustedEnv:     "10.0.0.0/8",
			wantRemoteAddr: "203.0.113.7:54321",
		},
		{
			name:           "trusted peer: RemoteAddr rewritten to honored client IP",
			remoteAddr:     "10.0.0.5:1111",
			xff:            "198.51.100.23",
			trustedEnv:     "10.0.0.0/8",
			wantRemoteAddr: "198.51.100.23",
		},
		{
			name:           "no XFF at all: RemoteAddr untouched",
			remoteAddr:     "203.0.113.7:54321",
			xff:            "",
			trustedEnv:     "10.0.0.0/8",
			wantRemoteAddr: "203.0.113.7:54321",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TRUSTED_PROXY_CIDRS", tc.trustedEnv)
			var seen string
			h := TrustedRealIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = r.RemoteAddr
			}))
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			h.ServeHTTP(httptest.NewRecorder(), r)
			if seen != tc.wantRemoteAddr {
				t.Fatalf("RemoteAddr = %q, want %q", seen, tc.wantRemoteAddr)
			}
		})
	}
}
