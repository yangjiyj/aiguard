package safetarget

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveOptionsEachSwitchAllowsOnlyItsClass(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		url  string
		ip   string
		opts Options
	}{
		{"loopback", "http://loop.example/x", "127.0.0.1", Options{AllowLoopback: true}},
		{"ipv6 loopback", "http://loop6.example/x", "::1", Options{AllowLoopback: true}},
		{"link local", "http://ll.example/x", "169.254.20.1", Options{AllowLinkLocal: true}},
		{"metadata", "http://imds.example/x", "169.254.169.254", Options{AllowMetadata: true}},
		{"aliyun metadata", "http://imds.example/x", "100.100.100.200", Options{AllowMetadata: true}},
	}
	for _, tc := range cases {
		host := strings.Split(strings.TrimPrefix(tc.url, "http://"), "/")[0]
		if _, err := ResolveWithOptions(ctx, tc.url, Options{}, resolverFor(host, tc.ip)); !errors.Is(err, ErrForbiddenAddress) {
			t.Errorf("%s: default err=%v, want ErrForbiddenAddress", tc.name, err)
		}
		target, err := ResolveWithOptions(ctx, tc.url, tc.opts, resolverFor(host, tc.ip))
		if err != nil || target.IP.String() != tc.ip {
			t.Errorf("%s: opted-in target=%+v err=%v", tc.name, target, err)
		}
	}
	// 开关互不放大：链路本地不放开元数据，回环不放开链路本地，内网不放开元数据。
	for _, tc := range []struct {
		ip   string
		opts Options
	}{
		{"169.254.169.254", Options{AllowLinkLocal: true}},
		{"169.254.20.1", Options{AllowLoopback: true}},
		{"100.100.100.200", Options{AllowPrivate: true}},
		{"127.0.0.1", Options{AllowPrivate: true, AllowLinkLocal: true, AllowMetadata: true}},
	} {
		if _, err := ResolveWithOptions(ctx, "http://x.example/", tc.opts, resolverFor("x.example", tc.ip)); err == nil {
			t.Errorf("%s allowed by %+v", tc.ip, tc.opts)
		}
	}
}

func TestResolveOptionsInternalHostnamesStillCheckResolvedAddress(t *testing.T) {
	ctx := context.Background()
	if _, err := ResolveWithOptions(ctx, "http://localhost:8080/", Options{}, nil); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("default localhost err=%v", err)
	}
	// 名字放开了，解析到回环仍要回环开关。
	if _, err := ResolveWithOptions(ctx, "http://localhost:8080/", Options{AllowInternalHostnames: true}, resolverFor("localhost", "127.0.0.1")); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("internal hostname resolving to loopback without loopback opt-in: err=%v", err)
	}
	if _, err := ResolveWithOptions(ctx, "http://metadata.google.internal/", Options{AllowInternalHostnames: true}, resolverFor("metadata.google.internal", "169.254.169.254")); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("metadata hostname resolving to IMDS without metadata opt-in: err=%v", err)
	}
	target, err := ResolveWithOptions(ctx, "http://metadata.google.internal/", Options{AllowInternalHostnames: true}, resolverFor("metadata.google.internal", "203.0.113.10"))
	if err != nil || target.IP.String() != "203.0.113.10" {
		t.Fatalf("internal hostname resolving public: %+v err=%v", target, err)
	}
	if _, err := ResolveWithOptions(ctx, "http://localhost:8080/", Options{AllowInternalHostnames: true, AllowLoopback: true}, resolverFor("localhost", "127.0.0.1")); err != nil {
		t.Fatalf("both opt-ins: err=%v", err)
	}
}

func TestResolveRejectsInvalidTrustedCAPEM(t *testing.T) {
	_, err := ResolveWithOptions(context.Background(), "https://api.example/", Options{TrustedCAPEM: "not a certificate"}, resolverFor("api.example", "203.0.113.10"))
	if !errors.Is(err, ErrInvalidTrustedCA) {
		t.Fatalf("err=%v, want ErrInvalidTrustedCA", err)
	}
}

func tlsServerAndCA(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	return server, caPEM
}

func TestClientTLSOptionsTrustCustomCAOrSkipVerify(t *testing.T) {
	server, caPEM := tlsServerAndCA(t)
	ctx := context.Background()
	// httptest 证书签给 example.com 和 127.0.0.1；直接用 IP 字面量。
	rawURL := server.URL + "/v1"
	plain, err := ResolveWithOptions(ctx, rawURL, Options{AllowLoopback: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := Client(nil, plain, false).Get(rawURL); err == nil {
		resp.Body.Close()
		t.Fatal("self-signed upstream accepted without a trusted CA")
	}
	trusted, err := ResolveWithOptions(ctx, rawURL, Options{AllowLoopback: true, TrustedCAPEM: caPEM}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Client(nil, trusted, false).Get(rawURL)
	if err != nil {
		t.Fatalf("trusted CA: %v", err)
	}
	resp.Body.Close()
	insecure, err := ResolveWithOptions(ctx, rawURL, Options{AllowLoopback: true, InsecureSkipVerify: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = Client(nil, insecure, true).Get(rawURL)
	if err != nil {
		t.Fatalf("insecure skip verify: %v", err)
	}
	resp.Body.Close()
}

func TestClientSameHostRedirectOptionNeverFollowsCrossHost(t *testing.T) {
	var crossHits int
	cross := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		crossHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cross.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/away":
			http.Redirect(w, r, cross.URL+"/x", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	ctx := context.Background()
	defaultTarget, err := ResolveWithOptions(ctx, server.URL+"/start", Options{AllowLoopback: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Client(nil, defaultTarget, false).Get(server.URL + "/start"); !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("default same-host redirect err=%v", err)
	}
	target, err := ResolveWithOptions(ctx, server.URL+"/start", Options{AllowLoopback: true, AllowSameHostRedirect: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Client(nil, target, false).Get(server.URL + "/start")
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("same-host redirect: resp=%v err=%v", resp, err)
	}
	resp.Body.Close()
	if _, err := Client(nil, target, false).Get(server.URL + "/away"); !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("cross-host redirect err=%v", err)
	}
	if crossHits != 0 {
		t.Fatalf("cross-host redirect followed %d times", crossHits)
	}
}

func TestEgressOverridesParseOptionsAndEnabledFlags(t *testing.T) {
	o, err := ParseEgressOverrides([]byte(`{"allow_loopback":true,"trusted_ca_pem":"","insecure_skip_verify":true,"allow_same_host_redirect":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := o.Enabled(); strings.Join(got, ",") != "allow_loopback,insecure_skip_verify,allow_same_host_redirect" {
		t.Fatalf("enabled = %v", got)
	}
	opts := o.Options(true)
	if !opts.AllowPrivate || !opts.AllowLoopback || !opts.InsecureSkipVerify || !opts.AllowSameHostRedirect {
		t.Fatalf("options = %+v", opts)
	}
	// 反向代理不认证书与重定向三项（只对 MCP 服务有效）。
	if rp := o.ForReverseProxy(); rp.InsecureSkipVerify || rp.AllowSameHostRedirect || !rp.AllowLoopback {
		t.Fatalf("reverse proxy overrides = %+v", rp)
	}
	for _, raw := range []string{`{"allow_everything":true}`, `{"allow_loopback":"yes"}`, `[]`} {
		if _, err := ParseEgressOverrides([]byte(raw)); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
	if empty, err := ParseEgressOverrides(nil); err != nil || len(empty.Enabled()) != 0 {
		t.Fatalf("empty = %+v err=%v", empty, err)
	}
	if _, err := ParseEgressOverrides([]byte(`{"trusted_ca_pem":"garbage"}`)); err == nil {
		t.Fatal("invalid CA PEM accepted")
	}
}
