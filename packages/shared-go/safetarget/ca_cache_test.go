package safetarget

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 自定义 CA 只解析一次：同一份 PEM 复用同一个证书池（随路由的 egress_overrides 缓存）。
func TestTrustedCAPEMParsedOnce(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	first, err := ResolveWithOptions(context.Background(), "https://203.0.113.10/", Options{TrustedCAPEM: caPEM}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ResolveWithOptions(context.Background(), "https://203.0.113.11/", Options{TrustedCAPEM: caPEM}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.rootCAs == nil || first.rootCAs != second.rootCAs {
		t.Fatal("the same trusted CA PEM must be parsed once and reused")
	}
	if _, err := ResolveWithOptions(context.Background(), "https://203.0.113.10/", Options{TrustedCAPEM: "not a certificate"}, nil); err != ErrInvalidTrustedCA {
		t.Fatalf("invalid PEM must still be rejected, got %v", err)
	}
}
