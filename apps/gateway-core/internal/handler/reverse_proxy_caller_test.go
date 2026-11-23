package handler

import (
	"net/http"
	"strings"
	"testing"
)

func reqWithHeaders(h map[string]string) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "https://api.example-gateway.com/v1/chat/completions", nil)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	return req
}

func TestReverseProxyCallerIDStableAndScheveStripped(t *testing.T) {
	// Keep the fixture low-entropy so repository secret scanning does not flag a fake credential.
	rawKey := "aaaa-bbbb-cccc"

	withBearer := reverseProxyCallerID(reqWithHeaders(map[string]string{"Authorization": "Bearer " + rawKey}))
	withoutScheme := reverseProxyCallerID(reqWithHeaders(map[string]string{"Authorization": rawKey}))

	if withBearer == "" {
		t.Fatal("expected non-empty caller id for Authorization header")
	}
	if !strings.HasPrefix(withBearer, "caller_") {
		t.Fatalf("caller id must be prefixed caller_, got %q", withBearer)
	}
	// 同一 key 无论是否带 Bearer 前缀，都应映射到同一身份。
	if withBearer != withoutScheme {
		t.Fatalf("scheme prefix must not change identity: %q vs %q", withBearer, withoutScheme)
	}
	// 绝不泄露明文密钥材料。
	if strings.Contains(withBearer, rawKey) {
		t.Fatalf("caller id must not leak raw key material: %q", withBearer)
	}
}

func TestReverseProxyCallerIDDistinguishesKeys(t *testing.T) {
	a := reverseProxyCallerID(reqWithHeaders(map[string]string{"Authorization": "Bearer key-team-a"}))
	b := reverseProxyCallerID(reqWithHeaders(map[string]string{"Authorization": "Bearer key-team-b"}))
	if a == "" || b == "" || a == b {
		t.Fatalf("distinct keys must yield distinct caller ids: a=%q b=%q", a, b)
	}
}

func TestReverseProxyCallerIDFallbacksAndEmpty(t *testing.T) {
	if got := reverseProxyCallerID(reqWithHeaders(map[string]string{})); got != "" {
		t.Fatalf("no credential must yield empty caller id, got %q", got)
	}
	if got := reverseProxyCallerID(nil); got != "" {
		t.Fatalf("nil request must yield empty caller id, got %q", got)
	}
	// X-Api-Key 作为回退凭据也应识别。
	if got := reverseProxyCallerID(reqWithHeaders(map[string]string{"X-Api-Key": "xak-12345"})); !strings.HasPrefix(got, "caller_") {
		t.Fatalf("X-Api-Key fallback must produce a caller id, got %q", got)
	}
}
