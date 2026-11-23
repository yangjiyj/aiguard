package handler

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
)

func TestReverseInspectionDeclaresWantSecretText(t *testing.T) {
	seen := map[string]string{}
	h := &ReverseProxyHandler{securityURL: "http://engine.invalid", client: &http.Client{Transport: reverseTimeoutRoundTripper(func(r *http.Request) (*http.Response, error) {
		seen[r.URL.Path] = r.Header.Get(security.WantSecretTextHeader)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"action":"allow","inspection_status":"completed"}`))}, nil
	})}}
	for _, path := range []string{"/check-input/", "/check-output/"} {
		if _, err := h.postReverseInspection(t.Context(), path, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if seen[path] != "1" {
			t.Errorf("%s: 请求头=%q，应为 1", path, seen[path])
		}
	}
}
