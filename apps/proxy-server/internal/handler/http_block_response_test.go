package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// 普通 HTTP 入口的规则阻断必须和 MITM 一样返回 JSON，说明命中了哪条规则，
// 而不是一句纯文本 "Request blocked due to security policy"。
func TestHandleHTTPRuleBlockExplainsTheRule(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "")
	t.Setenv("SECURITY_AUDIT_ONLY", "false")

	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"block","findings":[{"type":"file","category":"phone_cn","action":"block","rule_id":"dlp-phone","rule_name":"phone egress"}]}`)
	}))
	defer securityServer.Close()

	var upstreamCalls atomic.Int32
	h := NewProxyHandler(successfulEmptyWhitelistChecker(), nil, NewSecurityClient(securityServer.URL), nil, nil)
	h.transport = fileDLPTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("upstream")), Request: r}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://files.example.test/upload/report.pdf", bytes.NewReader([]byte("%PDF-1.4\nphone 13812345678\n")))
	req.Header.Set("Content-Type", "application/pdf")
	rec := httptest.NewRecorder()
	h.handleHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("blocked request reached upstream")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("block response must be JSON, got %q body=%s", ct, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode block body: %v (%s)", err, rec.Body.String())
	}
	if body.Error.Code != "security_blocked" || !strings.Contains(body.Error.Message, "dlp-phone") {
		t.Fatalf("block body must name the rule, got %+v", body.Error)
	}
}
