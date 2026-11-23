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

type fileDLPTestRoundTripper func(*http.Request) (*http.Response, error)

func (f fileDLPTestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type countedReadCloser struct {
	reader bytes.Reader
	read   int64
}

func newCountedReadCloser(body []byte) *countedReadCloser {
	return &countedReadCloser{reader: *bytes.NewReader(body)}
}

func (r *countedReadCloser) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += int64(n)
	return n, err
}

func (r *countedReadCloser) Close() error { return nil }

func TestHandleHTTPBlocksRawFileBeforeUpstreamWhenContentDLPDisabled(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "")

	var upstreamCalls atomic.Int32
	var received map[string]interface{}
	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode security request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"action\":\"block\",\"findings\":[{\"type\":\"file\",\"category\":\"phone_cn\",\"action\":\"block\"}]}")
	}))
	defer securityServer.Close()

	h := NewProxyHandler(successfulEmptyWhitelistChecker(), nil, NewSecurityClient(securityServer.URL), nil, nil)
	h.transport = fileDLPTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("upstream reached")),
			Request:    r,
		}, nil
	})

	body := []byte("%PDF-1.4\ncustomer phone 13812345678\n")
	req := httptest.NewRequest(http.MethodPost, "http://files.example.test/upload/report.pdf", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/pdf")
	recorder := httptest.NewRecorder()

	h.handleHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("raw file should be blocked, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("blocked file reached upstream %d time(s)", upstreamCalls.Load())
	}
	context, ok := received["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("security context missing: %#v", received)
	}
	attachments, ok := context["attachments"].([]interface{})
	if !ok || len(attachments) != 1 {
		t.Fatalf("raw PDF attachment missing from security request: %#v", context["attachments"])
	}
}

func TestHandleHTTPAuditOnlyAllowsRawFileEnforcementActions(t *testing.T) {
	for _, engineAction := range []string{"block", "reply"} {
		t.Run(engineAction, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", "true")
			var upstreamCalls atomic.Int32
			var forwardedBody []byte
			securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer r.Body.Close()
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"action":"`+engineAction+`","findings":[{"type":"file","category":"blocked_type","action":"`+engineAction+`"}]}`)
			}))
			defer securityServer.Close()

			h := NewProxyHandler(successfulEmptyWhitelistChecker(), nil, NewSecurityClient(securityServer.URL), nil, nil)
			h.transport = fileDLPTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				upstreamCalls.Add(1)
				forwardedBody, _ = io.ReadAll(r.Body)
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("upstream reached")),
					Request:    r,
				}, nil
			})

			body := []byte("%PDF-1.4\ncustomer phone 13812345678\n")
			req := httptest.NewRequest(http.MethodPost, "http://files.example.test/upload/report.pdf", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/pdf")
			recorder := httptest.NewRecorder()

			h.handleHTTP(recorder, req)

			if recorder.Code != http.StatusOK {
				t.Fatalf("audit-only %s must forward raw file, got status=%d body=%s", engineAction, recorder.Code, recorder.Body.String())
			}
			if upstreamCalls.Load() != 1 {
				t.Fatalf("audit-only %s must reach upstream once, got %d", engineAction, upstreamCalls.Load())
			}
			if !bytes.Equal(forwardedBody, body) {
				t.Fatalf("audit-only %s forwarded body mismatch: got=%q want=%q", engineAction, forwardedBody, body)
			}
		})
	}
}

// The proxy cannot mask a raw file; the configured action is "mask", not
// "block", so the original is forwarded and alerted.
func TestHandleHTTPForwardsUnmaskableRawFile(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")

	var upstreamCalls atomic.Int32
	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"mask","findings":[{"type":"file","action":"mask"}]}`)
	}))
	defer securityServer.Close()

	h := NewProxyHandler(successfulEmptyWhitelistChecker(), nil, NewSecurityClient(securityServer.URL), nil, nil)
	h.transport = fileDLPTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("upstream reached")),
			Request:    r,
		}, nil
	})

	body := []byte("%PDF-1.4\ncustomer phone 13812345678\n")
	req := httptest.NewRequest(http.MethodPost, "http://files.example.test/upload/report.pdf", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/pdf")
	recorder := httptest.NewRecorder()

	h.handleHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unmaskable raw file must be forwarded, got status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("unmaskable file must reach upstream once, got %d", upstreamCalls.Load())
	}
}

func TestHandleHTTPStreamedOversizedFileDoesNotPreloadWholeBodyAndAuditForwards(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	t.Setenv("SECURITY_FILE_CONTENT_MAX_REQUEST_MB", "1")
	const limit = int64(1 << 20)
	body := bytes.Repeat([]byte("x"), int(limit)+8192)
	source := newCountedReadCloser(body)

	h := NewProxyHandler(successfulEmptyWhitelistChecker(), nil, NewSecurityClient("http://security.invalid"), nil, nil)
	var beforeForward int64
	var forwarded []byte
	h.transport = fileDLPTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		beforeForward = source.read
		if beforeForward > limit+1 {
			t.Fatalf("proxy preloaded %d bytes before upstream, limit=%d", beforeForward, limit+1)
		}
		var err error
		forwarded, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read forwarded body: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("upstream reached")),
			Request:    r,
		}, nil
	})

	req := httptest.NewRequest(http.MethodPost, "http://files.example.test/upload/report.pdf", nil)
	req.Body = source
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/pdf")
	recorder := httptest.NewRecorder()

	h.handleHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("audit-only oversized file status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if beforeForward > limit+1 {
		t.Fatalf("proxy preloaded %d bytes before upstream", beforeForward)
	}
	if !bytes.Equal(forwarded, body) {
		t.Fatalf("forwarded body mismatch: got=%d want=%d", len(forwarded), len(body))
	}
}

func TestFileEngineFailureIsIncompleteNotHighRisk(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "false")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	client := NewSecurityClient(server.URL)
	req := httptest.NewRequest(http.MethodPost, "http://files.example.test/upload/report.pdf", strings.NewReader("%PDF-1.4 test"))
	req.Header.Set("Content-Type", "application/pdf")
	action, findings, meta := client.CheckInput(req.Context(), "tenant-a", "runtime-failure", req)
	if action != "audit" || meta == nil || meta.SemanticStatus != "incomplete" {
		t.Fatalf("failure not observable: %s %+v", action, meta)
	}
	for _, f := range findings {
		if f["counts_as_security_finding"] != false || f["severity"] != "low" {
			t.Fatalf("failure is not risk: %+v", f)
		}
	}
}
