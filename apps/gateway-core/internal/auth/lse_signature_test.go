package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestVerifyLSECorrelationSignatureAcceptsActiveKey(t *testing.T) {
	t.Setenv("LSE_CORRELATION_HMAC_KEYS", "active=unit-secret,old=old-secret")
	t.Setenv("LSE_CORRELATION_HMAC_MODE", "required")
	now := time.Now().Unix()
	req := httptest.NewRequest(http.MethodPost, "http://gateway.test/v1/chat/completions", nil)
	req.Header.Set("X-LSE-Eval-Run-Id", "eval_run_123")
	req.Header.Set("X-LSE-Task-Id", "task-456")
	req.Header.Set("X-LSE-Sample-Id", "sample_789")
	req.Header.Set("X-LSE-Target-Id", "target-A")
	req.Header.Set("X-LSE-Trace-Id", "trace_abc-123")
	req.Header.Set("X-LSE-Correlation-Signature", signTestLSECorrelation(req, "active", "unit-secret", now, "nonce-1"))
	corr, trusted := extractVerifiedLSECorrelation(req)
	if !trusted {
		t.Fatalf("valid signature should be trusted")
	}
	if corr.TraceID != "trace_abc-123" || corr.TaskID != "task-456" {
		t.Fatalf("unexpected correlation: %+v", corr)
	}
}

func TestVerifyLSECorrelationSignatureRejectsTamperAndMissing(t *testing.T) {
	t.Setenv("LSE_CORRELATION_HMAC_KEYS", "active=unit-secret")
	t.Setenv("LSE_CORRELATION_HMAC_MODE", "required")
	now := time.Now().Unix()
	req := httptest.NewRequest(http.MethodPost, "http://gateway.test/v1/chat/completions", nil)
	req.Header.Set("X-LSE-Task-Id", "task-456")
	req.Header.Set("X-LSE-Trace-Id", "trace-abc")
	req.Header.Set("X-LSE-Correlation-Signature", signTestLSECorrelation(req, "active", "unit-secret", now, "nonce-2"))
	req.Header.Set("X-LSE-Task-Id", "attacker-task")
	if corr, trusted := extractVerifiedLSECorrelation(req); trusted || corr != (LSECorrelation{}) {
		t.Fatalf("tampered signature must not be trusted: corr=%+v trusted=%v", corr, trusted)
	}
	req.Header.Del("X-LSE-Correlation-Signature")
	if corr, trusted := extractVerifiedLSECorrelation(req); trusted || corr != (LSECorrelation{}) {
		t.Fatalf("missing signature must not be trusted in required mode: corr=%+v trusted=%v", corr, trusted)
	}
}

func TestLegacyLSECorrelationModePreservesHeadersButNotTrust(t *testing.T) {
	t.Setenv("LSE_CORRELATION_HMAC_KEYS", "")
	t.Setenv("LSE_CORRELATION_HMAC_MODE", "off")
	req := httptest.NewRequest(http.MethodPost, "http://gateway.test/v1/chat/completions", nil)
	req.Header.Set("X-LSE-Trace-Id", "legacy-trace")
	corr, trusted := extractVerifiedLSECorrelation(req)
	if trusted || corr.TraceID != "legacy-trace" {
		t.Fatalf("legacy mode should preserve compatibility without trust: corr=%+v trusted=%v", corr, trusted)
	}
}

func signTestLSECorrelation(req *http.Request, kid, secret string, timestamp int64, nonce string) string {
	corr := extractLSECorrelationHeaders(req.Header)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonicalLSECorrelation(req, corr, timestamp, nonce)))
	return "v1." + kid + "." + strconv.FormatInt(timestamp, 10) + "." + nonce + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
