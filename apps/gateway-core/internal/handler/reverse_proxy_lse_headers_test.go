package handler

import (
	"net/http"
	"testing"
)

func TestCopyHeadersStripsLSECorrelationHeaders(t *testing.T) {
	src := http.Header{}
	src.Set("X-LSE-Eval-Run-Id", "eval-1")
	src.Set("X-LSE-Task-Id", "task-1")
	src.Set("X-LSE-Sample-Id", "sample-1")
	src.Set("X-LSE-Target-Id", "target-1")
	src.Set("X-LSE-Trace-Id", "trace-1")
	src.Set("X-Request-ID", "req-1")

	dst := http.Header{}
	copyHeaders(dst, src)

	for _, key := range []string{"X-LSE-Eval-Run-Id", "X-LSE-Task-Id", "X-LSE-Sample-Id", "X-LSE-Target-Id", "X-LSE-Trace-Id"} {
		if got := dst.Get(key); got != "" {
			t.Fatalf("%s should be stripped before forwarding upstream, got %q", key, got)
		}
	}
	if got := dst.Get("X-Request-ID"); got != "req-1" {
		t.Fatalf("non-LSE header should be preserved, got %q", got)
	}
}
