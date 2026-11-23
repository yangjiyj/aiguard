package handler

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

func TestWriteUpstreamErrorResponseLogsUpstreamMessageAndPassesThrough4xx(t *testing.T) {
	var captured bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&captured)
	t.Cleanup(func() { log.SetOutput(previous) })

	upstreamErr := &provider.UpstreamHTTPError{
		StatusCode: http.StatusBadRequest,
		Body:       []byte(`{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: 1000000 > 128000, which is the maximum allowed number of output tokens for claude-opus-5"}}`),
		Message:    "max_tokens: 1000000 > 128000, which is the maximum allowed number of output tokens for claude-opus-5",
	}
	recorder := httptest.NewRecorder()
	writeUpstreamErrorResponse(recorder, upstreamErr, "req-log-1", "upstream_response")

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", recorder.Code)
	}
	// 4xx 的 message 经净化后给客户端（让它知道怎么改）；上游原始 JSON 正文不原样转发。
	var clientBody ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &clientBody); err != nil {
		t.Fatalf("client body is not JSON: %v: %s", err, recorder.Body.String())
	}
	if !strings.Contains(clientBody.Error.Message, "max_tokens: 1000000 > 128000") || clientBody.Error.Code != "upstream_error" || strings.Contains(recorder.Body.String(), `"type":"error"`) {
		t.Fatalf("client should get the sanitized 4xx message, not the raw upstream body: %s", recorder.Body.String())
	}
	logged := captured.String()
	for _, want := range []string{"[provider.error]", "request_id=req-log-1", "stage=upstream_response", "status=400", "max_tokens: 1000000 > 128000"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("server log is missing %q: %s", want, logged)
		}
	}
}

func TestLogUpstreamHTTPErrorFallsBackToBodyAndBounds(t *testing.T) {
	var captured bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&captured)
	t.Cleanup(func() { log.SetOutput(previous) })

	logUpstreamHTTPError("req-log-2", "upstream_response", &provider.UpstreamHTTPError{
		StatusCode: http.StatusServiceUnavailable,
		Body:       []byte("<html>\n" + strings.Repeat("x", 2000) + "</html>"),
	})
	logged := captured.String()
	if !strings.Contains(logged, "status=503") || !strings.Contains(logged, "<html> xxx") {
		t.Fatalf("raw body should be logged when no message was parsed: %s", logged)
	}
	if len(logged) > 800 {
		t.Fatalf("logged message must be bounded, got %d bytes", len(logged))
	}
	logUpstreamHTTPError("req-log-3", "upstream_response", nil)
}
