package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadAndRestoreRequestBody(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", strings.NewReader(body))

	first, err := readAndRestoreRequestBody(req)
	if err != nil {
		t.Fatalf("readAndRestoreRequestBody error: %v", err)
	}
	second, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}

	if string(first) != body || string(second) != body {
		t.Fatalf("body was not restored: first=%q second=%q", first, second)
	}
}
