package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUnparseableProtocolHasSeparateSecurityProjection(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
	engine, getPayloads := captureEngine(t, func(map[string]interface{}) string {
		return `{"action":"allow","findings":[]} `
	})
	defer engine.Close()
	h := newStructuredTestHandler(engine)
	body := []byte(`{"model":"gpt-5","instructions":"Skill contains AKIA1234567890ABCDEF","messages":[{"role":"assistant","content":"internal history"}]}`)
	req := httptest.NewRequest(http.MethodPost, "https://gw.local/v1/responses", bytes.NewReader(body))
	decision, err := h.checkRequestSecurityStructured(context.Background(), "req-no-user", req, body, "application/json", "api.openai.com", "/v1/responses")
	if err != nil || !decision.Allowed {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if payloads := getPayloads(); len(payloads) != 1 || payloads[0]["skip_semantic"] != true || decision.SemanticStatus != "incomplete" || decision.VerifiedContent != "" {
		t.Fatalf("没有已验证用户输入时不得扫描协议整包: %#v", payloads)
	}
}

func TestProtocolParseFailureKeepsDeterministicScan(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
	engine, getPayloads := captureEngine(t, func(map[string]interface{}) string {
		return `{"action":"allow","findings":[]} `
	})
	defer engine.Close()
	h := newStructuredTestHandler(engine)
	body := []byte(`{"model":"gpt-5","messages":`)
	req := httptest.NewRequest(http.MethodPost, "https://gw.local/v1/chat/completions", bytes.NewReader(body))
	decision, err := h.checkRequestSecurityStructured(context.Background(), "req-parse-fail-no-scan", req, body, "application/json", "api.openai.com", "/v1/chat/completions")
	if err != nil || !decision.Allowed {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if payloads := getPayloads(); len(payloads) != 1 || payloads[0]["skip_semantic"] != true || decision.SemanticStatus != "incomplete" || decision.VerifiedContent != "" {
		t.Fatalf("已知 LLM 解析失败时不得扫描原始 JSON: %#v", payloads)
	}
}

func TestVerifiedContentOutputMetadataOnlySkipsEnvelopeScan(t *testing.T) {
	engine, getPayloads := captureEngine(t, func(map[string]interface{}) string {
		return `{"action":"allow","findings":[]} `
	})
	defer engine.Close()
	h := newStructuredTestHandler(engine)
	body := []byte(`{"response":{"instructions":"internal Skill contains 13812345678"},"output":[]} `)
	decision, err := h.checkResponseSecurityStructured(context.Background(), "req-output-no-visible-text", body, "application/json", "api.example.com", "/v1/responses")
	if err != nil || !decision.Allowed {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if payloads := getPayloads(); len(payloads) != 0 {
		t.Fatalf("没有最终用户可见输出时不得扫描协议整包: %#v", payloads)
	}
}
