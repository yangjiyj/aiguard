package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGeminiGenerateContentRequestDecoder(t *testing.T) {
	body := []byte(`{
		"systemInstruction":{"parts":[{"text":"SYSTEM-RULE"}]},
		"contents":[{"role":"user","parts":[{"text":"phone 13812345678"},{"inlineData":{"mimeType":"image/png","data":"aGVsbG8="}}]}]
	}`)
	req := httptest.NewRequest(http.MethodPost, "https://aiplatform.googleapis.com/v1/projects/demo/locations/global/publishers/google/models/gemini-2.5-flash:generateContent", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	decoder, ok := getWebDecoder("gemini_generate_content")
	if !ok {
		t.Fatal("gemini_generate_content decoder is not registered")
	}
	extracted, matched := decoder.DecodeRequest(req, body, "application/json")
	if !matched {
		t.Fatal("native Gemini request should match")
	}
	if !strings.Contains(extracted.Text, "13812345678") || !strings.Contains(extracted.Text, "SYSTEM-RULE") {
		t.Fatalf("request text incomplete: %q", extracted.Text)
	}
	if extracted.Model != "gemini-2.5-flash" {
		t.Fatalf("model = %q", extracted.Model)
	}
	if len(extracted.Attachments) != 1 || extracted.Attachments[0].ContentType != "image/png" {
		t.Fatalf("inline image missing: %+v", extracted.Attachments)
	}
}

func TestGeminiGenerateContentResponseDecoderJSON(t *testing.T) {
	body := []byte(`{
		"modelVersion":"gemini-2.5-flash",
		"candidates":[{"content":{"role":"model","parts":[
			{"thought":true,"text":"reasoning text"},
			{"text":"response with phone 13812345678"},
			{"functionCall":{"name":"lookup","args":{"phone":"13812345678"}}}
		]}}]
	}`)
	decoder, _ := getWebDecoder("gemini_generate_content")
	extracted, matched := decoder.DecodeResponse(body, "application/json")
	if !matched {
		t.Fatal("native Gemini JSON response should match")
	}
	for _, want := range []string{"[reasoning] reasoning text", "response with phone", "13812345678"} {
		if !strings.Contains(extracted.Text, want) {
			t.Fatalf("response text missing %q: %q", want, extracted.Text)
		}
	}
	if extracted.Model != "gemini-2.5-flash" {
		t.Fatalf("model = %q", extracted.Model)
	}
	if !extracted.VisibleTextKnown || extracted.VisibleText != "response with phone 13812345678" {
		t.Fatalf("Gemini JSON 客户投影不得包含 thought/functionCall: %+v", extracted)
	}
}

func TestGeminiGenerateContentResponseDecoderSSE(t *testing.T) {
	body := []byte("data: {\"modelVersion\":\"gemini-2.5-flash\",\"candidates\":[{\"content\":{\"parts\":[{\"thought\":true,\"text\":\"reasoning\"}]}}]}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"rotate the database password\"}]}}]}\n\n")
	decoder, _ := getWebDecoder("gemini_generate_content")
	extracted, matched := decoder.DecodeResponse(body, "text/event-stream")
	if !matched {
		t.Fatal("native Gemini SSE response should match")
	}
	if !strings.Contains(extracted.Text, "[reasoning] reasoning") || !strings.Contains(extracted.Text, "rotate the database password") {
		t.Fatalf("stream response incomplete: %q", extracted.Text)
	}
	if !extracted.VisibleTextKnown || extracted.VisibleText != "rotate the database password" {
		t.Fatalf("Gemini SSE 客户投影不得包含 thought: %+v", extracted)
	}
}

func TestGeminiGenerateContentDecoderRejectsNonChatJSON(t *testing.T) {
	body := []byte(`{"model":"text-embedding-004","values":[[0.1,0.2]]}`)
	decoder, _ := getWebDecoder("gemini_generate_content")
	if _, matched := decoder.DecodeRequest(nil, body, "application/json"); matched {
		t.Fatal("non-chat JSON should not match Gemini decoder")
	}
}
