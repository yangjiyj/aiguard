package aimsg

import (
	"strings"
	"testing"
)

func TestParseGeminiGenerateContentRequest(t *testing.T) {
	body := []byte(`{
		"systemInstruction":{"parts":[{"text":"SYSTEM-RULE"}]},
		"tools":[{"functionDeclarations":[{"name":"lookup","description":"lookup data","parameters":{"type":"OBJECT","properties":{"q":{"type":"STRING"}}}}]}],
		"contents":[
			{"role":"user","parts":[{"text":"phone 13812345678"},{"inlineData":{"mimeType":"image/png","data":"aGVsbG8="}}]},
			{"role":"model","parts":[{"thought":true,"text":"reasoning text"},{"functionCall":{"name":"lookup","args":{"q":"customer"}}}]},
			{"role":"user","parts":[{"functionResponse":{"name":"lookup","response":{"result":"hit"}}}]}
		]
	}`)

	parsed, ok := ParseGeminiGenerateContentRequest(body)
	if !ok {
		t.Fatal("Gemini generateContent request should match")
	}
	text := FlattenMessages(parsed.Messages)
	if len(parsed.Images) != 1 || parsed.Images[0].MediaType != "image/png" {
		t.Fatalf("inline image not extracted: %+v", parsed.Images)
	}
	for _, want := range []string{"13812345678", "[reasoning] reasoning text", "[tool_use:lookup]", "[tool_result:lookup]"} {
		if !strings.Contains(text, want) {
			t.Fatalf("structured Gemini content missing %q: %+v", want, parsed.Messages)
		}
	}
	if parsed.SystemText != "SYSTEM-RULE" {
		t.Fatalf("SystemText = %q", parsed.SystemText)
	}
	if parsed.ToolsDigest == "" || parsed.FirstUserSHA == "" {
		t.Fatalf("derived digests missing: %+v", parsed)
	}
}

func TestParseChatRequestRecognizesGeminiGenerateContent(t *testing.T) {
	body := []byte(`{"contents":[{"role":"user","parts":[{"text":"GEMINI-PARSE-TEST"}]}]}`)
	parsed, ok := ParseChatRequest("/v1/projects/p/locations/global/models/gemini:generateContent", body)
	if !ok {
		t.Fatal("ParseChatRequest should recognize native Gemini")
	}
	if !strings.Contains(FlattenMessages(parsed.Messages), "GEMINI-PARSE-TEST") {
		t.Fatalf("Gemini content missing: %+v", parsed.Messages)
	}
}

func TestParseGeminiGenerateContentRejectsNonChatJSON(t *testing.T) {
	if _, ok := ParseGeminiGenerateContentRequest([]byte(`{"model":"text-embedding-004","content":"embedding"}`)); ok {
		t.Fatal("non-Gemini chat JSON should not match")
	}
}
