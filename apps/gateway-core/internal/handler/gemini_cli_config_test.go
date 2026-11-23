package handler

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// 夹具来自 2026-11-07 对 @google/gemini-cli 0.67.0 的真实捕获（假 key 指向本地捕获服务器），
// testdata 文件逐字保存，未经手改。gen=utility 非流式调用，stream=主对话流式调用。
func loadGeminiCLIFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata" + string(os.PathSeparator) + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGeminiIngressAcceptsGeminiCLIStreamRequest(t *testing.T) {
	chat, err := geminiRequestToChat(loadGeminiCLIFixture(t, "gemini_cli_stream.json"), "logical")
	if err != nil {
		t.Fatalf("Gemini CLI stream request rejected: %v", err)
	}
	if chat["top_k"] != json.Number("64") {
		t.Fatalf("topK not mapped to top_k: %v", chat["top_k"])
	}
	if _, exists := chat["response_format"]; exists {
		t.Fatal("stream request carries no response format, none should be synthesized")
	}
	if chat["reasoning_effort"] != "high" {
		t.Fatalf("thinkingLevel HIGH not mapped to reasoning_effort high: %v", chat["reasoning_effort"])
	}
	encoded, _ := json.Marshal(chat)
	if strings.Contains(string(encoded), "thinkingConfig") {
		t.Fatal("thinkingConfig must not leak into the chat request")
	}
}

func TestGeminiIngressAcceptsGeminiCLIJSONModeRequest(t *testing.T) {
	chat, err := geminiRequestToChat(loadGeminiCLIFixture(t, "gemini_cli_gen.json"), "logical")
	if err != nil {
		t.Fatalf("Gemini CLI utility request rejected: %v", err)
	}
	format, ok := chat["response_format"].(map[string]any)
	if !ok || format["type"] != "json_schema" {
		t.Fatalf("responseMimeType+schema not mapped to json_schema: %v", chat["response_format"])
	}
	nested := format["json_schema"].(map[string]any)
	schema, _ := json.Marshal(nested["schema"])
	if !strings.Contains(string(schema), "complexity_score") {
		t.Fatalf("response schema lost: %s", schema)
	}
	if strings.Contains(string(schema), "OBJECT") {
		t.Fatalf("schema types should be lowered for the chat protocol: %s", schema)
	}
}

func TestGeminiIngressThinkingBudgetZeroMapsToMinimal(t *testing.T) {
	raw := `{"contents":[{"parts":[{"text":"x"}]}],"generationConfig":{"thinkingConfig":{"thinkingBudget":0}}}`
	chat, err := geminiRequestToChat([]byte(raw), "logical")
	if err != nil {
		t.Fatal(err)
	}
	if chat["reasoning_effort"] != "minimal" {
		t.Fatalf("thinkingBudget 0 should map to minimal, got %v", chat["reasoning_effort"])
	}
}

func TestGeminiIngressJSONModeWithoutSchemaMapsToObject(t *testing.T) {
	raw := `{"contents":[{"parts":[{"text":"x"}]}],"generationConfig":{"responseMimeType":"application/json"}}`
	chat, err := geminiRequestToChat([]byte(raw), "logical")
	if err != nil {
		t.Fatal(err)
	}
	format := chat["response_format"].(map[string]any)
	if format["type"] != "json_object" {
		t.Fatalf("expected json_object, got %v", format)
	}
}

func TestGeminiIngressStillRejectsUnknownGenerationConfigFields(t *testing.T) {
	raw := `{"contents":[{"parts":[{"text":"x"}]}],"generationConfig":{"mysteryField":1}}`
	_, err := geminiRequestToChat([]byte(raw), "logical")
	if err == nil || !strings.Contains(err.Error(), "unsupported field") {
		t.Fatalf("unknown field must stay rejected, got %v", err)
	}
}

func TestGeminiIngressRejectsBadTopKAndMime(t *testing.T) {
	for _, raw := range []string{
		`{"contents":[{"parts":[{"text":"x"}]}],"generationConfig":{"topK":0}}`,
		`{"contents":[{"parts":[{"text":"x"}]}],"generationConfig":{"topK":-3}}`,
		`{"contents":[{"parts":[{"text":"x"}]}],"generationConfig":{"topK":"high"}}`,
		`{"contents":[{"parts":[{"text":"x"}]}],"generationConfig":{"responseMimeType":"text/html"}}`,
		`{"contents":[{"parts":[{"text":"x"}]}],"generationConfig":{"thinkingConfig":"fast"}}`,
		`{"contents":[{"parts":[{"text":"x"}]}],"generationConfig":{"thinkingConfig":{"thinkingLevel":"MEDIUM"}}}`,
		`{"contents":[{"parts":[{"text":"x"}]}],"generationConfig":{"thinkingConfig":{"thinkingBudget":4096}}}`,
		`{"contents":[{"parts":[{"text":"x"}]}],"generationConfig":{"thinkingConfig":{"thinkingBudget":-1}}}`,
	} {
		if _, err := geminiRequestToChat([]byte(raw), "logical"); err == nil {
			t.Fatalf("expected rejection for %s", raw)
		}
	}
}
