package handler

import (
	"os"
	"strings"
	"testing"
)

func TestWebDecoderVendorLogicLivesOutsideContentExtractor(t *testing.T) {
	source, err := os.ReadFile("content_extractor.go")
	if err != nil {
		t.Fatalf("read content_extractor.go: %v", err)
	}
	text := string(source)

	for _, symbol := range []string{
		"func extractWorkBuddyInvokeRequestContent(",
		"func isWorkBuddyInvokeRequest(",
		"func collectWorkBuddyInvokeJSONText(",
		"func appendWorkBuddyInvokeJSONString(",
		"func isWorkBuddyPromptJSONPath(",
		"func chatGPTEstuaryReferenceID(",
		"func extractGoogleBatchExecuteContent(",
		"func walkBatchExecuteValue(",
		"func geminiFileEntry(",
		"func walkGeminiFReqValue(",
		"func reassembleClaudeBlockStream(",
		"func reassembleDeepSeekPatchStream(",
		"func looksLikeDeepSeekPatch(",
		"func looksLikeDeepSeekPatchDefault(",
		"func applyDeepSeekPath(",
		"func pushDSFragment(",
		"func resolveFragmentIndex(",
		"func extractGeminiStreamGenerate(",
		"func geminiWrbFrSnapshots(",
		"func collectWrbFr(",
		"func geminiStreamResponseSnapshot(",
		"func geminiSnapshotReasoning(",
		"func reassembleKimiWebStream(",
		"func parseConnectFrames(",
		"func liftKimiChatID(",
		"func liftKimiBlockTextContent(",
		"func liftKimiChatFiles(",
		"func reassembleQwenWebStream(",
		"func liftQwenSessionID(",
		"func stripQwenPlaceholders(",
	} {
		if strings.Contains(text, symbol) {
			t.Fatalf("vendor-private decoder symbol %s must live in decoder_<vendor>.go, not content_extractor.go", symbol)
		}
	}
}

func TestDecoderProtocolKeysAreVendorScoped(t *testing.T) {
	vendorOnlyProtocolKeys := map[string][]string{
		"doubao_web":  {"intent_agent_name", "z_agent_name", "z_hit_intervene", "z_intervene_type", "z_is_xianliu", "z_is_jiangji_vlm", "file_link_current_round"},
		"gemini_web":  {"rcid", "f.sid", "bl", "at", "rpcids"},
		"kimi_web":    {"local_conversation_id"},
		"chatgpt_web": {"message_status"},
	}

	for vendor, keys := range vendorOnlyProtocolKeys {
		for _, key := range keys {
			if _, ok := commonProtocolJSONKeys[key]; ok {
				t.Fatalf("vendor-only protocol key %q must not live in commonProtocolJSONKeys", key)
			}
			if !hasProtocolJSONKey(vendor, key) {
				t.Fatalf("vendor %s must own protocol key %q", vendor, key)
			}
		}
	}

	for _, key := range []string{"content", "text", "prompt", "query", "question", "answer", "response", "output"} {
		if _, ok := commonSemanticJSONKeys[key]; !ok {
			t.Fatalf("generic semantic key %q should remain common", key)
		}
	}
}

func TestCatalogDirectedChatGPTWebDecoderIgnoresLooseDeepSeekSniffer(t *testing.T) {
	_, responseDecoder := detectLLMDecoders("chatgpt.com", "/backend-api/conversation")
	if responseDecoder != "chatgpt_web" {
		t.Fatalf("chatgpt.com catalog response decoder = %q, want chatgpt_web", responseDecoder)
	}

	oldSniffer := deepSeekPatchSniffer
	deepSeekPatchSniffer = func(ev sseEvent) bool {
		m, ok := ev.decoded.(map[string]interface{})
		if !ok {
			return false
		}
		_, hasPath := m["p"].(string)
		_, hasOp := m["o"].(string)
		return hasPath && hasOp
	}
	defer func() { deepSeekPatchSniffer = oldSniffer }()

	body := []byte(strings.Join([]string{
		`data: {"p":"/message/content/parts/0","o":"append","v":"ChatGPT catalog 定向回答："}`,
		`data: {"p":"/message/content/parts/0","o":"append","v":"13812345678"}`,
		`data: [DONE]`,
		``,
	}, "\n"))

	extracted := extractResponseContentWithDecoder(body, "text/event-stream", responseDecoder)
	if !strings.Contains(extracted.Text, "ChatGPT catalog 定向回答：13812345678") {
		t.Fatalf("catalog 指定 chatgpt_web 后不得被 DeepSeek 宽松嗅探误吞，实际: %q", extracted.Text)
	}
}

func TestURLReferenceClassificationIsSeparatedFromActions(t *testing.T) {
	source, err := os.ReadFile("content_extractor.go")
	if err != nil {
		t.Fatalf("read content_extractor.go: %v", err)
	}
	text := string(source)
	for _, symbol := range []string{
		"func looksLikeImageURL(",
		"func looksLikeRetainedFileURL(",
	} {
		if strings.Contains(text, symbol) {
			t.Fatalf("URL classifier %s must be split into classify* helpers plus explicit attachment/discard actions", symbol)
		}
	}
	for _, symbol := range []string{
		"func classifyImageURL(",
		"func classifyRetainedFileURL(",
		"func shouldDiscardRetainedFileURLText(",
	} {
		if !strings.Contains(text, symbol) {
			t.Fatalf("content_extractor.go missing separated URL helper %s", symbol)
		}
	}
}
