package handler

import (
	"testing"
)

// 任务 3.5：模型能力标签落地（P1-16，支柱①模型治理）。
//
// 现状根因：UpsertByProviderAndName 的 INSERT 把 capabilities_json 硬编码成 '{}'，
// UPDATE 从不碰它 → 每个同步进来的模型出生即空能力。provider catalog /v1/models
// 只回 model-ID 字符串（无能力字段），pricing seed 价格专用，shared-go/llmcatalog
// 按 host/path 编排（非 model 名），gateway-core modelrouter 在不可导入的独立 module。
// 全仓无可串接的权威 per-model 能力源 → 只能保守名称推断，且必须带溯源标记（保守不编造）。
//
// 设计（保守 + 溯源）：只对高信号 token 打标，其余默认 text。每条带 source：
// 有信号→name_inference，无信号→default。刻意不把 gpt-4-vision 这类「输入支持图像
// 的对话模型」当 image，避免把输入模态误当成图像生成能力。词表对齐 classifyEndpointKind。
// 纯函数直测，绕开 Dependencies.ModelRepo 具体类型 nil-panic（同 3.3/3.4）。

func TestClassifyModelModality(t *testing.T) {
	cases := []struct {
		name                string
		wantType            string
		wantSource          string
		wantChatCompletions bool
	}{
		// High-signal modality names.
		{"text-embedding-3-small", "embedding", "name_inference", false},
		{"text-embedding-ada-002", "embedding", "name_inference", false},
		{"bge-large-zh-v1.5-embedding", "embedding", "name_inference", false},
		{"whisper-1", "audio", "name_inference", false},
		{"gpt-4o-mini-tts", "audio", "name_inference", false},
		{"dall-e-3", "image", "name_inference", false},
		{"stable-diffusion-xl-base-1.0", "image", "name_inference", false},
		{"gpt-image-1", "image", "name_inference", false},
		{"gpt-image-2", "image", "name_inference", false},
		{"DALL-E-3", "image", "name_inference", false},
		{"Text-Embedding-3-Large", "embedding", "name_inference", false},
		// Responses is never inferred from a GPT-like name.
		{"gpt-4o", "text", "default", true},
		{"gpt-4-vision-preview", "text", "default", true},
		{"gpt-5.4", "text", "default", true},
		{"gpt-5.5", "text", "default", true},
		{"gpt-5.6", "text", "default", true},
		{"gpt-5.6-luna", "text", "default", true},
		{"gpt-5.6-sol", "text", "default", true},
		{"gpt-5.6-terra", "text", "default", true},
		{"GPT-5.6-LUNA", "text", "default", true},
		{"gpt-5.6-other", "text", "default", true},
		// Non-GPT routes must not inherit native Responses capability.
		{"claude-3-5-sonnet-20241022", "text", "default", false},
		{"", "text", "default", false},
	}

	for _, c := range cases {
		got := classifyModelModality(c.name)
		m, ok := got["modality"].(map[string]interface{})
		if !ok {
			t.Fatalf("%q: expected modality map, got %#v", c.name, got["modality"])
		}
		if m["type"] != c.wantType {
			t.Errorf("%q: type want %q, got %v", c.name, c.wantType, m["type"])
		}
		if m["source"] != c.wantSource {
			t.Errorf("%q: source want %q, got %v", c.name, c.wantSource, m["source"])
		}

		protocols, ok := got["protocols"].(map[string]interface{})
		if c.wantChatCompletions && (!ok || protocols["chat_completions"] != true) {
			t.Errorf("%q: expected chat_completions=true, got %#v", c.name, got["protocols"])
		}
		if ok && protocols["responses_native"] == true {
			t.Errorf("%q: unexpected native Responses protocol marker: %#v", c.name, protocols)
		}
		if c.wantType == "image" {
			if !ok || protocols["images"] != true {
				t.Errorf("%q: expected images=true, got %#v", c.name, got["protocols"])
			}
		} else if c.wantType != "image" && ok && protocols["images"] == true {
			t.Errorf("%q: unexpected images protocol marker: %#v", c.name, protocols)
		}
	}
}

func TestProtocolCapabilitiesFromSelections(t *testing.T) {
	got, err := protocolCapabilitiesFromSelections([]string{"chat_completions", "responses", "anthropic_messages"})
	if err != nil {
		t.Fatal(err)
	}
	if got["chat_completions"] != true || got["responses_native"] != true || got["anthropic_messages"] != true {
		t.Fatalf("unexpected protocol mapping: %#v", got)
	}
	if got, err := protocolCapabilitiesFromSelections([]string{"auto"}); err != nil || got != nil {
		t.Fatalf("auto selection should defer to detection: got=%#v err=%v", got, err)
	}
	if _, err := protocolCapabilitiesFromSelections([]string{"auto", "responses"}); err == nil {
		t.Fatal("auto cannot be combined with an explicit protocol")
	}
}

func TestVertexIsAnExplicitRuntimeProviderType(t *testing.T) {
	if !isSupportedRuntimeProviderType("vertex") {
		t.Fatal("vertex provider must be accepted as an explicit Gemini/Vertex adapter type")
	}
}

func TestOpenAICompatibleProviderRegistryIsUsedForAdmissionAndProbe(t *testing.T) {
	for _, providerType := range []string{"doubao", "kimi", "newapi", "openrouter", "xinference"} {
		if !isSupportedRuntimeProviderType(providerType) {
			t.Fatalf("provider %q must be accepted by runtime admission", providerType)
		}
		if !providerSupportsOpenAIProtocolProbe(providerType) {
			t.Fatalf("provider %q must use real OpenAI protocol probing", providerType)
		}
	}
}
