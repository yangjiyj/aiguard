package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"
)

func TestAnthropicPrefixedModelsAnd55Controls(t *testing.T) {
	for _, model := range []string{"anthropic/claude-sonnet-5-5", "us.anthropic.claude-opus-4-8-v1:0", "claude-opus-5-5@20260101", "anthropic/claude-haiku-5-5", "EU.ANTHROPIC.CLAUDE-OPUS-5-5-v1:0", "bedrock/claude-opus-5-5", "vertex_ai/claude-sonnet-5-5", "team/path/claude-haiku-5-5", "apac.anthropic.claude-opus-5-5", "global.anthropic.claude-opus-5-5"} {
		p := resolveAnthropicModelProfile(model)
		if p.MaxOutputTokens != 128000 || !p.RejectsSampling || !p.AdaptiveThinking {
			t.Errorf("模型未识别 %s: %+v", model, p)
		}
	}
	for _, stream := range []bool{false, true} {
		for _, model := range []string{"anthropic/claude-opus-5-5", "anthropic/claude-sonnet-5-5", "anthropic/claude-haiku-5-5"} {
			for _, extra := range []string{`"thinking":{"type":"disabled"}`, `"reasoning_effort":"none"`} {
				body := fmt.Sprintf(`{"model":"x","stream":%t,"messages":[{"role":"user","content":"hi"}],"max_tokens":131072,"temperature":0.7,%s}`, stream, extra)
				got := transformChatForModel(t, model, body)
				if got["max_tokens"] != float64(128000) || got["temperature"] != nil || got["thinking"] != nil {
					t.Fatalf("5.5 参数不合法: %s %+v", model, got)
				}
			}
		}
		got := transformChatForModel(t, "anthropic/claude-haiku-5-5", fmt.Sprintf(`{"model":"x","stream":%t,"messages":[]}`, stream))
		if got["max_tokens"] != float64(4096) {
			t.Fatalf("未设置上限应使用默认 4096: %+v", got)
		}
	}
	if p := resolveAnthropicModelProfile("not-a-claude-model"); p.MaxOutputTokens != 0 {
		t.Fatalf("非 Claude profile 应保持未知: %+v", p)
	}
}

func TestAnthropicUnknownModelWarnsOnce(t *testing.T) {
	anthropicUnknownModelWarnings.Delete("anthropic/claude-foo-9")
	anthropicUnknownModelWarnings.Delete("private-alias-hotfix")
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	for _, model := range []string{"anthropic/claude-foo-9", "private-alias-hotfix"} {
		for i := 0; i < 2; i++ {
			got := transformChatForModel(t, model, `{"model":"x","messages":[],"max_tokens":599999982}`)
			if got["max_tokens"] != float64(128000) {
				t.Errorf("未知 Anthropic 上游应兜底: %+v", got)
			}
		}
		if count := strings.Count(logs.String(), model); count != 1 {
			t.Errorf("模型应只警告一次: %s count=%d logs=%s", model, count, logs.String())
		}
	}
}

func TestAnthropicOutputLimitEnvironmentFormats(t *testing.T) {
	// 现场未提供完整 JSON；此处用 14 个模型覆盖同样的对象格式。
	models := []string{"claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-opus-5", "claude-sonnet-5", "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5", "claude-sonnet-4-5", "claude-opus-4-5", "claude-fable-5-1", "claude-mythos-5-1"}
	entries := map[string]int{}
	for _, model := range models {
		entries[model] = 128000
	}
	fixture, _ := json.Marshal(entries)
	for _, raw := range []string{"a=1,b=2", ` {"a":1,"b":2} `, string(fixture)} {
		t.Run(raw, func(t *testing.T) {
			old := anthropicMaxOutputOverrides
			t.Cleanup(func() { anthropicMaxOutputOverrides = old })
			anthropicMaxOutputOverrides = nil
			t.Setenv(anthropicMaxOutputTokensEnv, raw)
			loadAnthropicMaxOutputOverrides()
			want := 2
			if strings.Contains(raw, "claude") {
				want = 14
			}
			if len(anthropicMaxOutputOverrides) != want {
				t.Fatalf("条目数=%d，应为%d", len(anthropicMaxOutputOverrides), want)
			}
			if want == 2 {
				if resolveAnthropicModelProfile("vendor/Alias").MaxOutputTokens != 1 || resolveAnthropicModelProfile("B-test").MaxOutputTokens != 2 {
					t.Fatal("原始名/规范化名匹配失败")
				}
			} else if resolveAnthropicModelProfile("Anthropic/CLAUDE-HAIKU-5-5").MaxOutputTokens != 128000 {
				t.Fatal("JSON 覆盖未生效")
			}
		})
	}
}

func TestAnthropicOutputLimitEnvironmentWarningsAndDefault(t *testing.T) {
	old := anthropicMaxOutputOverrides
	oldDefault := anthropicDefaultMaxOutputTokens
	t.Cleanup(func() { anthropicMaxOutputOverrides = old; anthropicDefaultMaxOutputTokens = oldDefault })
	t.Setenv(anthropicMaxOutputTokensEnv, `{"valid":2000,"bad":"x","zero":0}`)
	t.Setenv("UAG_ANTHROPIC_MAX_OUTPUT_TOKENS_DEFAULT", "96000")
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	loadAnthropicMaxOutputOverrides()
	if len(anthropicMaxOutputOverrides) != 1 || logs.Len() == 0 {
		t.Fatalf("无效条目应警告且保留有效项: %s", logs.String())
	}
	got := transformChatForModel(t, "new-private-alias-hotfix", `{"model":"x","messages":[],"max_tokens":200000}`)
	if got["max_tokens"] != float64(96000) {
		t.Fatalf("全局兜底未生效: %+v", got)
	}
}

func TestAnthropicOutputLimitEnvironmentRawAndNormalized(t *testing.T) {
	old, oldDefault := anthropicMaxOutputOverrides, anthropicDefaultMaxOutputTokens
	t.Cleanup(func() { anthropicMaxOutputOverrides = old; anthropicDefaultMaxOutputTokens = oldDefault })
	for _, raw := range []string{
		`anthropic/claude-haiku-5-5=120000,claude-haiku-5-5=64000`,
		`{"anthropic/claude-haiku-5-5":120000,"claude-haiku-5-5":64000}`,
	} {
		t.Setenv(anthropicMaxOutputTokensEnv, raw)
		loadAnthropicMaxOutputOverrides()
		if got := resolveAnthropicModelProfile("ANTHROPIC/CLAUDE-HAIKU-5-5").MaxOutputTokens; got != 120000 {
			t.Fatalf("原始名应命中更长前缀: %d", got)
		}
		if got := resolveAnthropicModelProfile("vendor/claude-haiku-5-5@20260101").MaxOutputTokens; got != 64000 {
			t.Fatalf("规范化名应命中无供应商前缀: %d", got)
		}
	}
	for _, raw := range []string{`{"broken":`, `missing-equals,bad=no,zero=0,negative=-1,=10`} {
		t.Setenv(anthropicMaxOutputTokensEnv, raw)
		t.Setenv(anthropicMaxOutputTokensDefaultEnv, "invalid")
		var logs bytes.Buffer
		previous := log.Writer()
		log.SetOutput(&logs)
		loadAnthropicMaxOutputOverrides()
		log.SetOutput(previous)
		if len(anthropicMaxOutputOverrides) != 0 || anthropicDefaultMaxOutputTokens != 128000 || logs.Len() == 0 {
			t.Fatalf("无效配置应警告且恢复默认: %s", logs.String())
		}
	}
}
