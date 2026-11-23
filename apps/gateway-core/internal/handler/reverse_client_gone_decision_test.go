package handler

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// 函数级断言：结构化检测函数在客户端断开时返回的 decision 本身必须是干净的
// （不带 incomplete / DetectionFailed / 重试标记），不只是依赖调用方看到哨兵后丢弃它。
// 这样以后新增调用方直接使用 decision 时，不会重新引入「断开被记成检测失败」。

func rcgRequireCleanGoneDecision(t *testing.T, d reverseProxySecurityDecision, err error) {
	t.Helper()
	if !errors.Is(err, errClientGoneDuringSecurity) {
		t.Fatalf("err=%v, want errClientGoneDuringSecurity", err)
	}
	if d.SemanticStatus != "" || d.SemanticReason != "" || d.DetectionFailed || d.RetryUnavailable || len(d.RetryTaskIDs) != 0 || !d.Allowed {
		t.Errorf("断开的 decision 必须干净: %+v", d)
	}
}

// 协议解析失败分支（整包按 unknown 送检）：不能被下面的 incomplete 覆写盖住。
func TestReverseClientGoneStructuredInputParseFailedDecisionIsClean(t *testing.T) {
	e := newRCGEnv(t, rcgScenarios[0], rcgConfigs[1], "/check-input/", "application/json", "")
	body := []byte(`{"model":"m","messages":"not-an-array"}`)
	d, err := e.h.checkRequestSecurityStructured(e.ctx, "req-rcg", nil, body, "application/json", "api.openai.com", "/v1/chat/completions")
	rcgRequireCleanGoneDecision(t, d, err)
	if d.Action != "allow" {
		t.Errorf("协议解析失败分支不应把断开抬成 audit: action=%q", d.Action)
	}
}

// 多分组：第一组断开立即返回，decision 不带前面累积的 incomplete。
func TestReverseClientGoneStructuredInputMultiGroupDecisionIsClean(t *testing.T) {
	e := newRCGEnv(t, rcgScenarios[0], rcgConfigs[1], "/check-input/", "application/json", "")
	d, err := e.h.checkRequestSecurityStructured(e.ctx, "req-rcg", nil, []byte(rcgMultiRequest), "application/json", "api.openai.com", "/v1/chat/completions")
	rcgRequireCleanGoneDecision(t, d, err)
}

// 非流式结构化输出：断开时不叠加 captureTruncated / projectionReason 的 incomplete。
func TestReverseClientGoneStructuredOutputDecisionIsClean(t *testing.T) {
	t.Run("capture_truncated", func(t *testing.T) {
		e := newRCGEnv(t, rcgScenarios[0], rcgConfigs[1], "/check-output/", "application/json", "")
		d, err := e.h.checkResponseSecurityStructuredCaptured(e.ctx, "req-rcg", []byte(rcgChatResponse), "application/json", "api.openai.com", "/v1/chat/completions", true)
		rcgRequireCleanGoneDecision(t, d, err)
	})
	t.Run("projection_reason", func(t *testing.T) {
		// tool_calls 参数 JSON 嵌套超过 maxReverseToolJSONDepth，输出投影会返回 projectionReason。
		deep := strings.Repeat("[", maxReverseToolJSONDepth+6) + strings.Repeat("]", maxReverseToolJSONDepth+6)
		raw, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{
			"role": "assistant", "content": "hello",
			"tool_calls": []any{map[string]any{"function": map[string]any{"name": "f", "arguments": deep}}},
		}}}})
		// 前提：这个 body 确实会产生 projectionReason，否则本子用例就是空测。
		if _, ok, reason := extractReverseProxyLLMOutputInspection("/v1/chat/completions", "application/json", raw, false); !ok || reason == "" {
			t.Fatalf("夹具未触发 projectionReason: ok=%v reason=%q", ok, reason)
		}
		e := newRCGEnv(t, rcgScenarios[0], rcgConfigs[1], "/check-output/", "application/json", "")
		d, err := e.h.checkResponseSecurityStructured(e.ctx, "req-rcg", raw, "application/json", "api.openai.com", "/v1/chat/completions")
		rcgRequireCleanGoneDecision(t, d, err)
	})
}
