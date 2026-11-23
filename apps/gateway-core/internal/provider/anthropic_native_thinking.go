package provider

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 原生 /v1/messages 发往 Anthropic 类型上游前的 thinking 兼容改写。
//
// 背景：Claude Code 等原生客户端按自己认识的模型代际写 thinking，网关后面的上游模型却可能是
// 另一代——5.5 系列上游只认 adaptive（配合 output_config.effort），enabled+budget_tokens 一律 400，
// disabled / between_tools 又各有各的支持范围。上游 400 后客户端只能看到网关的统一文案，
// 没法自己纠正。这里按模型 profile（anthropic_model_profile.go）把客户端写法翻译成该模型接受的写法。
//
// 原则：
//   - 只按请求体里的 model（即上游模型 id）查 profile；表外 / 未知模型不改写。
//   - 没有可改写的内容时原样返回同一份字节，不重新序列化。
//   - 只动 thinking 与 output_config.effort；其余顶层字段保持原始字节。
//   - 日志只记录模型名、改写类型与 request_id，不记录请求内容与预算数值。
const (
	nativeThinkingEnabledToAdaptive     = "enabled_to_adaptive"
	nativeThinkingDisabledToBetween     = "disabled_to_between_tools"
	nativeThinkingDisabledRemoved       = "disabled_removed"
	nativeThinkingBetweenToDisabled     = "between_tools_to_disabled"
	nativeThinkingBetweenToolsRemoved   = "between_tools_removed"
	nativeThinkingEffortLowBudgetMax    = 4096  // budget_tokens 小于该值映射为 low
	nativeThinkingEffortMediumBudgetMax = 16384 // 小于该值映射为 medium，否则 high
)

// anthropicEffortFromThinkingBudget 把客户端的 thinking 预算折算成 output_config.effort。
// 与 Chat 路径的 anthropicEffortFromBudget（面向 OpenAI thinking_budget 提示）刻意分开：
// 原生客户端的 budget_tokens 是真实预算，档位按任务书约定取 4096 / 16384 为界。
func anthropicEffortFromThinkingBudget(budget int64) string {
	switch {
	case budget < nativeThinkingEffortLowBudgetMax:
		return "low"
	case budget < nativeThinkingEffortMediumBudgetMax:
		return "medium"
	default:
		return "high"
	}
}

type nativeThinkingRewrite struct {
	kind    string
	remove  bool           // 去掉 thinking 字段
	replace map[string]any // 整体替换 thinking
	effort  string         // 非空：客户端没带 effort 时补上
}

func applyNativeAnthropicThinkingCompat(payload []byte, envelope *modelrouter.RequestEnvelope) ([]byte, error) {
	if !bytes.Contains(payload, []byte(`"thinking"`)) {
		return payload, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		// 解析失败交给后面的 capNativeAnthropicOutputTokens / 上游给出原有报错，这里不改变既有行为。
		return payload, nil
	}
	rawThinking, ok := fields["thinking"]
	if !ok {
		return payload, nil
	}
	var model string
	if raw, ok := fields["model"]; ok {
		_ = json.Unmarshal(raw, &model)
	}
	profile := resolveAnthropicModelProfile(model)
	thinking, ok := decodeNativeJSONObject(rawThinking)
	if !ok {
		return payload, nil
	}

	outputConfig, hasOutputConfig := decodeNativeJSONObject(fields["output_config"])
	clientEffort := ""
	if hasOutputConfig {
		if value, ok := outputConfig["effort"].(string); ok {
			clientEffort = strings.ToLower(strings.TrimSpace(value))
		}
	}

	rewrite, changed := planNativeThinkingRewrite(profile, thinking, clientEffort)
	if !changed {
		return payload, nil
	}

	if rewrite.remove {
		delete(fields, "thinking")
	} else {
		encoded, err := marshalNativeJSON(rewrite.replace)
		if err != nil {
			return payload, nil
		}
		fields["thinking"] = encoded
	}
	if rewrite.effort != "" && clientEffort == "" {
		switch {
		case hasOutputConfig:
			// 客户端已带 output_config（可能含 format 等）：只补 effort，且不覆盖已有 effort。
			if _, exists := outputConfig["effort"]; !exists {
				outputConfig["effort"] = rewrite.effort
				if encoded, err := marshalNativeJSON(outputConfig); err == nil {
					fields["output_config"] = encoded
				}
			}
		case len(fields["output_config"]) == 0:
			if encoded, err := marshalNativeJSON(map[string]any{"effort": rewrite.effort}); err == nil {
				fields["output_config"] = encoded
			}
			// output_config 存在但不是对象：不碰，交给上游报它自己的错误。
		}
	}

	rewritten, err := marshalNativeJSON(fields)
	if err != nil {
		return payload, nil
	}
	requestID := ""
	if envelope != nil {
		requestID = envelope.RequestID
	}
	log.Printf("[provider.compat] native_thinking_rewrite model=%s kind=%s request_id=%s",
		normalizeAnthropicModelName(model), rewrite.kind, requestID)
	return rewritten, nil
}

// planNativeThinkingRewrite 是纯函数：给定模型 profile 与客户端 thinking，决定怎么改写。
func planNativeThinkingRewrite(profile anthropicModelProfile, thinking map[string]any, clientEffort string) (nativeThinkingRewrite, bool) {
	kind, _ := thinking["type"].(string)
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "enabled":
		if !profile.RejectsBudgetTokens {
			return nativeThinkingRewrite{}, false
		}
		replaced := make(map[string]any, len(thinking))
		for key, value := range thinking {
			if key == "budget_tokens" {
				continue
			}
			replaced[key] = value
		}
		replaced["type"] = "adaptive"
		rewrite := nativeThinkingRewrite{kind: nativeThinkingEnabledToAdaptive, replace: replaced}
		if budget, ok := anthropicIntValue(thinking["budget_tokens"]); ok && budget > 0 {
			rewrite.effort = anthropicEffortFromThinkingBudget(budget)
		}
		return rewrite, true
	case "disabled":
		switch profile.ThinkingOff {
		case thinkingOffBetweenTools:
			// between_tools 只在 effort high 及以下可用；xhigh / max 时它同样会 400，
			// 此时客户端明显想要深度思考，直接省略 thinking（模型默认 adaptive）。
			if clientEffort == "xhigh" || clientEffort == "max" {
				return nativeThinkingRewrite{kind: nativeThinkingDisabledRemoved, remove: true}, true
			}
			return nativeThinkingRewrite{kind: nativeThinkingDisabledToBetween, replace: map[string]any{"type": "between_tools"}}, true
		case thinkingOffOmit:
			return nativeThinkingRewrite{kind: nativeThinkingDisabledRemoved, remove: true}, true
		}
	case "between_tools":
		switch profile.ThinkingOff {
		case thinkingOffDisabled:
			return nativeThinkingRewrite{kind: nativeThinkingBetweenToDisabled, replace: map[string]any{"type": "disabled"}}, true
		case thinkingOffOmit:
			return nativeThinkingRewrite{kind: nativeThinkingBetweenToolsRemoved, remove: true}, true
		}
	}
	return nativeThinkingRewrite{}, false
}

// decodeNativeJSONObject 解码 JSON 对象并保留数字的原始写法（json.Number）。
func decodeNativeJSONObject(raw json.RawMessage) (map[string]any, bool) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

// marshalNativeJSON 序列化时不转义 <、>、&，避免无谓改变客户端内容的字节形态。
func marshalNativeJSON(value any) (json.RawMessage, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}
