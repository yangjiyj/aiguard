package handler

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// 配置金额额度后，控制面在准入阶段按可用金额折算有约束意义的输出 token 上限。
// 网关仅收紧客户端已设置的上限，不把钱包金额折算的 cap 注入缺省请求：
//   - OpenAI Chat：max_tokens / max_completion_tokens
//   - OpenAI Responses：max_output_tokens
//   - Anthropic Messages：max_tokens（同时让 thinking.budget_tokens 保持小于 max_tokens）
// 未设置上限时保留供应商默认值；流式请求由本地预算 guard 兜底截断。
// 控制面未下发上限时请求体逐字节不变。

// billingOutputTokenCap 返回准入时下发的输出上限；未下发（无金额额度、折算值过大或输出免费）时 ok=false。
func billingOutputTokenCap(preflight BillingPreflight, requestID string) (int64, bool) {
	provider, ok := preflight.(streamBudgetProvider)
	if !ok || provider == nil {
		return 0, false
	}
	limit, _, ok := provider.StreamBudget(requestID)
	if !ok {
		return 0, false
	}
	// 上游不接受 0：预算连 1 个输出 token 都不够时也按 1 下发，由本地兜底截断收尾。
	if limit < 1 {
		limit = 1
	}
	return limit, true
}

// capChatRequestOutputTokens 同时收紧结构体字段与原始请求体：后续 marshalChatProviderBody
// 以结构体字段覆盖原始体，只改一边会被另一边覆盖回去。
func capChatRequestOutputTokens(req *ChatCompletionRequest, body []byte, providerType string, limit int64) ([]byte, bool, error) {
	if req == nil {
		return body, false, nil
	}
	changed := false
	if req.MaxTokens > 0 && int64(req.MaxTokens) > limit {
		req.MaxTokens, changed = int(limit), true
	}
	if req.MaxCompletionTokens > 0 && int64(req.MaxCompletionTokens) > limit {
		req.MaxCompletionTokens, changed = int(limit), true
	}
	capped, bodyChanged, err := capJSONOutputTokens(body, []string{"max_tokens", "max_completion_tokens"}, limit)
	if err != nil {
		return body, false, err
	}
	return capped, changed || bodyChanged, nil
}

// capResponsesRequestOutputTokens 收紧原生 Responses 请求的 max_output_tokens。
func capResponsesRequestOutputTokens(body []byte, limit int64) ([]byte, bool, error) {
	return capJSONOutputTokens(body, []string{"max_output_tokens"}, limit)
}

// capMessagesRequestOutputTokens 收紧原生 Anthropic Messages 请求的 max_tokens；
// 启用了扩展思考时同步让 budget_tokens 小于 max_tokens（上游硬性要求），预算放不下 1024 时关闭 thinking。
func capMessagesRequestOutputTokens(body []byte, limit int64) ([]byte, bool, error) {
	capped, changed, err := capJSONOutputTokens(body, []string{"max_tokens"}, limit)
	if err != nil || !changed {
		return capped, changed, err
	}
	fields, err := decodeJSONObject(capped)
	if err != nil {
		return body, false, err
	}
	rawThinking, ok := fields["thinking"]
	if !ok {
		return capped, true, nil
	}
	var thinking map[string]json.RawMessage
	if json.Unmarshal(rawThinking, &thinking) != nil {
		return capped, true, nil
	}
	var thinkingType string
	_ = json.Unmarshal(thinking["type"], &thinkingType)
	budget, hasBudget := jsonInt(thinking["budget_tokens"])
	if !strings.EqualFold(thinkingType, "enabled") || !hasBudget || budget < limit {
		return capped, true, nil
	}
	budget = limit - 1
	if budget < 1024 {
		delete(fields, "thinking")
	} else {
		thinking["budget_tokens"] = json.RawMessage(itoa64(budget))
		encoded, err := json.Marshal(thinking)
		if err != nil {
			return body, false, err
		}
		fields["thinking"] = encoded
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return body, false, err
	}
	return out, true, nil
}

// capJSONOutputTokens 把 fields 中已存在且大于上限的值收紧到上限；客户端未设置时不注入。
// 没有任何改动时原样返回请求体（不重新编码）。
func capJSONOutputTokens(body []byte, fields []string, limit int64) ([]byte, bool, error) {
	object, err := decodeJSONObject(body)
	if err != nil {
		return body, false, err
	}
	changed := false
	for _, field := range fields {
		raw, ok := object[field]
		if !ok || string(raw) == "null" {
			continue
		}
		value, isInt := jsonInt(raw)
		if !isInt || value <= 0 {
			// 非法或 0 值交给上游按原样报错/处理。
			continue
		}
		if value > limit {
			object[field] = json.RawMessage(itoa64(limit))
			changed = true
		}
	}
	if !changed {
		return body, false, nil
	}
	out, err := json.Marshal(object)
	if err != nil {
		return body, false, err
	}
	return out, true, nil
}

func decodeJSONObject(body []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	if object == nil {
		object = map[string]json.RawMessage{}
	}
	return object, nil
}

func jsonInt(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&number) != nil {
		return 0, false
	}
	value, err := number.Int64()
	return value, err == nil
}

func itoa64(value int64) string { return strconv.FormatInt(value, 10) }
