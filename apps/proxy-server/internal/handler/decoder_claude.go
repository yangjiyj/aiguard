package handler

import "strings"

func decodeClaudeWebResponse(body []byte, contentType string) (ExtractedContent, bool) {
	if !isEventStream(contentType, body) {
		return ExtractedContent{}, false
	}
	return reassembleClaudeBlockStream(parseSSEDataEvents(body))
}

func reassembleClaudeBlockStream(events []sseEvent) (ExtractedContent, bool) {
	matched := false
	var answer, reasoning, toolInput strings.Builder
	for _, ev := range events {
		m, ok := ev.decoded.(map[string]interface{})
		if !ok {
			continue
		}
		if m["type"] != "content_block_delta" {
			continue
		}
		delta, ok := m["delta"].(map[string]interface{})
		if !ok {
			continue
		}
		switch delta["type"] {
		case "text_delta":
			if s, ok := delta["text"].(string); ok {
				matched = true
				answer.WriteString(s)
			}
		case "thinking_delta":
			if s, ok := delta["thinking"].(string); ok {
				matched = true
				reasoning.WriteString(s)
			}
		case "input_json_delta":
			// 工具调用入参常是自然语言、按 token 下发，拼回回答避免敏感正文漏检。
			if s, ok := delta["partial_json"].(string); ok {
				matched = true
				toolInput.WriteString(s)
			}
		default:
			// signature_delta 及其它协议增量忽略。
		}
	}
	att := collectStreamAttachments(events)
	if !matched || (answer.Len() == 0 && reasoning.Len() == 0 && toolInput.Len() == 0 && len(att) == 0) {
		return ExtractedContent{}, false
	}
	return buildReassembledExtractedWithTool(answer.String(), reasoning.String(), toolInput.String(), att), true
}

// reassembleOpenAIResponsesStream 处理 OpenAI Responses API 的流式 SSE。
// GitHub Copilot / VS Code Copilot Chat 经正向代理(:3128)后即走此格式：
// 没有 choices[]，而是按 {"type":"response.*","delta":"..."} 下发增量。
//
//	response.output_text.delta              → 回答正文增量
//	response.refusal.delta                  → 拒答正文（同属回答，避免漏检）
//	response.function_call_arguments.delta  → 工具调用入参(常为自然语言)拼回回答
//	response.reasoning_summary_text.delta / response.reasoning_text.delta → 思考增量
//
// 只累积 *.delta；忽略 *.done（整段回显）与 response.completed（整个 response 对象，
// 内含 output[] 全文、resp_/msg_/rs_ 等 ID、reasoning 的 encrypted_content 加密块）。
// 这样回答只留存一份、思考以 [reasoning] 分开，且绝不把 ID/加密块塞进给人看的留存，
// 契合 Track5「不要出现什么编码、什么ID，正式一点给人看」。仅当出现已知 response.*
// 内容增量才判定命中，避免误吞 OpenAI-chat(choices[])/DeepSeek({o,p,v})/Claude 流；
// 个别只发 .done 不发 .delta 的实现，回退到最长的 output_text.done 全文。
