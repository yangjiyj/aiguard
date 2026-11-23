package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
	"log"
	"strings"
)

// Inspect model-produced text, reasoning and tool arguments; request instructions
// and transport metadata are excluded from the output projection.
func extractReverseProxyLLMOutput(targetPath, contentType string, body []byte) (string, bool) {
	return extractReverseProxyLLMOutputCaptured(targetPath, contentType, body, false)
}

func extractReverseProxyLLMOutputCaptured(targetPath, contentType string, body []byte, captureTruncated bool) (string, bool) {
	text, ok, _ := extractReverseProxyLLMOutputInspection(targetPath, contentType, body, captureTruncated)
	return text, ok
}

func extractReverseProxyLLMOutputInspection(targetPath, contentType string, body []byte, captureTruncated bool) (string, bool, string) {
	if len(bytes.TrimSpace(body)) == 0 {
		return "", false, ""
	}
	lowerPath := strings.ToLower(targetPath)
	if isReverseProxySSE(contentType, body) {
		extras, reason := reverseProxySSEInspectionExtras(targetPath, body)
		join := func(text string) (string, bool, string) {
			text, ok := joinReverseInspectionOutput(text, extras)
			return text, ok, reason
		}
		switch {
		case strings.Contains(lowerPath, "/v1/responses"):
			text := extractReverseProxyResponsesSSEOutput(body)
			if captureTruncated && !hasReverseProxyResponsesSSEFinalOutput(body) {
				return "", false, reason
			}
			return join(text)
		case strings.Contains(lowerPath, "/v1/messages"):
			if captureTruncated {
				return "", false, reason
			}
			text := extractAnthropicSSEOutput(body)
			return join(text)
		default:
			if captureTruncated {
				return "", false, reason
			}
			text := extractChatCompletionsSSEOutput(body)
			return join(text)
		}
	}
	if !isReverseProxyJSON(contentType, body) {
		return "", false, ""
	}
	extras, reason := reverseProxyJSONInspectionExtras(targetPath, body)
	var text string
	switch {
	case strings.Contains(lowerPath, "/v1/responses"):
		text, _ = extractResponsesJSONOutput(body)
	case strings.Contains(lowerPath, "/v1/messages"):
		text, _ = extractAnthropicJSONOutput(body)
	default:
		text, _ = extractChatCompletionsJSONOutput(body)
	}
	text, ok := joinReverseInspectionOutput(text, extras)
	return text, ok, reason
}

type reverseProxySSEEvent struct {
	Name string
	Data []byte
}

func reverseProxySSEEvents(body []byte) []reverseProxySSEEvent {
	normalized := strings.ReplaceAll(string(body), "\r\n", "\n")
	blocks := strings.Split(normalized, "\n\n")
	events := make([]reverseProxySSEEvent, 0, len(blocks))
	for _, block := range blocks {
		event := reverseProxySSEEvent{}
		dataLines := make([]string, 0, 1)
		for _, rawLine := range strings.Split(block, "\n") {
			line := strings.TrimSpace(rawLine)
			switch {
			case strings.HasPrefix(line, "event:"):
				event.Name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
		if len(dataLines) == 0 {
			continue
		}
		event.Data = []byte(strings.Join(dataLines, "\n"))
		events = append(events, event)
	}
	return events
}

func hasReverseProxyResponsesSSEFinalOutput(body []byte) bool {
	for _, event := range reverseProxySSEEvents(body) {
		var payload struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(event.Data, &payload) != nil {
			continue
		}
		eventType := event.Name
		if eventType == "" {
			eventType = payload.Type
		}
		if eventType == "response.output_text.done" && strings.TrimSpace(payload.Text) != "" {
			return true
		}
	}
	return false
}

// Known LLM protocols contribute only model-produced output fields.
func (h *ReverseProxyHandler) checkResponseSecurityStructured(ctx context.Context, requestID string, body []byte, contentType, targetHost, targetPath string) (reverseProxySecurityDecision, error) {
	return h.checkResponseSecurityStructuredCaptured(ctx, requestID, body, contentType, targetHost, targetPath, false)
}

func (h *ReverseProxyHandler) checkResponseSecurityStructuredCaptured(ctx context.Context, requestID string, body []byte, contentType, targetHost, targetPath string, captureTruncated bool) (reverseProxySecurityDecision, error) {
	if llmcatalog.IsTelemetry(targetHost, targetPath) || (h.runtimeConfigClient != nil && !h.runtimeConfigClient.InspectionPolicy(ctx).InspectModelOutput) {
		return reverseProxySecurityDecision{Body: body, Allowed: true, Action: "allow"}, nil
	}
	if !isReverseProxyChatEndpoint(targetHost, targetPath) {
		return h.checkResponseSecurity(ctx, requestID, body, contentType, targetHost, targetPath)
	}
	output, ok, projectionReason := extractReverseProxyLLMOutputInspection(targetPath, contentType, body, captureTruncated)
	if ok {
		decision, err := h.checkSecurityWithExtras(
			ctx, requestID, "/check-output/", body, output, "text/plain",
			targetHost, targetPath, "", map[string]interface{}{
				"verified_content": true, "verified_stage": "output", "extraction": "verified_final_output",
			},
		)
		if clientGoneDuring(ctx, err) {
			// 客户端已断开：decision 不可用，直接把哨兵交给调用方，不再叠加 projection/截断的 incomplete。
			return decision, err
		}
		if captureTruncated {
			decision.SemanticStatus = "incomplete"
			decision.SemanticReason = "output_capture_truncated"
		}
		if projectionReason != "" {
			mergeReverseStreamDecision(&decision, h.reverseInspectionFailure(ctx, nil, projectionReason))
			decision = h.applyReverseInspectionPolicy(ctx, decision)
			decision.Body = body
		}
		if err != nil || decision.Action != "mask" {
			return decision, err
		}
		decision.Body = body
		decision.Action = "audit"
		decision.Allowed = true
		return decision, nil
	}
	if projectionReason != "" {
		decision := h.reverseInspectionFailure(ctx, nil, projectionReason)
		decision.Body = body
		return decision, nil
	}
	if captureTruncated {
		return reverseProxySecurityDecision{Body: body, Allowed: true, Action: "audit", SemanticStatus: "incomplete", SemanticReason: "output_capture_truncated"}, nil
	}
	log.Printf("Reverse proxy verified output unavailable: request=%s target=%s reason=no_final_user_visible_text", requestID, targetPath)
	return reverseProxySecurityDecision{Body: body, Action: "allow", Allowed: true}, nil
}

func extractResponsesJSONOutput(body []byte) (string, bool) {
	var response struct {
		OutputText string `json:"output_text"`
		Output     []struct {
			Type    string          `json:"type"`
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", false
	}
	if text := strings.TrimSpace(response.OutputText); text != "" {
		return text, true
	}
	var parts []string
	for _, item := range response.Output {
		if strings.ToLower(strings.TrimSpace(item.Type)) != "message" ||
			strings.ToLower(strings.TrimSpace(item.Role)) != "assistant" {
			continue
		}
		if text := llmTextContent(item.Content); text != "" {
			parts = append(parts, text)
		}
	}
	text := strings.Join(parts, "\n")
	return text, strings.TrimSpace(text) != ""
}

func extractChatCompletionsJSONOutput(body []byte) (string, bool) {
	var response struct {
		Choices []struct {
			Message struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
			Text string `json:"text"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", false
	}
	var parts []string
	for _, choice := range response.Choices {
		if text := llmTextContent(choice.Message.Content); text != "" {
			parts = append(parts, text)
			continue
		}
		if text := strings.TrimSpace(choice.Text); text != "" {
			parts = append(parts, text)
		}
	}
	text := strings.Join(parts, "\n")
	return text, strings.TrimSpace(text) != ""
}

func extractAnthropicJSONOutput(body []byte) (string, bool) {
	var response struct {
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", false
	}
	text := llmTextContent(response.Content)
	return text, strings.TrimSpace(text) != ""
}

func extractChatCompletionsSSEOutput(body []byte) string {
	var parts []string
	for _, payload := range reverseProxySSEPayloads(body) {
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content json.RawMessage `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal(payload, &chunk) != nil {
			continue
		}
		for _, choice := range chunk.Choices {
			if text := llmDeltaTextContent(choice.Delta.Content); text != "" {
				parts = append(parts, text)
			}
		}
	}
	return strings.Join(parts, "")
}

func extractAnthropicSSEOutput(body []byte) string {
	var parts []string
	for _, payload := range reverseProxySSEPayloads(body) {
		var event struct {
			Type  string `json:"type"`
			Delta struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"delta"`
		}
		if json.Unmarshal(payload, &event) != nil ||
			event.Type != "content_block_delta" ||
			event.Delta.Type != "text_delta" {
			continue
		}
		parts = append(parts, event.Delta.Text)
	}
	return strings.Join(parts, "")
}

func reverseProxySSEPayloads(body []byte) [][]byte {
	var payloads [][]byte
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		payloads = append(payloads, []byte(payload))
	}
	return payloads
}

func llmTextContent(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text)
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var texts []string
	for _, part := range parts {
		switch strings.ToLower(strings.TrimSpace(part.Type)) {
		case "", "text", "input_text", "output_text":
			if text := strings.TrimSpace(part.Text); text != "" {
				texts = append(texts, text)
			}
		}
	}
	return strings.Join(texts, "\n")
}

// llmDeltaTextContent 保留流式 token 的前后空格；对 delta 使用 TrimSpace 会把
// "Chat " + "流式回答" 错拼成 "Chat流式回答"。
func llmDeltaTextContent(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	return llmTextContent(raw)
}
