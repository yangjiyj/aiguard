package aimsg

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

func ParseOpenAIChatResponse(body []byte) (RetentionProjection, bool) {
	if events := sseDataEvents(body); len(events) > 0 {
		var text strings.Builder
		var artifacts []byte
		for _, event := range events {
			if strings.TrimSpace(event) == "[DONE]" {
				continue
			}
			var root map[string]json.RawMessage
			if json.Unmarshal([]byte(event), &root) != nil {
				continue
			}
			for _, choice := range rawObjects(root["choices"]) {
				delta := rawObject(choice["delta"])
				if value := rawStringExact(delta["content"]); value != "" {
					text.WriteString(value)
				}
				message := rawObject(choice["message"])
				if text.Len() == 0 {
					text.WriteString(outputText(message["content"]))
				}
				if len(message["content"]) > 0 {
					artifacts = append(artifacts, message["content"]...)
				}
			}
		}
		if text.Len() == 0 {
			return RetentionProjection{}, false
		}
		return newOutputProjection("", text.String(), openAIArtifactCandidates(artifacts, "output")), true
	}

	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil {
		return RetentionProjection{}, false
	}
	var output string
	var outputArtifacts []json.RawMessage
	for _, choice := range rawObjects(root["choices"]) {
		message := rawObject(choice["message"])
		if content := outputText(message["content"]); content != "" {
			output = content
			outputArtifacts = append(outputArtifacts, message["content"])
		}
	}
	if output == "" {
		return RetentionProjection{}, false
	}
	return newOutputProjection(rawString(root["model"]), output, candidatesFromRawParts(outputArtifacts, "output")), true
}

func ParseOpenAIResponsesResponse(body []byte) (RetentionProjection, bool) {
	if events := sseDataEvents(body); len(events) > 0 {
		var text strings.Builder
		var completed RetentionProjection
		for _, event := range events {
			var root map[string]json.RawMessage
			if json.Unmarshal([]byte(event), &root) != nil {
				continue
			}
			switch rawString(root["type"]) {
			case "response.output_text.delta":
				text.WriteString(rawStringExact(root["delta"]))
			case "response.completed", "response.done":
				if projection, ok := parseResponsesResponseObject(rawObject(root["response"])); ok {
					completed = projection
				}
			}
		}
		if text.Len() > 0 {
			completed.ModelOutput = text.String()
			completed.Status = ParseComplete
			completed.ParserName = "aimsg.responses"
			completed.ParserVersion = "v1"
			return completed, true
		}
		if completed.Status != "" {
			return completed, true
		}
		return RetentionProjection{}, false
	}

	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil {
		return RetentionProjection{}, false
	}
	return parseResponsesResponseObject(root)
}

func ParseAnthropicMessagesResponse(body []byte) (RetentionProjection, bool) {
	if events := sseDataEvents(body); len(events) > 0 {
		var text strings.Builder
		for _, event := range events {
			var root map[string]json.RawMessage
			if json.Unmarshal([]byte(event), &root) != nil {
				continue
			}
			delta := rawObject(root["delta"])
			if rawString(delta["type"]) == "text_delta" {
				text.WriteString(rawStringExact(delta["text"]))
			}
		}
		if text.Len() == 0 {
			return RetentionProjection{}, false
		}
		return newOutputProjection("", text.String(), nil), true
	}

	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil {
		return RetentionProjection{}, false
	}
	var blocks []anthropicContentBlock
	if json.Unmarshal(root["content"], &blocks) != nil {
		return RetentionProjection{}, false
	}
	var text strings.Builder
	for _, block := range blocks {
		if strings.EqualFold(strings.TrimSpace(block.Type), "text") {
			text.WriteString(block.Text)
		}
	}
	if text.Len() == 0 {
		return RetentionProjection{}, false
	}
	return newOutputProjection(
		rawString(root["model"]),
		text.String(),
		anthropicArtifactCandidates(blocks, "output"),
	), true
}

func parseResponsesResponseObject(root map[string]json.RawMessage) (RetentionProjection, bool) {
	if root == nil {
		return RetentionProjection{}, false
	}
	var text strings.Builder
	var artifacts []json.RawMessage
	for _, item := range rawObjects(root["output"]) {
		switch strings.ToLower(rawString(item["type"])) {
		case "message":
			if strings.EqualFold(rawString(item["role"]), "assistant") {
				text.WriteString(outputText(item["content"]))
				artifacts = append(artifacts, item["content"])
			}
		case "image_generation_call", "image", "file", "document":
			artifacts = append(artifacts, rawPartArray(item))
		}
	}
	if text.Len() == 0 {
		return RetentionProjection{}, false
	}
	return newOutputProjection(rawString(root["model"]), text.String(), candidatesFromRawParts(artifacts, "output")), true
}

func newOutputProjection(model, output string, artifacts []retentionartifact.Candidate) RetentionProjection {
	return RetentionProjection{
		ModelOutput:   output,
		Model:         model,
		ParserName:    "aimsg",
		ParserVersion: "v1",
		Status:        ParseComplete,
		Artifacts:     retentionartifact.Deduplicate(artifacts),
	}
}

func outputText(raw json.RawMessage) string {
	if value := rawStringExact(raw); value != "" {
		return value
	}
	var parts []map[string]json.RawMessage
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var text strings.Builder
	for _, part := range parts {
		switch strings.ToLower(rawString(part["type"])) {
		case "", "text", "output_text":
			text.WriteString(rawStringExact(part["text"]))
		}
	}
	return text.String()
}

func candidatesFromRawParts(parts []json.RawMessage, direction retentionartifact.Direction) []retentionartifact.Candidate {
	var result []retentionartifact.Candidate
	for _, raw := range parts {
		result = append(result, openAIArtifactCandidates(raw, direction)...)
	}
	return retentionartifact.Deduplicate(result)
}

func rawPartArray(object map[string]json.RawMessage) json.RawMessage {
	value, err := json.Marshal([]map[string]json.RawMessage{object})
	if err != nil {
		return nil
	}
	return value
}

func rawObjects(raw json.RawMessage) []map[string]json.RawMessage {
	var result []map[string]json.RawMessage
	if json.Unmarshal(raw, &result) != nil {
		return nil
	}
	return result
}

func rawObject(raw json.RawMessage) map[string]json.RawMessage {
	var result map[string]json.RawMessage
	if json.Unmarshal(raw, &result) != nil {
		return nil
	}
	return result
}

func rawStringExact(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	return ""
}

func sseDataEvents(body []byte) []string {
	if !bytes.Contains(body, []byte("data:")) && !bytes.Contains(body, []byte("event:")) {
		return nil
	}
	normalized := strings.ReplaceAll(string(body), "\r\n", "\n")
	var events []string
	var dataLines []string
	for _, line := range strings.Split(normalized, "\n") {
		if line == "" {
			if len(dataLines) > 0 {
				events = append(events, strings.Join(dataLines, "\n"))
				dataLines = nil
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if len(dataLines) > 0 {
		events = append(events, strings.Join(dataLines, "\n"))
	}
	return events
}
