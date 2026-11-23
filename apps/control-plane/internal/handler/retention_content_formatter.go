package handler

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionfmt"
)

type responsesRetentionEnvelope struct {
	Instructions string          `json:"instructions"`
	Input        json.RawMessage `json:"input"`
}

// parseResponsesRetentionEnvelope reads top-level fields one by one. A
// retention row can be byte-capped after input is complete, making full JSON
// unmarshalling fail even though the user message is available.
func parseResponsesRetentionEnvelope(raw string) (responsesRetentionEnvelope, bool) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return responsesRetentionEnvelope{}, false
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return responsesRetentionEnvelope{}, false
	}
	var envelope responsesRetentionEnvelope
	found := false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		key, ok := token.(string)
		if !ok {
			break
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			break
		}
		switch key {
		case "instructions":
			if json.Unmarshal(value, &envelope.Instructions) == nil && strings.TrimSpace(envelope.Instructions) != "" {
				found = true
			}
		case "input":
			envelope.Input = value
			found = true
		}
	}
	return envelope, found
}

func formatAccessRetentionRequest(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	normalized := retentionfmt.NormalizeNewlines(raw)

	if envelope, ok := parseResponsesRetentionEnvelope(normalized); ok &&
		(strings.TrimSpace(envelope.Instructions) != "" || len(bytes.TrimSpace(envelope.Input)) > 0) {
		userText := responsesRetentionUserText(envelope.Input)
		return aimsg.NormalizeRetainedUserText(userText)
	}
	projected := aimsg.NormalizeRetainedUserText(normalized)
	if projected != strings.TrimSpace(normalized) {
		return projected
	}
	if retentionfmt.IsAgentMetaContent(normalized) {
		return ""
	}
	return projected
}

func formatAccessRetentionResponse(raw, request string) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	normalizedRaw := strings.TrimSpace(retentionfmt.NormalizeNewlines(raw))
	if isCodexRuntimeInstruction(normalizedRaw) {
		return ""
	}
	instructions := responsesRetentionInstructions(request)
	if len([]rune(instructions)) < 32 {
		return aimsg.NormalizeLegacyRetainedAssistantText(raw)
	}
	if !strings.HasPrefix(normalizedRaw, instructions) {
		return aimsg.NormalizeLegacyRetainedAssistantText(raw)
	}
	suffix := strings.TrimSpace(strings.TrimPrefix(normalizedRaw, instructions))
	if suffix == "" {
		return ""
	}
	return aimsg.NormalizeLegacyRetainedAssistantText(suffix)
}

func isCodexRuntimeInstruction(raw string) bool {
	if len([]rune(raw)) < 400 {
		return false
	}
	lower := strings.ToLower(raw)
	markers := []string{
		"you are codex",
		"current_turn",
		"shell_command",
		"sandbox_permissions",
		"working directory",
		"available skills",
	}
	hits := 0
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			hits++
		}
	}
	return hits >= 2 ||
		(strings.Contains(lower, "# personality") &&
			strings.Contains(lower, "vivid inner life as codex"))
}

func responsesRetentionInstructions(raw string) string {
	envelope, ok := parseResponsesRetentionEnvelope(raw)
	if !ok {
		return ""
	}
	return strings.TrimSpace(retentionfmt.NormalizeNewlines(envelope.Instructions))
}

func responsesRetentionUserText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text)
	}

	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return ""
	}
	var users []string
	for _, item := range items {
		var obj map[string]json.RawMessage
		if json.Unmarshal(item, &obj) != nil {
			continue
		}
		role := ""
		_ = json.Unmarshal(obj["role"], &role)
		content := retentionJSONText(obj["content"])
		if content == "" {
			content = retentionJSONText(obj["text"])
		}
		if content == "" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(role), "user") || role == "" {
			users = append(users, content)
		}
	}
	return strings.Join(users, "\n\n")
}

func retentionJSONText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text)
	}
	var parts []json.RawMessage
	if json.Unmarshal(raw, &parts) == nil {
		var texts []string
		for _, part := range parts {
			if text := retentionJSONText(part); text != "" {
				texts = append(texts, text)
			}
		}
		return strings.Join(texts, "\n")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		for _, key := range []string{"text", "value", "input_text", "content"} {
			if text := retentionJSONText(obj[key]); text != "" {
				return text
			}
		}
	}
	return ""
}
func normalizeAccessRetentionContent(item *repository.AccessContentLog) {
	if item == nil {
		return
	}
	rawRequest := item.RequestContent
	item.RequestContent = formatAccessRetentionRequest(rawRequest)
	item.ResponseContent = formatAccessRetentionResponse(item.ResponseContent, rawRequest)
}
