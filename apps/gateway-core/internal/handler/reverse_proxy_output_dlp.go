package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const maxReverseToolJSONDepth = 64
const maxReverseAuxiliaryText = 8 * 1024 * 1024

// Keep independent calls/choices separate while joining each argument stream.
type reverseAuxiliaryOutput struct {
	order         []string
	parts         map[string]*strings.Builder
	tools         map[string]bool
	toolSnapshots map[string][]string
	hold          bool
}

func (a *reverseAuxiliaryOutput) add(key, value string, delta bool) string {
	if value == "" {
		return ""
	}
	if a.parts == nil {
		a.parts = make(map[string]*strings.Builder)
	}
	part, exists := a.parts[key]
	if !exists {
		part = &strings.Builder{}
		a.parts[key] = part
		a.order = append(a.order, key)
	}
	old := part.String()
	if delta {
		part.WriteString(value)
		return value
	}
	if strings.Contains(old, value) {
		return ""
	}
	// A benign terminal object cannot erase bytes observed in earlier deltas.
	if old == "" || strings.Contains(value, old) {
		part.Reset()
		part.WriteString(value)
	} else {
		part.WriteString("\n")
		part.WriteString(value)
	}
	return value
}

func (a *reverseAuxiliaryOutput) addTool(key, value string, delta bool) string {
	if a.tools == nil {
		a.tools = make(map[string]bool)
	}
	a.tools[key] = true
	if !delta && value != "" {
		if part := a.parts[key]; part != nil {
			old := part.String()
			if old != "" && !strings.Contains(old, value) && !strings.Contains(value, old) {
				if a.toolSnapshots == nil {
					a.toolSnapshots = make(map[string][]string)
				}
				// A divergent terminal JSON document must decode independently of an
				// earlier incomplete delta, while both remain in the raw evidence.
				a.toolSnapshots[key] = append(a.toolSnapshots[key], value)
			}
		}
	}
	return a.add(key, value, delta)
}

func (a *reverseAuxiliaryOutput) String() string {
	text, _ := a.inspectionText()
	return text
}

func (a *reverseAuxiliaryOutput) inspectionText() (string, string) {
	parts := make([]string, 0, len(a.order))
	remaining := maxReverseAuxiliaryText
	for _, key := range a.order {
		if text := a.parts[key].String(); text != "" {
			if len(text)+1 > remaining {
				return strings.Join(parts, "\n"), "output_tool_json_text_limit_exceeded"
			}
			parts = append(parts, text)
			remaining -= len(text) + 1
			if a.tools[key] {
				sources := append([]string{text}, a.toolSnapshots[key]...)
				for _, source := range sources {
					decoded, reason := decodedOutputToolJSON(source, remaining)
					if decoded != "" {
						parts = append(parts, decoded)
						remaining -= len(decoded) + 1
					}
					if reason != "" {
						return strings.Join(parts, "\n"), reason
					}
				}
			}
		}
	}
	return strings.Join(parts, "\n"), ""
}

// Decode only structured arguments in known protocol tool fields. Raw bytes stay
// in the projection, including earlier snapshots and incomplete streamed JSON.
func decodedOutputToolJSON(raw string, limit int) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || (raw[0] != '{' && raw[0] != '[') {
		return "", ""
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	depth := 0
	var decoded strings.Builder
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return decoded.String(), ""
		}
		if err != nil {
			return decoded.String(), ""
		}
		switch value := token.(type) {
		case json.Delim:
			if value == '{' || value == '[' {
				depth++
				if depth > maxReverseToolJSONDepth {
					return decoded.String(), "output_tool_json_depth_limit_exceeded"
				}
			} else {
				depth--
			}
		case string:
			if value == "" || strings.Contains(raw, value) {
				continue
			}
			if decoded.Len()+len(value)+1 > limit {
				return decoded.String(), "output_tool_json_text_limit_exceeded"
			}
			decoded.WriteString(value)
			decoded.WriteByte('\n')
		}
	}
}

func joinNonemptyOutputParts(parts []string) string {
	var present []string
	for _, part := range parts {
		if part != "" {
			present = append(present, part)
		}
	}
	return strings.Join(present, "\n")
}

func outputArgumentText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	if raw[0] == '{' || raw[0] == '[' {
		var compact bytes.Buffer
		if json.Compact(&compact, raw) == nil {
			return compact.String()
		}
	}
	return ""
}

func outputReasoningText(raw json.RawMessage) string {
	if text := llmDeltaTextContent(raw); text != "" {
		return text
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var texts []string
	for _, part := range parts {
		if part.Text != "" {
			texts = append(texts, part.Text)
		}
	}
	return strings.Join(texts, "\n")
}

func (a *reverseAuxiliaryOutput) responseItems(raw json.RawMessage) string {
	var items []struct {
		ID        string          `json:"id"`
		Type      string          `json:"type"`
		Arguments json.RawMessage `json:"arguments"`
		Input     json.RawMessage `json:"input"`
		Action    json.RawMessage `json:"action"`
		Summary   json.RawMessage `json:"summary"`
		Content   json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &items) != nil {
		return ""
	}
	var added []string
	for index, item := range items {
		key := item.ID
		if key == "" {
			key = fmt.Sprintf("item_%d", index)
		}
		switch item.Type {
		case "function_call", "custom_tool_call", "computer_call", "local_shell_call":
			a.hold = true
			var payload json.RawMessage
			switch item.Type {
			case "function_call":
				payload = item.Arguments
			case "custom_tool_call":
				payload = item.Input
			case "computer_call", "local_shell_call":
				payload = item.Action
			}
			arguments := outputArgumentText(payload)
			added = append(added, a.addTool("tool_"+key, arguments, false))
		case "reasoning":
			a.hold = true
			for index, text := range outputReasoningParts(item.Summary) {
				added = append(added, a.add(responseReasoningKey(key, "summary", index), text, false))
			}
			for index, text := range outputReasoningParts(item.Content) {
				added = append(added, a.add(responseReasoningKey(key, "text", index), text, false))
			}
		}
	}
	return joinNonemptyOutputParts(added)
}

func responseReasoningKey(item, family string, index int) string {
	return fmt.Sprintf("reason_%s_%s_%d", item, family, index)
}

func outputReasoningParts(raw json.RawMessage) []string {
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		texts := make([]string, len(parts))
		for i, part := range parts {
			texts[i] = part.Text
		}
		return texts
	}
	return []string{outputReasoningText(raw)}
}

func reverseProxyJSONInspectionExtras(path string, body []byte) (string, string) {
	var a reverseAuxiliaryOutput
	if strings.Contains(strings.ToLower(path), "/responses") {
		var response struct {
			Output json.RawMessage `json:"output"`
		}
		if json.Unmarshal(body, &response) == nil {
			a.responseItems(response.Output)
		}
		return a.inspectionText()
	}
	if strings.Contains(strings.ToLower(path), "/messages") {
		var response struct {
			Content []struct {
				Type     string          `json:"type"`
				Input    json.RawMessage `json:"input"`
				Thinking string          `json:"thinking"`
			} `json:"content"`
		}
		if json.Unmarshal(body, &response) != nil {
			return "", ""
		}
		for i, block := range response.Content {
			if block.Type == "tool_use" || block.Type == "server_tool_use" {
				a.addTool(fmt.Sprintf("tool_%d", i), outputArgumentText(block.Input), false)
			}
			if block.Type == "thinking" {
				a.add(fmt.Sprintf("reason_%d", i), block.Thinking, false)
			}
		}
		return a.inspectionText()
	}
	var response struct {
		Choices []struct {
			Message json.RawMessage `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &response) != nil {
		return "", ""
	}
	for i, choice := range response.Choices {
		a.chatMessage(fmt.Sprintf("choice_%d", i), choice.Message, false)
	}
	return a.inspectionText()
}

func (a *reverseAuxiliaryOutput) chatMessage(key string, raw json.RawMessage, delta bool) string {
	var message struct {
		Reasoning        json.RawMessage `json:"reasoning"`
		ReasoningContent json.RawMessage `json:"reasoning_content"`
		FunctionCall     struct {
			Arguments json.RawMessage `json:"arguments"`
		} `json:"function_call"`
		ToolCalls []struct {
			Index    *int `json:"index"`
			Function struct {
				Arguments json.RawMessage `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
	}
	if json.Unmarshal(raw, &message) != nil {
		return ""
	}
	var added []string
	for _, part := range []struct {
		key   string
		value string
	}{
		{key + "_reasoning", outputReasoningText(message.Reasoning)},
		{key + "_reasoning_content", outputReasoningText(message.ReasoningContent)},
	} {
		if part.value != "" {
			a.hold = true
			added = append(added, a.add(part.key, part.value, delta))
		}
	}
	if arguments := outputArgumentText(message.FunctionCall.Arguments); arguments != "" {
		a.hold = true
		added = append(added, a.addTool(key+"_legacy_tool", arguments, delta))
	}
	for position, tool := range message.ToolCalls {
		index := position
		if tool.Index != nil {
			index = *tool.Index
		}
		a.hold = true
		added = append(added, a.addTool(fmt.Sprintf("%s_tool_%d", key, index), outputArgumentText(tool.Function.Arguments), delta))
	}
	return joinNonemptyOutputParts(added)
}

func (a *reverseAuxiliaryOutput) event(path, kind string, raw []byte) string {
	if strings.Contains(strings.ToLower(path), "/responses") {
		var event struct {
			Type         string          `json:"type"`
			ItemID       string          `json:"item_id"`
			OutputIndex  int             `json:"output_index"`
			SummaryIndex int             `json:"summary_index"`
			ContentIndex int             `json:"content_index"`
			Delta        string          `json:"delta"`
			Text         string          `json:"text"`
			Arguments    json.RawMessage `json:"arguments"`
			Input        json.RawMessage `json:"input"`
			Part         struct {
				Text string `json:"text"`
			} `json:"part"`
			Item     json.RawMessage `json:"item"`
			Response struct {
				Output json.RawMessage `json:"output"`
			} `json:"response"`
		}
		if json.Unmarshal(raw, &event) != nil {
			return ""
		}
		if kind == "" {
			kind = event.Type
		}
		key := event.ItemID
		if key == "" {
			key = fmt.Sprintf("item_%d", event.OutputIndex)
		}
		switch kind {
		case "response.function_call_arguments.delta":
			a.hold = true
			return a.addTool("tool_"+key, event.Delta, true)
		case "response.function_call_arguments.done":
			a.hold = true
			return a.addTool("tool_"+key, outputArgumentText(event.Arguments), false)
		case "response.custom_tool_call_input.delta":
			a.hold = true
			return a.addTool("tool_"+key, event.Delta, true)
		case "response.custom_tool_call_input.done":
			a.hold = true
			return a.addTool("tool_"+key, outputArgumentText(event.Input), false)
		case "response.reasoning.delta":
			a.hold = true
			return a.add(responseReasoningKey(key, "legacy", event.ContentIndex), event.Delta, true)
		case "response.reasoning_text.delta":
			a.hold = true
			return a.add(responseReasoningKey(key, "text", event.ContentIndex), event.Delta, true)
		case "response.reasoning_summary_text.delta":
			a.hold = true
			return a.add(responseReasoningKey(key, "summary", event.SummaryIndex), event.Delta, true)
		case "response.reasoning_text.done":
			a.hold = true
			return a.add(responseReasoningKey(key, "text", event.ContentIndex), event.Text, false)
		case "response.reasoning_summary_text.done":
			a.hold = true
			return a.add(responseReasoningKey(key, "summary", event.SummaryIndex), event.Text, false)
		case "response.reasoning_summary_part.added", "response.reasoning_summary_part.done":
			a.hold = true
			return a.add(responseReasoningKey(key, "summary", event.SummaryIndex), event.Part.Text, false)
		case "response.output_item.added", "response.output_item.done":
			if len(event.Item) > 0 {
				return a.responseItems(append(append([]byte{'['}, event.Item...), ']'))
			}
		case "response.completed":
			return a.responseItems(event.Response.Output)
		}
		return ""
	}
	if strings.Contains(strings.ToLower(path), "/messages") {
		var event struct {
			Type  string `json:"type"`
			Index int    `json:"index"`
			Delta struct {
				Type        string `json:"type"`
				PartialJSON string `json:"partial_json"`
				Thinking    string `json:"thinking"`
			} `json:"delta"`
			ContentBlock struct {
				Type     string          `json:"type"`
				Input    json.RawMessage `json:"input"`
				Thinking string          `json:"thinking"`
			} `json:"content_block"`
		}
		if json.Unmarshal(raw, &event) != nil {
			return ""
		}
		if event.Type == "content_block_delta" {
			switch event.Delta.Type {
			case "input_json_delta":
				a.hold = true
				return a.addTool(fmt.Sprintf("tool_%d", event.Index), event.Delta.PartialJSON, true)
			case "thinking_delta":
				a.hold = true
				return a.add(fmt.Sprintf("reason_%d", event.Index), event.Delta.Thinking, true)
			}
		}
		if event.Type == "content_block_start" {
			switch event.ContentBlock.Type {
			case "tool_use", "server_tool_use":
				a.hold = true
				if text := outputArgumentText(event.ContentBlock.Input); text != "{}" {
					return a.addTool(fmt.Sprintf("tool_%d", event.Index), text, false)
				}
			case "thinking":
				a.hold = true
				return a.add(fmt.Sprintf("reason_%d", event.Index), event.ContentBlock.Thinking, false)
			}
		}
		return ""
	}
	var event struct {
		Choices []struct {
			Index   *int            `json:"index"`
			Delta   json.RawMessage `json:"delta"`
			Message json.RawMessage `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(raw, &event) != nil {
		return ""
	}
	var added []string
	for position, choice := range event.Choices {
		index := position
		if choice.Index != nil {
			index = *choice.Index
		}
		key := fmt.Sprintf("choice_%d", index)
		added = append(added, a.chatMessage(key, choice.Delta, true), a.chatMessage(key, choice.Message, false))
	}
	return joinNonemptyOutputParts(added)
}

func reverseProxySSEInspectionExtras(path string, body []byte) (string, string) {
	var a reverseAuxiliaryOutput
	for _, event := range reverseProxySSEEvents(body) {
		a.event(path, event.Name, event.Data)
	}
	return a.inspectionText()
}

func joinReverseInspectionOutput(text, extras string) (string, bool) {
	if strings.TrimSpace(extras) != "" {
		if strings.TrimSpace(text) != "" {
			text += "\n"
		}
		text += extras
	}
	return text, strings.TrimSpace(text) != ""
}
