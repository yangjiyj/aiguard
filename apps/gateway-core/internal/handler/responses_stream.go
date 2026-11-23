package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type ResponsesError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ResponsesTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

func responsesContentToChat(content []interface{}) []interface{} {
	converted := make([]interface{}, 0, len(content))
	for _, raw := range content {
		block, ok := raw.(map[string]interface{})
		if !ok {
			converted = append(converted, raw)
			continue
		}
		copyBlock := make(map[string]interface{}, len(block))
		for key, value := range block {
			copyBlock[key] = value
		}
		switch copyBlock["type"] {
		case "input_text", "output_text":
			copyBlock["type"] = "text"
		case "input_image":
			if imageURL, ok := copyBlock["image_url"].(string); ok && imageURL != "" {
				copyBlock["type"] = "image_url"
				copyBlock["image_url"] = map[string]interface{}{"url": imageURL}
			}
		}
		converted = append(converted, copyBlock)
	}
	return converted
}

func responsesToolChoiceToChat(choice interface{}) interface{} {
	object, ok := choice.(map[string]interface{})
	if !ok {
		return choice
	}
	if object["type"] != "function" {
		return choice
	}
	name, _ := object["name"].(string)
	if name == "" {
		if function, ok := object["function"].(map[string]interface{}); ok {
			name, _ = function["name"].(string)
		}
	}
	if name == "" {
		return choice
	}
	return map[string]interface{}{
		"type":     "function",
		"function": map[string]interface{}{"name": name},
	}
}

func writeResponsesSSEEvent(w http.ResponseWriter, eventType string, payload map[string]interface{}, sequenceNumber int) error {
	payload["sequence_number"] = sequenceNumber
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, body); err != nil {
		return err
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	return nil
}

func writeResponsesStream(w http.ResponseWriter, response *ResponsesResponse) error {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	inProgress := *response
	inProgress.Status = "in_progress"
	inProgress.Output = []ResponsesOutput{}
	inProgress.Usage = nil
	sequenceNumber := 0
	emit := func(eventType string, payload map[string]interface{}) error {
		err := writeResponsesSSEEvent(w, eventType, payload, sequenceNumber)
		sequenceNumber++
		return err
	}
	if err := emit("response.created", map[string]interface{}{
		"type": "response.created", "response": &inProgress,
	}); err != nil {
		return err
	}
	if err := emit("response.in_progress", map[string]interface{}{
		"type": "response.in_progress", "response": &inProgress,
	}); err != nil {
		return err
	}

	for outputIndex, item := range response.Output {
		switch item.Type {
		case "function_call":
			added := item
			added.Status = "in_progress"
			added.Arguments = ""
			if err := emit("response.output_item.added", map[string]interface{}{
				"type": "response.output_item.added", "output_index": outputIndex, "item": added,
			}); err != nil {
				return err
			}
			if err := emit("response.function_call_arguments.delta", map[string]interface{}{
				"type": "response.function_call_arguments.delta", "item_id": item.ID,
				"output_index": outputIndex, "delta": item.Arguments,
			}); err != nil {
				return err
			}
			if err := emit("response.function_call_arguments.done", map[string]interface{}{
				"type": "response.function_call_arguments.done", "item_id": item.ID,
				"output_index": outputIndex, "arguments": item.Arguments,
			}); err != nil {
				return err
			}
			if err := emit("response.output_item.done", map[string]interface{}{
				"type": "response.output_item.done", "output_index": outputIndex, "item": item,
			}); err != nil {
				return err
			}
		default:
			text := item.Text
			if len(item.Content) > 0 {
				text = item.Content[0].Text
			}
			added := item
			added.Status = "in_progress"
			added.Text = ""
			added.Content = []ResponsesContent{}
			addedJSON, err := json.Marshal(added)
			if err != nil {
				return err
			}
			var addedItem map[string]interface{}
			_ = json.Unmarshal(addedJSON, &addedItem)
			addedItem["content"] = []ResponsesContent{}
			if err := emit("response.output_item.added", map[string]interface{}{
				"type": "response.output_item.added", "output_index": outputIndex, "item": addedItem,
			}); err != nil {
				return err
			}
			part := ResponsesContent{Type: "output_text", Text: "", Annotations: []interface{}{}}
			if err := emit("response.content_part.added", map[string]interface{}{
				"type": "response.content_part.added", "item_id": item.ID,
				"output_index": outputIndex, "content_index": 0, "part": part,
			}); err != nil {
				return err
			}
			if err := emit("response.output_text.delta", map[string]interface{}{
				"type": "response.output_text.delta", "item_id": item.ID,
				"output_index": outputIndex, "content_index": 0, "delta": text, "logprobs": []interface{}{},
			}); err != nil {
				return err
			}
			if err := emit("response.output_text.done", map[string]interface{}{
				"type": "response.output_text.done", "item_id": item.ID,
				"output_index": outputIndex, "content_index": 0, "text": text, "logprobs": []interface{}{},
			}); err != nil {
				return err
			}
			part.Text = text
			if err := emit("response.content_part.done", map[string]interface{}{
				"type": "response.content_part.done", "item_id": item.ID,
				"output_index": outputIndex, "content_index": 0, "part": part,
			}); err != nil {
				return err
			}
			if err := emit("response.output_item.done", map[string]interface{}{
				"type": "response.output_item.done", "output_index": outputIndex, "item": item,
			}); err != nil {
				return err
			}
		}
	}

	return emit("response.completed", map[string]interface{}{
		"type": "response.completed", "response": response,
	})
}

func writeResponsesStreamFailure(w http.ResponseWriter, responseID, code, message string) error {
	w.Header().Set("Content-Type", "text/event-stream")
	sequenceNumber := 0
	emit := func(eventType string, payload map[string]interface{}) error {
		err := writeResponsesSSEEvent(w, eventType, payload, sequenceNumber)
		sequenceNumber++
		return err
	}
	if err := emit("error", map[string]interface{}{
		"type": "error", "code": code, "message": message,
	}); err != nil {
		return err
	}
	failed := &ResponsesResponse{
		ID: responseID, Object: "response", Status: "failed",
		Error: &ResponsesError{Code: code, Message: message},
	}
	return emit("response.failed", map[string]interface{}{
		"type": "response.failed", "response": failed,
	})
}
