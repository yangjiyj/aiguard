package handler

import (
	"encoding/json"
	"fmt"
	"strings"
)

func secureNativeResponsesOutput(final, securedView []byte) ([]byte, error) {
	var secured ChatCompletionResponse
	if err := json.Unmarshal(securedView, &secured); err != nil {
		return nil, err
	}
	allowedCalls := make(map[string]struct{})
	safetyText := ""
	if len(secured.Choices) > 0 {
		safetyText = secured.Choices[0].Message.Content
		for _, call := range secured.Choices[0].Message.ToolCalls {
			if identity, ok := responsesToolIdentity(call.OutputItemID, call.ID); ok && !call.ProtocolIdentityRejected {
				allowedCalls[identity] = struct{}{}
			}
		}
	}
	if strings.TrimSpace(safetyText) == "" {
		safetyText = "?????????????"
	}

	var response map[string]interface{}
	if err := json.Unmarshal(final, &response); err != nil {
		return nil, err
	}
	rawOutput, ok := response["output"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("Responses output is not an array")
	}
	output := make([]interface{}, 0, len(rawOutput)+1)
	blocked := false
	for _, raw := range rawOutput {
		item, isObject := raw.(map[string]interface{})
		if !isObject {
			output = append(output, raw)
			continue
		}
		itemType, _ := item["type"].(string)
		if !strings.Contains(strings.ToLower(itemType), "call") {
			output = append(output, raw)
			continue
		}
		itemID, _ := item["id"].(string)
		callID, _ := item["call_id"].(string)
		identity, validIdentity := responsesToolIdentity(itemID, callID)
		if _, allowed := allowedCalls[identity]; validIdentity && allowed {
			output = append(output, raw)
			continue
		}
		blocked = true
	}
	if !blocked {
		return append([]byte(nil), final...), nil
	}
	output = append(output, map[string]interface{}{
		"id": "msg_jjdguard_safety", "type": "message", "status": "completed", "role": "assistant",
		"content": []interface{}{map[string]interface{}{
			"type": "output_text", "text": safetyText, "annotations": []interface{}{},
		}},
	})
	response["output"] = output
	return json.Marshal(response)
}

func responsesToolIdentity(outputItemID, callID string) (string, bool) {
	outputItemID = strings.TrimSpace(outputItemID)
	callID = strings.TrimSpace(callID)
	if outputItemID == "" || callID == "" {
		return "", false
	}
	return outputItemID + "\x1f" + callID, true
}
