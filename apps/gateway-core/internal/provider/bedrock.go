package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// BedrockAdapter translates OpenAI Chat Completions to Amazon Bedrock Converse.
// APIKey is the decrypted AWS credential JSON configured for the provider.
type BedrockAdapter struct {
	BaseURL           string
	APIKey            string
	ProxyURL          string
	StreamIdleTimeout time.Duration

	model         string
	upstreamModel string
}

func (a *BedrockAdapter) Name() string { return "bedrock" }

func (a *BedrockAdapter) SupportsEndpoint(endpoint string) bool { return endpoint == "chat" }

type bedrockCredential struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	Region          string `json:"region"`
}

type bedrockContentBlock struct {
	Text       string             `json:"text,omitempty"`
	ToolUse    *bedrockToolUse    `json:"toolUse,omitempty"`
	ToolResult *bedrockToolResult `json:"toolResult,omitempty"`
}

type bedrockToolUse struct {
	ToolUseID string          `json:"toolUseId"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
}

type bedrockToolResult struct {
	ToolUseID string           `json:"toolUseId"`
	Content   []map[string]any `json:"content"`
}

type bedrockMessagePayload struct {
	Role    string                `json:"role"`
	Content []bedrockContentBlock `json:"content"`
}

type bedrockInferenceConfig struct {
	MaxTokens     *int     `json:"maxTokens,omitempty"`
	Temperature   *float64 `json:"temperature,omitempty"`
	TopP          *float64 `json:"topP,omitempty"`
	StopSequences []string `json:"stopSequences,omitempty"`
}

type bedrockConverseRequest struct {
	System          []bedrockContentBlock   `json:"system,omitempty"`
	Messages        []bedrockMessagePayload `json:"messages"`
	InferenceConfig *bedrockInferenceConfig `json:"inferenceConfig,omitempty"`
	ToolConfig      map[string]any          `json:"toolConfig,omitempty"`
}

type bedrockResponseContent struct {
	Text    string          `json:"text,omitempty"`
	ToolUse *bedrockToolUse `json:"toolUse,omitempty"`
}

type bedrockConverseResponse struct {
	Output struct {
		Message struct {
			Role    string                   `json:"role"`
			Content []bedrockResponseContent `json:"content"`
		} `json:"message"`
	} `json:"output"`
	StopReason string       `json:"stopReason"`
	Usage      bedrockUsage `json:"usage"`
}

type bedrockUsage struct {
	InputTokens  int `json:"inputTokens"`
	OutputTokens int `json:"outputTokens"`
	TotalTokens  int `json:"totalTokens"`
}

func parseBedrockCredential(raw string) (bedrockCredential, error) {
	var credential bedrockCredential
	if strings.TrimSpace(raw) == "" {
		return credential, errors.New("bedrock provider is not configured with AWS credential JSON")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return credential, fmt.Errorf("bedrock: invalid AWS credential JSON: %w", err)
	}
	credential.AccessKeyID = bedrockStringField(fields, "access_key_id", "aws_access_key_id", "accessKeyId")
	credential.SecretAccessKey = bedrockStringField(fields, "secret_access_key", "aws_secret_access_key", "secretAccessKey")
	credential.SessionToken = bedrockStringField(fields, "session_token", "aws_session_token", "sessionToken")
	credential.Region = bedrockStringField(fields, "region", "aws_region")
	if credential.AccessKeyID == "" || credential.SecretAccessKey == "" {
		return credential, errors.New("bedrock: AWS credential JSON must include access_key_id and secret_access_key")
	}
	if credential.Region == "" {
		return credential, errors.New("bedrock: AWS credential JSON must include region")
	}
	return credential, nil
}

func bedrockStringField(fields map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		raw, ok := fields[name]
		if !ok {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (a *BedrockAdapter) TransformRequest(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, error) {
	if envelope == nil || envelope.EndpointType != "chat" {
		return nil, fmt.Errorf("%w: AWS Bedrock supports chat completions only", ErrEndpointNotSupported)
	}
	a.model = strings.TrimSpace(envelope.Model)
	a.upstreamModel = strings.TrimSpace(envelope.UpstreamModelID)
	if a.upstreamModel == "" {
		a.upstreamModel = a.model
	}
	if a.model == "" {
		a.model = a.upstreamModel
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &input); err != nil {
		return nil, fmt.Errorf("bedrock: invalid OpenAI request: %w", err)
	}
	if raw, ok := input["parallel_tool_calls"]; ok && string(raw) == "false" {
		return nil, errors.New("bedrock: serial-only tool calls cannot be guaranteed")
	}
	rawMessages, ok := input["messages"]
	if !ok {
		return nil, errors.New("bedrock: messages must be a non-empty array")
	}
	var messages []json.RawMessage
	if err := json.Unmarshal(rawMessages, &messages); err != nil || len(messages) == 0 {
		return nil, errors.New("bedrock: messages must be a non-empty array")
	}
	request := bedrockConverseRequest{Messages: make([]bedrockMessagePayload, 0, len(messages))}
	for _, rawMessage := range messages {
		message, role, err := bedrockMessage(rawMessage)
		if err != nil {
			return nil, err
		}
		if role == "system" {
			request.System = append(request.System, message.Content...)
		} else if len(request.Messages) > 0 && request.Messages[len(request.Messages)-1].Role == message.Role {
			last := &request.Messages[len(request.Messages)-1]
			last.Content = append(last.Content, message.Content...)
		} else {
			request.Messages = append(request.Messages, message)
		}
	}
	if len(request.Messages) == 0 {
		return nil, errors.New("bedrock: at least one non-system message is required")
	}
	toolConfig, err := bedrockTools(input)
	if err != nil {
		return nil, err
	}
	request.ToolConfig = toolConfig
	config := &bedrockInferenceConfig{}
	hasConfig := false
	if value, ok := bedrockFloatField(input, "temperature"); ok {
		config.Temperature, hasConfig = &value, true
	}
	if value, ok := bedrockFloatField(input, "top_p"); ok {
		config.TopP, hasConfig = &value, true
	}
	if value, ok := bedrockIntField(input, "max_tokens"); ok {
		config.MaxTokens, hasConfig = &value, true
	} else if value, ok := bedrockIntField(input, "max_completion_tokens"); ok {
		config.MaxTokens, hasConfig = &value, true
	}
	if rawStop, ok := input["stop"]; ok {
		var stops []string
		if json.Unmarshal(rawStop, &stops) == nil {
			config.StopSequences, hasConfig = stops, len(stops) > 0
		} else {
			var stop string
			if json.Unmarshal(rawStop, &stop) == nil && stop != "" {
				config.StopSequences, hasConfig = []string{stop}, true
			}
		}
	}
	if hasConfig {
		request.InferenceConfig = config
	}
	return json.Marshal(request)
}

func bedrockMessage(raw json.RawMessage) (bedrockMessagePayload, string, error) {
	var input map[string]json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil {
		return bedrockMessagePayload{}, "", fmt.Errorf("bedrock: invalid message: %w", err)
	}
	var role string
	if err := json.Unmarshal(input["role"], &role); err != nil || strings.TrimSpace(role) == "" {
		return bedrockMessagePayload{}, "", errors.New("bedrock: message role is required")
	}
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "developer" {
		role = "system"
	}
	if role == "tool" {
		var id string
		_ = json.Unmarshal(input["tool_call_id"], &id)
		if id == "" {
			return bedrockMessagePayload{}, "", errors.New("bedrock: tool result requires tool_call_id")
		}
		var text string
		raw := input["content"]
		if json.Unmarshal(raw, &text) != nil {
			text = string(raw)
		}
		return bedrockMessagePayload{Role: "user", Content: []bedrockContentBlock{{ToolResult: &bedrockToolResult{ToolUseID: id, Content: []map[string]any{{"text": text}}}}}}, "user", nil
	}
	if role != "system" && role != "user" && role != "assistant" {
		return bedrockMessagePayload{}, "", fmt.Errorf("bedrock: unsupported message role %q", role)
	}
	content := []bedrockContentBlock{}
	if rawContent, ok := input["content"]; ok && string(rawContent) != "null" {
		parts, err := bedrockContent(rawContent)
		if err != nil {
			return bedrockMessagePayload{}, "", err
		}
		content = append(content, parts...)
	}
	if raw, exists := input["tool_calls"]; exists {
		if role != "assistant" {
			return bedrockMessagePayload{}, "", errors.New("bedrock: tool_calls require assistant role")
		}
		var calls []struct {
			ID       string `json:"id"`
			Type     string `json:"type"`
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		}
		if err := json.Unmarshal(raw, &calls); err != nil {
			return bedrockMessagePayload{}, "", err
		}
		for _, call := range calls {
			var args map[string]any
			if call.ID == "" || call.Function.Name == "" || (call.Type != "" && call.Type != "function") || json.Unmarshal([]byte(call.Function.Arguments), &args) != nil || args == nil {
				return bedrockMessagePayload{}, "", errors.New("bedrock: function call requires id, name and object arguments")
			}
			content = append(content, bedrockContentBlock{ToolUse: &bedrockToolUse{ToolUseID: call.ID, Name: call.Function.Name, Input: json.RawMessage(call.Function.Arguments)}})
		}
	}
	if len(content) == 0 {
		return bedrockMessagePayload{}, "", errors.New("bedrock: message content must contain text or tool calls")
	}
	return bedrockMessagePayload{Role: role, Content: content}, role, nil
}

func bedrockContent(raw json.RawMessage) ([]bedrockContentBlock, error) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return []bedrockContentBlock{{Text: text}}, nil
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil, errors.New("bedrock: message content must be a string or text part array")
	}
	result := make([]bedrockContentBlock, 0, len(parts))
	for _, rawPart := range parts {
		var part map[string]json.RawMessage
		if err := json.Unmarshal(rawPart, &part); err != nil {
			return nil, errors.New("bedrock: invalid message content part")
		}
		var kind string
		_ = json.Unmarshal(part["type"], &kind)
		if kind != "" && kind != "text" && kind != "input_text" && kind != "output_text" {
			return nil, fmt.Errorf("bedrock: unsupported content part type %q", kind)
		}
		var value string
		if err := json.Unmarshal(part["text"], &value); err != nil {
			return nil, errors.New("bedrock: text content part requires text")
		}
		result = append(result, bedrockContentBlock{Text: value})
	}
	return result, nil
}

func bedrockFloatField(input map[string]json.RawMessage, name string) (float64, bool) {
	raw, ok := input[name]
	if !ok {
		return 0, false
	}
	var value float64
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	return value, true
}

func bedrockIntField(input map[string]json.RawMessage, name string) (int, bool) {
	raw, ok := input[name]
	if !ok {
		return 0, false
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	return value, true
}

func (a *BedrockAdapter) Call(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) ([]byte, error) {
	credential, err := parseBedrockCredential(a.APIKey)
	if err != nil {
		return nil, err
	}
	endpoint, err := bedrockEndpoint(a.BaseURL, credential.Region, a.upstreamModel, "converse")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if err := signBedrockRequest(req, credential); err != nil {
		return nil, err
	}
	setVerifiedIdempotencyHeader(req, envelope)
	client, err := nonStreamingHTTPClient(a.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("bedrock: invalid configured outbound proxy: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return readResponseBody(resp)
}

func (a *BedrockAdapter) CallStreaming(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) ([]byte, error) {
	credential, err := parseBedrockCredential(a.APIKey)
	if err != nil {
		return nil, err
	}
	endpoint, err := bedrockEndpoint(a.BaseURL, credential.Region, a.upstreamModel, "converse-stream")
	if err != nil {
		return nil, err
	}
	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.amazon.eventstream")
	if err := signBedrockRequest(req, credential); err != nil {
		return nil, err
	}
	client, err := streamingHTTPClient(a.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("bedrock: invalid configured outbound proxy: %w", err)
	}
	startedAt := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body = newByteIdleReadCloser(resp.Body, a.StreamIdleTimeout, cancel)
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readResponseBody(resp)
	}
	return accumulateBedrockEventStream(resp.Body, envelope, startedAt)
}

func bedrockEndpoint(baseURL, region, model, action string) (string, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = "https://bedrock-runtime." + region + ".amazonaws.com"
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("bedrock: invalid API address %q", baseURL)
	}
	if hostname := parsed.Hostname(); strings.HasPrefix(hostname, "bedrock-runtime.") && strings.HasSuffix(hostname, ".amazonaws.com") {
		parsed.Host = "bedrock-runtime." + region + ".amazonaws.com"
	}
	baseEscaped := strings.TrimRight(parsed.EscapedPath(), "/")
	decodedPath := strings.TrimRight(parsed.Path, "/") + "/model/" + model + "/" + action
	parsed.Path = decodedPath
	parsed.RawPath = baseEscaped + "/model/" + url.PathEscape(model) + "/" + action
	return parsed.String(), nil
}

func (a *BedrockAdapter) TransformResponse(resp []byte) ([]byte, error) {
	var response bedrockConverseResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, fmt.Errorf("bedrock: invalid Converse response: %w", err)
	}
	if response.Output.Message.Role == "" && len(response.Output.Message.Content) == 0 {
		return nil, errors.New("bedrock: Converse response has no assistant output")
	}
	var content strings.Builder
	calls := make([]any, 0)
	for _, block := range response.Output.Message.Content {
		content.WriteString(block.Text)
		if call := block.ToolUse; call != nil {
			if call.ToolUseID == "" || call.Name == "" || !json.Valid(call.Input) {
				return nil, errors.New("bedrock: invalid tool use response")
			}
			calls = append(calls, map[string]any{"id": call.ToolUseID, "type": "function", "function": map[string]any{"name": call.Name, "arguments": string(call.Input)}})
		}
	}
	message := map[string]any{"role": "assistant", "content": content.String()}
	if len(calls) > 0 {
		message["tool_calls"] = calls
	}
	usage := response.Usage
	if usage.TotalTokens == 0 {
		usage.TotalTokens = usage.InputTokens + usage.OutputTokens
	}
	result := map[string]interface{}{
		"id":      "bedrock-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   firstNonEmpty(a.model, a.upstreamModel),
		"choices": []interface{}{map[string]interface{}{
			"index":         0,
			"message":       message,
			"finish_reason": bedrockFinishReason(response.StopReason),
		}},
	}
	if usage.InputTokens != 0 || usage.OutputTokens != 0 || usage.TotalTokens != 0 {
		result["usage"] = map[string]int{"prompt_tokens": usage.InputTokens, "completion_tokens": usage.OutputTokens, "total_tokens": usage.TotalTokens}
	}
	return json.Marshal(result)
}

func bedrockFinishReason(reason string) string {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "max_tokens":
		return "length"
	case "guardrail_intervened":
		return "content_filter"
	case "tool_use":
		return "tool_calls"
	default:
		return "stop"
	}
}

func bedrockTools(input map[string]json.RawMessage) (map[string]any, error) {
	var tools []struct {
		Type     string `json:"type"`
		Function struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Parameters  json.RawMessage `json:"parameters"`
			Strict      bool            `json:"strict"`
		} `json:"function"`
	}
	if raw, ok := input["tools"]; ok && json.Unmarshal(raw, &tools) != nil {
		return nil, errors.New("bedrock: invalid tools")
	}
	config := map[string]any{}
	specs := make([]any, 0, len(tools))
	for _, tool := range tools {
		if tool.Type != "function" || tool.Function.Name == "" {
			return nil, errors.New("bedrock: only named function tools are supported")
		}
		spec := map[string]any{"name": tool.Function.Name}
		if tool.Function.Description != "" {
			spec["description"] = tool.Function.Description
		}
		schema := tool.Function.Parameters
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		spec["inputSchema"] = map[string]any{"json": schema}
		if tool.Function.Strict {
			spec["strict"] = true
		}
		specs = append(specs, map[string]any{"toolSpec": spec})
	}
	if len(specs) > 0 {
		config["tools"] = specs
	}
	if raw, exists := input["tool_choice"]; exists && string(raw) != "null" {
		var choice string
		if json.Unmarshal(raw, &choice) == nil {
			switch choice {
			case "none":
				return nil, nil
			case "auto":
				config["toolChoice"] = map[string]any{"auto": map[string]any{}}
			case "required":
				config["toolChoice"] = map[string]any{"any": map[string]any{}}
			default:
				return nil, errors.New("bedrock: unsupported tool_choice")
			}
		} else {
			var choice struct {
				Type     string `json:"type"`
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			}
			if json.Unmarshal(raw, &choice) != nil || choice.Type != "function" || choice.Function.Name == "" {
				return nil, errors.New("bedrock: invalid tool_choice")
			}
			config["toolChoice"] = map[string]any{"tool": map[string]any{"name": choice.Function.Name}}
		}
	}
	if len(specs) == 0 {
		if len(config) > 0 {
			return nil, errors.New("bedrock: tool_choice requires tools")
		}
		return nil, nil
	}
	return config, nil
}
