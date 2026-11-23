package provider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

const (
	geminiCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	geminiDefaultTokenURI    = "https://oauth2.googleapis.com/token"
	geminiTokenTTL           = time.Hour
)

// GeminiAdapter translates the gateway's OpenAI Chat Completions contract to
// Google Vertex AI's Gemini generateContent contract. APIKey contains the
// encrypted/decrypted Google service-account JSON configured for the provider.
type GeminiAdapter struct {
	BaseURL           string
	APIKey            string
	ProxyURL          string
	StreamIdleTimeout time.Duration

	// model is populated while transforming a request. The adapter is created
	// per route attempt, so this is safe and lets the response retain the
	// logical model name expected by the customer.
	model string
}

func (a *GeminiAdapter) Name() string { return "gemini" }

func (a *GeminiAdapter) SupportsEndpoint(endpoint string) bool { return endpoint == "chat" }

type geminiServiceAccount struct {
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

type geminiAccessTokenEntry struct {
	Token     string
	ExpiresAt time.Time
}

var geminiAccessTokens = struct {
	sync.Mutex
	entries map[string]geminiAccessTokenEntry
}{entries: make(map[string]geminiAccessTokenEntry)}

func (a *GeminiAdapter) TransformRequest(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, error) {
	if envelope == nil || envelope.EndpointType != "chat" {
		return nil, fmt.Errorf("%w: Gemini supports chat completions only", ErrEndpointNotSupported)
	}

	a.model = strings.TrimSpace(envelope.Model)
	if strings.TrimSpace(envelope.UpstreamModelID) != "" {
		a.model = strings.TrimSpace(envelope.UpstreamModelID)
	}

	var input map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &input); err != nil {
		return nil, fmt.Errorf("gemini: invalid OpenAI request: %w", err)
	}

	if raw, ok := input["parallel_tool_calls"]; ok && string(raw) == "false" {
		return nil, errors.New("gemini: serial-only tool calls cannot be guaranteed")
	}
	var messages []json.RawMessage
	if raw, ok := input["messages"]; !ok || json.Unmarshal(raw, &messages) != nil || len(messages) == 0 {
		return nil, errors.New("gemini: messages must be a non-empty array")
	}

	request := make(map[string]interface{})
	contents := make([]map[string]interface{}, 0, len(messages))
	var systemParts []map[string]interface{}
	toolNames := make(map[string]string)
	for _, rawMessage := range messages {
		var history map[string]json.RawMessage
		if err := json.Unmarshal(rawMessage, &history); err != nil {
			return nil, err
		}
		var roleName string
		_ = json.Unmarshal(history["role"], &roleName)
		if raw, exists := history["tool_calls"]; exists {
			var calls []struct {
				ID       string `json:"id"`
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			}
			if err := json.Unmarshal(raw, &calls); err != nil {
				return nil, err
			}
			for _, call := range calls {
				toolNames[call.ID] = call.Function.Name
			}
		}
		if roleName == "tool" {
			var id string
			_ = json.Unmarshal(history["tool_call_id"], &id)
			name := toolNames[id]
			if name == "" {
				return nil, errors.New("gemini: tool result has no matching named call")
			}
			history["name"], _ = json.Marshal(name)
			rawMessage, _ = json.Marshal(history)
		}
		content, role, err := geminiMessage(rawMessage)
		if err != nil {
			return nil, err
		}
		if role == "system" {
			systemParts = append(systemParts, content["parts"].([]map[string]interface{})...)
			continue
		}
		if len(contents) > 0 && contents[len(contents)-1]["role"] == role {
			last := contents[len(contents)-1]
			last["parts"] = append(last["parts"].([]map[string]interface{}), content["parts"].([]map[string]interface{})...)
		} else {
			contents = append(contents, content)
		}
	}
	if len(systemParts) > 0 {
		request["system_instruction"] = map[string]interface{}{"parts": systemParts}
	}
	if len(contents) == 0 {
		return nil, errors.New("gemini: at least one non-system message is required")
	}
	request["contents"] = contents

	if raw, ok := input["tools"]; ok {
		tools, err := geminiTools(raw)
		if err != nil {
			return nil, err
		}
		if len(tools) > 0 {
			request["tools"] = tools
		}
	}
	if raw, ok := input["tool_choice"]; ok {
		config, err := geminiToolConfig(raw)
		if err != nil {
			return nil, err
		}
		if config != nil {
			request["tool_config"] = config
		}
	}

	generation := make(map[string]interface{})
	copyNumberField(input, generation, "temperature", "temperature")
	copyNumberField(input, generation, "top_p", "topP")
	copyNumberField(input, generation, "top_k", "topK")
	copyNumberField(input, generation, "max_tokens", "maxOutputTokens")
	copyNumberField(input, generation, "max_completion_tokens", "maxOutputTokens")
	copyStringArrayField(input, generation, "stop", "stopSequences")
	if raw, ok := input["response_format"]; ok {
		if format := geminiResponseFormat(raw); format != nil {
			for key, value := range format {
				generation[key] = value
			}
		}
	}
	if effortRaw, ok := input["reasoning_effort"]; ok {
		var effort string
		if json.Unmarshal(effortRaw, &effort) == nil {
			// chat reasoning_effort 回映为 Gemini 原生思考档位（与 ingress 映射互逆）。
			switch effort {
			case "low":
				generation["thinkingConfig"] = map[string]interface{}{"thinkingLevel": "LOW"}
			case "high":
				generation["thinkingConfig"] = map[string]interface{}{"thinkingLevel": "HIGH"}
			case "minimal":
				generation["thinkingConfig"] = map[string]interface{}{"thinkingBudget": 0}
			}
		}
	}
	if len(generation) > 0 {
		request["generation_config"] = generation
	}

	return json.Marshal(request)
}

func geminiMessage(raw json.RawMessage) (map[string]interface{}, string, error) {
	var message map[string]json.RawMessage
	if err := json.Unmarshal(raw, &message); err != nil {
		return nil, "", fmt.Errorf("gemini: invalid message: %w", err)
	}
	var role string
	if err := json.Unmarshal(message["role"], &role); err != nil || strings.TrimSpace(role) == "" {
		return nil, "", errors.New("gemini: message role is required")
	}
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "developer" {
		role = "system"
	}

	parts := make([]map[string]interface{}, 0)
	if rawContent, ok := message["content"]; ok && string(rawContent) != "null" {
		parsed, err := geminiParts(rawContent)
		if err != nil {
			return nil, "", err
		}
		parts = append(parts, parsed...)
	}
	if rawToolCalls, ok := message["tool_calls"]; ok {
		var toolCalls []json.RawMessage
		if err := json.Unmarshal(rawToolCalls, &toolCalls); err != nil {
			return nil, "", fmt.Errorf("gemini: invalid tool_calls: %w", err)
		}
		for _, rawToolCall := range toolCalls {
			part, err := geminiFunctionCallPart(rawToolCall)
			if err != nil {
				return nil, "", err
			}
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return nil, "", errors.New("gemini: message content cannot be empty")
	}

	if role == "assistant" {
		role = "model"
	}
	if role == "tool" || role == "function" {
		role = "user"
		var name string
		_ = json.Unmarshal(message["name"], &name)
		if name == "" {
			_ = json.Unmarshal(message["tool_call_id"], &name)
		}
		var id string
		_ = json.Unmarshal(message["tool_call_id"], &id)
		var text strings.Builder
		for _, part := range parts {
			if value, ok := part["text"].(string); ok {
				text.WriteString(value)
			} else {
				return nil, "", errors.New("gemini: non-text tool result has no safe mapping")
			}
		}
		response := map[string]interface{}{"id": id, "name": name, "response": map[string]interface{}{"content": text.String()}}
		parts = []map[string]interface{}{{"functionResponse": response}}
	}
	return map[string]interface{}{"role": role, "parts": parts}, role, nil
}

func geminiParts(raw json.RawMessage) ([]map[string]interface{}, error) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return []map[string]interface{}{{"text": text}}, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("gemini: content must be a string or an array: %w", err)
	}
	parts := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		var part map[string]json.RawMessage
		if err := json.Unmarshal(item, &part); err != nil {
			return nil, fmt.Errorf("gemini: invalid content part: %w", err)
		}
		var typ string
		_ = json.Unmarshal(part["type"], &typ)
		switch typ {
		case "text", "input_text":
			var value string
			if err := json.Unmarshal(part["text"], &value); err != nil {
				return nil, errors.New("gemini: text content part requires text")
			}
			parts = append(parts, map[string]interface{}{"text": value})
		case "image_url", "input_image":
			imageURL := part["image_url"]
			if len(imageURL) == 0 {
				imageURL = part["image_url"]
			}
			var imageValue string
			if json.Unmarshal(imageURL, &imageValue) != nil {
				var imageObject map[string]json.RawMessage
				if json.Unmarshal(imageURL, &imageObject) == nil {
					_ = json.Unmarshal(imageObject["url"], &imageValue)
				}
			}
			if imageValue == "" {
				return nil, errors.New("gemini: image content part requires image_url.url")
			}
			if strings.HasPrefix(imageValue, "data:") {
				mimeType, data, ok := parseDataURL(imageValue)
				if !ok {
					return nil, errors.New("gemini: invalid image data URL")
				}
				parts = append(parts, map[string]interface{}{"inlineData": map[string]interface{}{"mimeType": mimeType, "data": data}})
			} else {
				parts = append(parts, map[string]interface{}{"fileData": map[string]interface{}{"mimeType": "image/*", "fileUri": imageValue}})
			}
		default:
			return nil, fmt.Errorf("gemini: unsupported content part type %q", typ)
		}
	}
	return parts, nil
}

func parseDataURL(value string) (string, string, bool) {
	comma := strings.IndexByte(value, ',')
	if comma < 0 {
		return "", "", false
	}
	meta := value[len("data:"):comma]
	if !strings.HasSuffix(meta, ";base64") {
		return "", "", false
	}
	mimeType := strings.TrimSuffix(meta, ";base64")
	if mimeType == "" {
		return "", "", false
	}
	if _, err := base64.StdEncoding.DecodeString(value[comma+1:]); err != nil {
		return "", "", false
	}
	return mimeType, value[comma+1:], true
}

func geminiFunctionCallPart(raw json.RawMessage) (map[string]interface{}, error) {
	var call map[string]json.RawMessage
	if err := json.Unmarshal(raw, &call); err != nil {
		return nil, fmt.Errorf("gemini: invalid tool call: %w", err)
	}
	function := call["function"]
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(function, &fn); err != nil {
		return nil, errors.New("gemini: tool call function is required")
	}
	var name, arguments string
	_ = json.Unmarshal(fn["name"], &name)
	_ = json.Unmarshal(fn["arguments"], &arguments)
	if name == "" {
		return nil, errors.New("gemini: tool call function name is required")
	}
	args := interface{}(map[string]interface{}{})
	if strings.TrimSpace(arguments) != "" {
		if err := json.Unmarshal([]byte(arguments), &args); err != nil {
			return nil, fmt.Errorf("gemini: invalid tool call arguments: %w", err)
		}
	}
	functionCall := map[string]interface{}{"name": name, "args": args}
	var id string
	_ = json.Unmarshal(call["id"], &id)
	if id != "" {
		functionCall["id"] = id
	}
	return map[string]interface{}{"functionCall": functionCall}, nil
}

func geminiTools(raw json.RawMessage) ([]map[string]interface{}, error) {
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("gemini: invalid tools: %w", err)
	}
	declarations := make([]map[string]interface{}, 0)
	for _, item := range items {
		var typ string
		_ = json.Unmarshal(item["type"], &typ)
		if typ != "function" {
			return nil, errors.New("gemini: only function tools have a safe mapping")
		}
		if rawFunction, ok := item["function"]; ok {
			var function map[string]json.RawMessage
			if err := json.Unmarshal(rawFunction, &function); err != nil {
				return nil, fmt.Errorf("gemini: invalid function tool: %w", err)
			}
			for key := range function {
				if key != "name" && key != "description" && key != "parameters" && key != "strict" {
					return nil, fmt.Errorf("gemini: function field %q has no safe mapping", key)
				}
			}
			var strict bool
			if raw, exists := function["strict"]; exists {
				if json.Unmarshal(raw, &strict) != nil || strict {
					return nil, errors.New("gemini: strict function schema enforcement cannot be guaranteed")
				}
			}
			var name, description string
			_ = json.Unmarshal(function["name"], &name)
			_ = json.Unmarshal(function["description"], &description)
			if name == "" {
				return nil, errors.New("gemini: function tool name is required")
			}
			declaration := map[string]interface{}{"name": name}
			if description != "" {
				declaration["description"] = description
			}
			if parameters, ok := function["parameters"]; ok {
				var schema interface{}
				if err := json.Unmarshal(parameters, &schema); err != nil {
					return nil, fmt.Errorf("gemini: invalid function parameters: %w", err)
				}
				declaration["parameters"] = schema
			}
			declarations = append(declarations, declaration)
		}
	}
	if len(declarations) == 0 {
		return nil, nil
	}
	return []map[string]interface{}{{"function_declarations": declarations}}, nil
}

func geminiToolConfig(raw json.RawMessage) (map[string]interface{}, error) {
	if string(raw) == "null" {
		return nil, nil
	}
	var choice string
	if json.Unmarshal(raw, &choice) == nil {
		mode := map[string]string{"auto": "AUTO", "none": "NONE", "required": "ANY"}[choice]
		if mode == "" {
			return nil, errors.New("gemini: unsupported tool_choice")
		}
		return map[string]interface{}{"function_calling_config": map[string]interface{}{"mode": mode}}, nil
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return nil, errors.New("gemini: invalid tool_choice")
	}
	var typ string
	_ = json.Unmarshal(object["type"], &typ)
	for key := range object {
		if key != "type" && key != "function" {
			return nil, errors.New("gemini: tool_choice extension has no safe mapping")
		}
	}
	var function map[string]json.RawMessage
	_ = json.Unmarshal(object["function"], &function)
	var name string
	_ = json.Unmarshal(function["name"], &name)
	if typ != "function" || name == "" || len(function) != 1 {
		return nil, errors.New("gemini: tool_choice must name one function")
	}
	return map[string]interface{}{"function_calling_config": map[string]interface{}{"mode": "ANY", "allowed_function_names": []string{name}}}, nil
}

func copyNumberField(input map[string]json.RawMessage, output map[string]interface{}, source, target string) {
	if raw, ok := input[source]; ok {
		var value interface{}
		if json.Unmarshal(raw, &value) == nil {
			output[target] = value
		}
	}
}

func copyStringArrayField(input map[string]json.RawMessage, output map[string]interface{}, source, target string) {
	if raw, ok := input[source]; ok {
		var value string
		if json.Unmarshal(raw, &value) == nil {
			output[target] = []string{value}
			return
		}
		var values []string
		if json.Unmarshal(raw, &values) == nil {
			output[target] = values
		}
	}
}

func geminiResponseFormat(raw json.RawMessage) map[string]interface{} {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return nil
	}
	var typ string
	_ = json.Unmarshal(object["type"], &typ)
	if typ == "json_object" {
		return map[string]interface{}{"responseMimeType": "application/json"}
	}
	if typ == "json_schema" {
		var schema map[string]json.RawMessage
		if json.Unmarshal(object["json_schema"], &schema) == nil {
			var value interface{}
			if json.Unmarshal(schema["schema"], &value) == nil {
				return map[string]interface{}{"responseMimeType": "application/json", "responseSchema": value}
			}
		}
	}
	return nil
}

func (a *GeminiAdapter) Call(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) ([]byte, error) {
	if envelope == nil || envelope.EndpointType != "chat" {
		return nil, fmt.Errorf("%w: Gemini supports chat completions only", ErrEndpointNotSupported)
	}
	endpoint, token, apiKey, err := a.requestTarget(ctx, envelope, false)
	if err != nil {
		return nil, err
	}
	return a.callVertex(ctx, endpoint, token, payload, apiKey)
}

func (a *GeminiAdapter) CallStreaming(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) ([]byte, error) {
	if envelope == nil || envelope.EndpointType != "chat" {
		return nil, fmt.Errorf("%w: Gemini supports chat completions only", ErrEndpointNotSupported)
	}
	startedAt := time.Now()
	endpoint, token, apiKey, err := a.requestTarget(ctx, envelope, true)
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
	req.Header.Set("Accept", "text/event-stream")
	setGeminiAuthentication(req, token, apiKey)
	setVerifiedIdempotencyHeader(req, envelope)
	client, err := streamingHTTPClient(a.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid configured outbound proxy: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body = newByteIdleReadCloser(resp.Body, a.StreamIdleTimeout, cancel)
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readResponseBody(resp)
	}

	var accumulator geminiResponse
	sawEvent := false
	readErr := readSSEEvents(resp.Body, func(event sseEvent) (bool, error) {
		data := strings.TrimSpace(event.data)
		if data == "" {
			return false, nil
		}
		var chunk geminiResponse
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			return false, fmt.Errorf("invalid Gemini SSE event: %w", err)
		}
		if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
			return false, &UpstreamHTTPError{StatusCode: http.StatusBadGateway, Body: []byte(data), Message: extractErrorMessage(chunk.Error)}
		}
		if len(chunk.Candidates) > 0 || chunk.UsageMetadata != nil {
			if !sawEvent {
				sawEvent = true
				recordUpstreamTTFT(envelope, startedAt)
			}
			mergeGeminiResponse(&accumulator, chunk)
		}
		return false, nil
	})
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, fmt.Errorf("upstream Gemini stream read error: %w", readErr)
	}
	if !sawEvent {
		return nil, fmt.Errorf("upstream Gemini stream ended without a valid response: %w", io.ErrUnexpectedEOF)
	}
	terminal := len(accumulator.Candidates) > 0
	for _, candidate := range accumulator.Candidates {
		terminal = terminal && candidate.FinishReason != ""
	}
	if !terminal {
		return nil, fmt.Errorf("upstream Gemini stream ended before finishReason: %w", io.ErrUnexpectedEOF)
	}
	return json.Marshal(accumulator)
}

func (a *GeminiAdapter) callVertex(ctx context.Context, endpoint, token string, payload []byte, apiKey bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	setGeminiAuthentication(req, token, apiKey)
	client, err := nonStreamingHTTPClient(a.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid configured outbound proxy: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return readResponseBody(resp)
}

func (a *GeminiAdapter) vertexEndpoint(account *geminiServiceAccount, envelope *modelrouter.RequestEnvelope, stream bool) (string, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(a.BaseURL), "/")
	if baseURL == "" {
		return "", errors.New("gemini provider requires a Vertex AI base URL")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return "", errors.New("gemini provider base URL must be an http(s) URL")
	}
	basePath := strings.TrimRight(parsed.Path, "/")
	basePath = strings.TrimSuffix(basePath, "/v1beta1")
	basePath = strings.TrimSuffix(basePath, "/v1")
	location := vertexLocation(parsed.Hostname())
	modelID := strings.TrimSpace(envelope.UpstreamModelID)
	if modelID == "" {
		modelID = strings.TrimSpace(envelope.Model)
	}
	modelID = strings.TrimPrefix(modelID, "publishers/google/models/")
	modelID = strings.TrimPrefix(modelID, "models/")
	if modelID == "" || strings.ContainsAny(modelID, "/\\") {
		return "", errors.New("gemini model id must be a single model name")
	}
	path := fmt.Sprintf("%s/v1/projects/%s/locations/%s/publishers/google/models/%s:%s", basePath, url.PathEscape(account.ProjectID), url.PathEscape(location), url.PathEscape(modelID), map[bool]string{true: "streamGenerateContent", false: "generateContent"}[stream])
	parsed.Path = path
	parsed.RawQuery = ""
	if stream {
		parsed.RawQuery = "alt=sse"
	}
	return parsed.String(), nil
}

func vertexLocation(host string) string {
	const suffix = "-aiplatform.googleapis.com"
	if strings.HasSuffix(host, suffix) {
		location := strings.TrimSuffix(host, suffix)
		if location != "" && location != "global" {
			return location
		}
	}
	return "global"
}

func parseGeminiServiceAccount(raw string) (*geminiServiceAccount, error) {
	var account geminiServiceAccount
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &account); err != nil {
		return nil, errors.New("gemini provider credential must be a valid Google service-account JSON")
	}
	if account.ProjectID == "" || account.ClientEmail == "" || account.PrivateKey == "" {
		return nil, errors.New("gemini provider credential is missing project_id, client_email, or private_key")
	}
	if account.TokenURI == "" {
		account.TokenURI = geminiDefaultTokenURI
	}
	return &account, nil
}

func geminiOAuthToken(ctx context.Context, account *geminiServiceAccount, proxyURL string) (string, error) {
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(account.ClientEmail+"\x00"+account.PrivateKey)))
	now := time.Now()
	geminiAccessTokens.Lock()
	if cached, ok := geminiAccessTokens.entries[key]; ok && cached.Token != "" && cached.ExpiresAt.After(now.Add(time.Minute)) {
		geminiAccessTokens.Unlock()
		return cached.Token, nil
	}
	geminiAccessTokens.Unlock()

	assertion, err := signedGeminiJWT(account, now)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, account.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("gemini oauth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client, err := nonStreamingHTTPClient(proxyURL)
	if err != nil {
		return "", fmt.Errorf("invalid configured outbound proxy: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gemini oauth token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp)
	if err != nil {
		return "", fmt.Errorf("gemini oauth token exchange failed: %w", err)
	}
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResponse); err != nil || tokenResponse.AccessToken == "" {
		return "", errors.New("gemini oauth token response did not contain access_token")
	}
	expiresIn := time.Duration(tokenResponse.ExpiresIn) * time.Second
	if expiresIn <= 0 || expiresIn > geminiTokenTTL {
		expiresIn = geminiTokenTTL
	}
	geminiAccessTokens.Lock()
	geminiAccessTokens.entries[key] = geminiAccessTokenEntry{Token: tokenResponse.AccessToken, ExpiresAt: now.Add(expiresIn)}
	geminiAccessTokens.Unlock()
	return tokenResponse.AccessToken, nil
}

func signedGeminiJWT(account *geminiServiceAccount, now time.Time) (string, error) {
	block, _ := pem.Decode([]byte(account.PrivateKey))
	if block == nil {
		return "", errors.New("gemini service-account private_key is not PEM encoded")
	}
	var privateKey *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		privateKey, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("gemini service-account private_key is not RSA")
		}
	} else if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		privateKey = parsed
	} else {
		return "", errors.New("gemini service-account private_key could not be parsed")
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]interface{}{
		"iss":   account.ClientEmail,
		"scope": geminiCloudPlatformScope,
		"aud":   account.TokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(55 * time.Minute).Unix(),
	})
	encodedClaims := base64.RawURLEncoding.EncodeToString(claims)
	unsigned := header + "." + encodedClaims
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("gemini service-account JWT signing failed: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type geminiResponse struct {
	Candidates    []geminiCandidate `json:"candidates,omitempty"`
	UsageMetadata *geminiUsage      `json:"usageMetadata,omitempty"`
	ModelVersion  string            `json:"modelVersion,omitempty"`
	Error         json.RawMessage   `json:"error,omitempty"`
}

type geminiCandidate struct {
	Index        int           `json:"index,omitempty"`
	Content      geminiContent `json:"content,omitempty"`
	FinishReason string        `json:"finishReason,omitempty"`
}

type geminiContent struct {
	Role  string                   `json:"role,omitempty"`
	Parts []map[string]interface{} `json:"parts,omitempty"`
}

type geminiUsage struct {
	PromptTokenCount        int `json:"promptTokenCount,omitempty"`
	CandidatesTokenCount    int `json:"candidatesTokenCount,omitempty"`
	TotalTokenCount         int `json:"totalTokenCount,omitempty"`
	CachedContentTokenCount int `json:"cachedContentTokenCount,omitempty"`
}

func mergeGeminiResponse(dst *geminiResponse, src geminiResponse) {
	if src.ModelVersion != "" {
		dst.ModelVersion = src.ModelVersion
	}
	if src.UsageMetadata != nil {
		dst.UsageMetadata = src.UsageMetadata
	}
	for _, candidate := range src.Candidates {
		found := -1
		for i := range dst.Candidates {
			if dst.Candidates[i].Index == candidate.Index {
				found = i
				break
			}
		}
		if found < 0 {
			dst.Candidates = append(dst.Candidates, candidate)
			continue
		}
		dst.Candidates[found].Content.Role = candidate.Content.Role
		dst.Candidates[found].Content.Parts = append(dst.Candidates[found].Content.Parts, candidate.Content.Parts...)
		if candidate.FinishReason != "" {
			dst.Candidates[found].FinishReason = candidate.FinishReason
		}
	}
}

func (a *GeminiAdapter) TransformResponse(resp []byte) ([]byte, error) {
	var native geminiResponse
	if err := json.Unmarshal(resp, &native); err != nil {
		return nil, fmt.Errorf("gemini: invalid response: %w", err)
	}
	if len(native.Error) > 0 && string(native.Error) != "null" {
		return nil, &UpstreamHTTPError{StatusCode: http.StatusBadGateway, Body: resp, Message: extractErrorMessage(native.Error)}
	}
	modelName := a.model
	if modelName == "" {
		modelName = native.ModelVersion
	}
	if modelName == "" {
		modelName = "gemini"
	}
	choices := make([]map[string]interface{}, 0, len(native.Candidates))
	for _, candidate := range native.Candidates {
		var text strings.Builder
		var reasoning strings.Builder
		toolCalls := make([]map[string]interface{}, 0)
		for _, part := range candidate.Content.Parts {
			if value, ok := part["text"].(string); ok {
				if thought, _ := part["thought"].(bool); thought {
					reasoning.WriteString(value)
				} else {
					text.WriteString(value)
				}
			}
			if call, ok := part["functionCall"].(map[string]interface{}); ok {
				name, _ := call["name"].(string)
				args, _ := json.Marshal(call["args"])
				toolCalls = append(toolCalls, map[string]interface{}{
					"id":   firstNonEmpty(compatStringValue(call["id"]), fmt.Sprintf("call_%d_%d", candidate.Index, len(toolCalls))),
					"type": "function",
					"function": map[string]interface{}{
						"name":      name,
						"arguments": string(args),
					},
				})
			}
		}
		message := map[string]interface{}{"role": "assistant", "content": nil}
		if text.Len() > 0 {
			message["content"] = text.String()
		}
		if reasoning.Len() > 0 {
			message["reasoning_content"] = reasoning.String()
		}
		if len(toolCalls) > 0 {
			message["tool_calls"] = toolCalls
		}
		finishReason := geminiFinishReason(candidate.FinishReason)
		if len(toolCalls) > 0 && finishReason == "stop" {
			finishReason = "tool_calls"
		}
		choices = append(choices, map[string]interface{}{
			"index":         candidate.Index,
			"message":       message,
			"finish_reason": finishReason,
		})
	}
	result := map[string]interface{}{
		"id":      "chatcmpl-gemini-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   modelName,
		"choices": choices,
	}
	if native.UsageMetadata != nil {
		result["usage"] = map[string]interface{}{
			"prompt_tokens":     native.UsageMetadata.PromptTokenCount,
			"completion_tokens": native.UsageMetadata.CandidatesTokenCount,
			"total_tokens":      native.UsageMetadata.TotalTokenCount,
		}
	}
	return json.Marshal(result)
}

func geminiFinishReason(reason string) string {
	switch strings.ToUpper(reason) {
	case "STOP":
		return "stop"
	case "MAX_TOKENS", "FINISH_REASON_UNSPECIFIED":
		return "length"
	case "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII":
		return "content_filter"
	default:
		return "stop"
	}
}

func setGeminiAuthentication(req *http.Request, token string, apiKey bool) {
	if apiKey {
		req.Header.Set("X-Goog-Api-Key", token)
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func (a *GeminiAdapter) requestTarget(ctx context.Context, envelope *modelrouter.RequestEnvelope, stream bool) (string, string, bool, error) {
	credential := strings.TrimSpace(a.APIKey)
	if credential == "" {
		return "", "", false, errors.New("gemini provider credential is required")
	}
	if strings.HasPrefix(credential, "{") {
		account, err := parseGeminiServiceAccount(credential)
		if err != nil {
			return "", "", false, err
		}
		token, err := geminiOAuthToken(ctx, account, a.ProxyURL)
		if err != nil {
			return "", "", false, err
		}
		endpoint, err := a.vertexEndpoint(account, envelope, stream)
		return endpoint, token, false, err
	}
	baseURL := strings.TrimRight(strings.TrimSpace(a.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://generativelanguage.googleapis.com"
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return "", "", false, errors.New("gemini provider base URL must be an http(s) URL")
	}
	if strings.HasSuffix(parsed.Hostname(), "aiplatform.googleapis.com") {
		return "", "", false, errors.New("Vertex AI requires Google service-account JSON")
	}
	model := strings.TrimPrefix(strings.TrimSpace(firstNonEmpty(envelope.UpstreamModelID, envelope.Model)), "models/")
	if model == "" || strings.ContainsAny(model, "/\\") {
		return "", "", false, errors.New("gemini model id must be a single model name")
	}
	basePath := strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(basePath, "/v1") && !strings.HasSuffix(basePath, "/v1beta") {
		basePath += "/v1beta"
	}
	action := "generateContent"
	if stream {
		action = "streamGenerateContent"
	}
	parsed.Path = basePath + "/models/" + model + ":" + action
	parsed.RawQuery = ""
	if stream {
		parsed.RawQuery = "alt=sse"
	}
	return parsed.String(), credential, true, nil
}
