package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/providercompat"
)

// ErrEndpointNotSupported is returned when a provider does not support the requested endpoint type
var ErrEndpointNotSupported = errors.New("endpoint not supported by provider")

var ErrProviderTypeUnsupported = errors.New("provider type has no explicit adapter")

// IsEndpointNotSupported checks if an error indicates the provider does not support the endpoint
func IsEndpointNotSupported(err error) bool {
	return errors.Is(err, ErrEndpointNotSupported)
}

// UpstreamHTTPError represents an error from the upstream provider (4xx/5xx responses)
type UpstreamHTTPError struct {
	StatusCode int
	Body       []byte
	Message    string
	Headers    http.Header
}

func (e *UpstreamHTTPError) Error() string {
	return fmt.Sprintf("upstream HTTP error: status=%d, message=%s", e.StatusCode, e.Message)
}

// IsUpstreamHTTPError checks if an error is an upstream HTTP error
func IsUpstreamHTTPError(err error) bool {
	_, ok := err.(*UpstreamHTTPError)
	return ok
}

// GetUpstreamHTTPError returns the UpstreamHTTPError if the error is one, nil otherwise
func GetUpstreamHTTPError(err error) *UpstreamHTTPError {
	if e, ok := err.(*UpstreamHTTPError); ok {
		return e
	}
	return nil
}

// ProviderAdapter 提供商适配器接口
type ProviderAdapter interface {
	Name() string
	SupportsEndpoint(endpoint string) bool
	TransformRequest(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, error)
	Call(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) ([]byte, error)
	// CallStreaming 向上游发 stream:true、边收 SSE 边累积, 返回与 Call 等价的、上游原生格式的
	// 完整非流式响应体。下游 TransformResponse 照旧跑(评审契约: 不在 adapter 内提前转格式)。
	CallStreaming(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) ([]byte, error)
	TransformResponse(resp []byte) ([]byte, error)
}

// EndpointCapability lets the routing executor reject an inapplicable route
// before reserving health state or invoking an upstream.
type EndpointCapability interface {
	SupportsEndpoint(endpoint string) bool
}

// FileUploadRequest is the normalized OpenAI-compatible multipart payload.
// The gateway creates it from authenticated request bytes; callers must not
// derive the upstream route or credentials from this structure.
type FileUploadRequest struct {
	FileName    string
	ContentType string
	Purpose     string
	Content     []byte
}

// FileUploadCaller is implemented only by adapters that explicitly support
// the OpenAI-compatible files endpoint.
type FileUploadCaller interface {
	UploadFile(ctx context.Context, upload FileUploadRequest) ([]byte, error)
}

// ImageResponseTransformer converts a Responses image-generation result into
// the OpenAI Images API response shape.
type ImageResponseTransformer interface {
	TransformImageResponse(respBody []byte) ([]byte, error)
}

// ProviderConfig holds provider-specific configuration
type ProviderConfig struct {
	BaseURL  string
	APIKey   string
	ProxyURL string
	AuthMode string
	// NativeAnthropicMessages makes a Chat client use the Anthropic Messages
	// wire protocol upstream while preserving the Chat response contract.
	NativeAnthropicMessages bool
	AzureAPIVersion         string
	StreamIdleTimeout       time.Duration
}

// GetAdapter returns the adapter for a provider type
func GetAdapter(name string) ProviderAdapter {
	return GetAdapterWithConfig(name, ProviderConfig{})
}

// GetAdapterWithConfig returns an adapter with custom configuration
func GetAdapterWithConfig(name string, config ProviderConfig) ProviderAdapter {
	if config.NativeAnthropicMessages {
		return &AnthropicAdapter{BaseURL: config.BaseURL, APIKey: config.APIKey, ProxyURL: config.ProxyURL, AuthMode: config.AuthMode, StreamIdleTimeout: config.StreamIdleTimeout}
	}
	switch name {
	case "openai":
		return &OpenAIAdapter{BaseURL: config.BaseURL, APIKey: config.APIKey, ProxyURL: config.ProxyURL, AuthMode: config.AuthMode, StreamIdleTimeout: config.StreamIdleTimeout}
	case "anthropic":
		return &AnthropicAdapter{BaseURL: config.BaseURL, APIKey: config.APIKey, ProxyURL: config.ProxyURL, AuthMode: config.AuthMode, StreamIdleTimeout: config.StreamIdleTimeout}
	case "bedrock":
		return &BedrockAdapter{BaseURL: config.BaseURL, APIKey: config.APIKey, ProxyURL: config.ProxyURL, StreamIdleTimeout: config.StreamIdleTimeout}
	case "gemini", "vertex":
		return &GeminiAdapter{BaseURL: config.BaseURL, APIKey: config.APIKey, ProxyURL: config.ProxyURL, StreamIdleTimeout: config.StreamIdleTimeout}
	case "azure":
		return &AzureAdapter{OpenAIAdapter: OpenAIAdapter{BaseURL: config.BaseURL, APIKey: config.APIKey, ProxyURL: config.ProxyURL, AuthMode: config.AuthMode, AzureAPIVersion: config.AzureAPIVersion, Azure: true, StreamIdleTimeout: config.StreamIdleTimeout}}
	default:
		if providercompat.OpenAICompatible(name) {
			return &OpenAICompatibleAdapter{OpenAIAdapter: OpenAIAdapter{BaseURL: config.BaseURL, APIKey: config.APIKey, ProxyURL: config.ProxyURL, AuthMode: config.AuthMode, StreamIdleTimeout: config.StreamIdleTimeout}, ProviderType: name}
		}
		return nil
	}
}

// SupportsChatResponsesBridge reports whether the provider adapter speaks the
// OpenAI wire format and can use the gateway's Chat -> Responses bridge.
func SupportsChatResponsesBridge(providerType string) bool {
	switch GetAdapter(providerType).(type) {
	case *OpenAIAdapter, *OpenAICompatibleAdapter, *AzureAdapter:
		return true
	default:
		return false
	}
}

// OpenAICompatibleAdapter is explicit about the provider type while reusing
// the OpenAI-compatible wire format. Capability admission remains on the
// model route; this adapter does not imply native Responses support.
type OpenAICompatibleAdapter struct {
	OpenAIAdapter
	ProviderType string
}

func (a *OpenAICompatibleAdapter) Name() string {
	return a.ProviderType
}

// AzureAdapter keeps Azure as a distinct provider choice even though the
// current customer endpoint exposes the OpenAI-compatible path.
type AzureAdapter struct {
	OpenAIAdapter
}

func (a *AzureAdapter) Name() string { return "azure" }

// OpenAIAdapter OpenAI 提供商适配器
type OpenAIAdapter struct {
	BaseURL           string
	APIKey            string
	ProxyURL          string
	AuthMode          string
	AzureAPIVersion   string
	Azure             bool
	StreamIdleTimeout time.Duration
	toolNames         *compatibleToolNameMap
}

func (a *OpenAIAdapter) Name() string {
	return "openai"
}

func (a *OpenAIAdapter) SupportsEndpoint(endpoint string) bool {
	if a.usesRawAuthorization() {
		return endpoint == "chat"
	}
	return endpoint == "chat" || endpoint == "embeddings" || endpoint == "responses" || endpoint == "images" || endpoint == "messages" || endpoint == "files"
}

func (a *OpenAIAdapter) usesRawAuthorization() bool {
	return strings.EqualFold(strings.TrimSpace(a.AuthMode), "authorization_raw")
}

// UploadFile forwards an authenticated multipart upload to an explicitly
// configured OpenAI-compatible upstream. It deliberately has no public
// OpenAI fallback: a tenant route must select the upstream before bytes leave
// the gateway.
func (a *OpenAIAdapter) UploadFile(ctx context.Context, upload FileUploadRequest) ([]byte, error) {
	if a.usesRawAuthorization() {
		return nil, fmt.Errorf("%w: authorization_raw only supports chat", ErrEndpointNotSupported)
	}
	baseURL := strings.TrimSpace(a.BaseURL)
	if baseURL == "" {
		return nil, fmt.Errorf("file upload requires a configured base URL")
	}
	if a.Azure && azureNativeEndpoint(baseURL) {
		return nil, fmt.Errorf("%w: Azure files endpoint requires an explicit adapter", ErrEndpointNotSupported)
	}
	if a.APIKey == "" {
		return nil, fmt.Errorf("openai provider is not configured with an API key")
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if strings.TrimSpace(upload.Purpose) != "" {
		if err := writer.WriteField("purpose", upload.Purpose); err != nil {
			return nil, fmt.Errorf("encode file upload purpose: %w", err)
		}
	}
	fileName := strings.TrimSpace(upload.FileName)
	if fileName == "" {
		fileName = "upload"
	}
	contentType := strings.TrimSpace(upload.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	partHeader := make(textproto.MIMEHeader)
	partHeader.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{
		"name":     "file",
		"filename": fileName,
	}))
	partHeader.Set("Content-Type", contentType)
	part, err := writer.CreatePart(partHeader)
	if err != nil {
		return nil, fmt.Errorf("encode file upload part: %w", err)
	}
	if _, err := part.Write(upload.Content); err != nil {
		return nil, fmt.Errorf("encode file upload body: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finalize file upload multipart body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinOpenAIPath(strings.TrimRight(baseURL, "/"), "/files"), &body)
	if err != nil {
		return nil, fmt.Errorf("create file upload request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if err := a.setAuthentication(req); err != nil {
		return nil, err
	}
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

func setVerifiedIdempotencyHeader(req *http.Request, envelope *modelrouter.RequestEnvelope) {
	if req == nil || envelope == nil || envelope.ClientRetryID == "" {
		return
	}
	capabilities := envelope.ProtocolCapabilities
	if capabilities.Explicit && capabilities.Verified && capabilities.Idempotent {
		req.Header.Set("Idempotency-Key", envelope.ClientRetryID)
	}
}

func (a *OpenAIAdapter) TransformRequest(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, error) {
	if envelope != nil && envelope.EndpointType == "messages" && !usesMessagesOpenAIBridge(envelope) {
		return rewriteNativeAnthropicModel(envelope, rawBody)
	}
	requestBody := rawBody
	a.toolNames = nil
	if usesMessagesOpenAIBridge(envelope) {
		var err error
		requestBody, err = transformAnthropicMessagesToChat(envelope, rawBody)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEndpointNotSupported, err)
		}
	}
	if envelope != nil && (envelope.EndpointType == "chat" || usesMessagesOpenAIBridge(envelope)) {
		var err error
		requestBody, a.toolNames, err = normalizeChatToolNames(requestBody)
		if err != nil {
			return nil, err
		}
	}
	if usesOpenAIResponsesBridge(envelope) {
		return transformChatCompletionsToResponses(envelope, requestBody)
	}
	if usesResponsesImageBridge(envelope) {
		return transformImagesRequestToResponses(envelope, rawBody)
	}

	// OpenAI 格式基本不变。仅当模型记录携带了与客户端不同的 upstream_model_id 时，
	// 替换请求体中的 model 字段，使上游收到它期望的 id。
	if envelope == nil || envelope.UpstreamModelID == "" || envelope.UpstreamModelID == envelope.Model {
		return requestBody, nil
	}

	var body map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(requestBody))
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		return nil, fmt.Errorf("failed to parse request body for model rewrite: %w", err)
	}

	body["model"] = envelope.UpstreamModelID
	return json.Marshal(body)
}

func (a *OpenAIAdapter) Call(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) ([]byte, error) {
	baseURL := a.BaseURL
	if baseURL == "" {
		// Only allow fallback to public URL for known public providers
		// Custom/self-hosted providers must have baseURL configured
		baseURL = "https://api.openai.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	endpoint, err := a.endpointForEnvelope(baseURL, envelope)
	if err != nil {
		return nil, err
	}
	if envelope.EndpointType == "messages" && !usesMessagesOpenAIBridge(envelope) {
		return callNativeAnthropicMessages(ctx, envelope, payload, baseURL, a.APIKey, a.ProxyURL, "bearer", false, 0)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	if a.APIKey == "" {
		return nil, fmt.Errorf("openai provider is not configured with an API key")
	}
	if err := a.setAuthentication(req); err != nil {
		return nil, err
	}
	setVerifiedIdempotencyHeader(req, envelope)

	client, err := nonStreamingHTTPClient(a.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid configured outbound proxy: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := readResponseBody(resp)
	if err != nil {
		return nil, err
	}
	if envelope.EndpointType == "responses" || usesResponsesImageBridge(envelope) || usesOpenAIResponsesBridge(envelope) {
		if err := validateNativeResponsesJSONTerminal(body); err != nil {
			return nil, err
		}
	}
	return body, nil
}

func (a *OpenAIAdapter) setAuthentication(req *http.Request) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}
	if a.APIKey == "" {
		return fmt.Errorf("provider is not configured with a credential")
	}
	req.Header.Del("api-key")
	req.Header.Del("Authorization")
	if a.usesRawAuthorization() {
		req.Header.Set("Authorization", a.APIKey)
		return nil
	}
	if !a.Azure {
		req.Header.Set("Authorization", "Bearer "+a.APIKey)
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(a.AuthMode)) {
	case "", "api_key", "api-key", "apikey", "key":
		req.Header.Set("api-key", a.APIKey)
		return nil
	case "entra", "entra_id", "azure_ad", "oauth", "oauth2", "bearer":
		req.Header.Set("Authorization", "Bearer "+a.APIKey)
		return nil
	default:
		return fmt.Errorf("unsupported Azure authentication mode %q", a.AuthMode)
	}
}

func (a *OpenAIAdapter) endpointForEnvelope(baseURL string, envelope *modelrouter.RequestEnvelope) (string, error) {
	if a.usesRawAuthorization() {
		if envelope == nil || envelope.EndpointType != "chat" {
			endpoint := ""
			if envelope != nil {
				endpoint = envelope.EndpointType
			}
			return "", fmt.Errorf("%w: authorization_raw only supports chat, got %s", ErrEndpointNotSupported, endpoint)
		}
		return a.BaseURL, nil
	}
	if a.Azure && azureNativeEndpoint(baseURL) {
		return azureEndpointWithVersion(baseURL, envelope, a.AzureAPIVersion)
	}
	if usesOpenAIResponsesBridge(envelope) {
		return joinOpenAIPath(baseURL, "/responses"), nil
	}
	switch envelope.EndpointType {
	case "chat":
		return joinOpenAIPath(baseURL, "/chat/completions"), nil
	case "embeddings":
		return joinOpenAIPath(baseURL, "/embeddings"), nil
	case "responses":
		return joinOpenAIPath(baseURL, "/responses"), nil
	case "images":
		if usesResponsesImageBridge(envelope) {
			return joinOpenAIPath(baseURL, "/responses"), nil
		}
		return joinOpenAIPath(baseURL, "/images/generations"), nil
	case "messages":
		if usesMessagesOpenAIBridge(envelope) && strings.EqualFold(envelope.UpstreamProtocol, "chat") {
			return joinOpenAIPath(baseURL, "/chat/completions"), nil
		}
		return "", nil
	default:
		return "", fmt.Errorf("%w: endpoint type %s", ErrEndpointNotSupported, envelope.EndpointType)
	}
}

func azureNativeEndpoint(baseURL string) bool {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return strings.Contains(host, ".openai.azure.com") ||
		strings.Contains(host, ".cognitiveservices.azure.com")
}

func azureEndpoint(baseURL string, envelope *modelrouter.RequestEnvelope) (string, error) {
	return azureEndpointWithVersion(baseURL, envelope, "")
}

func azureEndpointWithVersion(baseURL string, envelope *modelrouter.RequestEnvelope, apiVersion string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid Azure base URL")
	}

	if usesOpenAIResponsesBridge(envelope) {
		responsesEnvelope := *envelope
		responsesEnvelope.EndpointType = "responses"
		return azureEndpointWithVersion(baseURL, &responsesEnvelope, apiVersion)
	}

	path := strings.TrimRight(parsed.Path, "/")
	lowerPath := strings.ToLower(path)
	v1Root := ""
	if strings.HasSuffix(lowerPath, "/openai/v1") {
		v1Root = path
	}
	if envelope.EndpointType == "responses" {
		if v1Root != "" {
			parsed.Path = v1Root + "/responses"
		} else {
			root := path
			if !strings.HasSuffix(strings.ToLower(root), "/openai") {
				root += "/openai"
			}
			if strings.Contains(strings.ToLower(parsed.Hostname()), "cognitiveservices.azure.com") {
				parsed.Path = root + "/responses"
			} else {
				parsed.Path = root + "/v1/responses"
			}
		}
		query := parsed.Query()
		query.Del("api-version")
		parsed.RawQuery = query.Encode()
		return parsed.String(), nil
	}
	if envelope.EndpointType == "messages" {
		return "", fmt.Errorf("%w: Azure does not provide Anthropic Messages", ErrEndpointNotSupported)
	}

	modelID := strings.TrimSpace(envelope.UpstreamModelID)
	if modelID == "" {
		modelID = strings.TrimSpace(envelope.Model)
	}
	if modelID == "" {
		return "", fmt.Errorf("Azure deployment is required")
	}
	task := ""
	switch envelope.EndpointType {
	case "chat":
		task = "chat/completions"
	case "embeddings":
		task = "embeddings"
	case "images":
		task = "images/generations"
	default:
		return "", fmt.Errorf("%w: endpoint type %s", ErrEndpointNotSupported, envelope.EndpointType)
	}
	if v1Root != "" {
		parsed.Path = v1Root + "/" + task
		query := parsed.Query()
		query.Del("api-version")
		parsed.RawQuery = query.Encode()
		return parsed.String(), nil
	}
	root := path
	if !strings.HasSuffix(strings.ToLower(root), "/openai") {
		root += "/openai"
	}
	parsed.Path = root + "/deployments/" + url.PathEscape(modelID) + "/" + task
	query := parsed.Query()
	version := strings.TrimSpace(apiVersion)
	if version == "" {
		version = query.Get("api-version")
	}
	if version == "" {
		version = "2024-10-21"
	}
	query.Set("api-version", version)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func usesResponsesImageBridge(envelope *modelrouter.RequestEnvelope) bool {
	return envelope != nil && envelope.EndpointType == "images" && envelope.ProtocolCapabilities.ImagesResponsesBridge
}

func transformImagesRequestToResponses(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, error) {
	var imagesRequest map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &imagesRequest); err != nil {
		return nil, fmt.Errorf("failed to parse image request for Responses bridge: %w", err)
	}

	var prompt string
	if err := json.Unmarshal(imagesRequest["prompt"], &prompt); err != nil || strings.TrimSpace(prompt) == "" {
		return nil, fmt.Errorf("image prompt is required for Responses bridge")
	}

	if streamRaw, ok := imagesRequest["stream"]; ok {
		var stream bool
		if err := json.Unmarshal(streamRaw, &stream); err != nil {
			return nil, fmt.Errorf("image stream must be a boolean")
		}
		if stream {
			return nil, fmt.Errorf("streaming is not supported for image generation")
		}
	}

	if nRaw, ok := imagesRequest["n"]; ok {
		var n int
		if err := json.Unmarshal(nRaw, &n); err != nil || n < 1 {
			return nil, fmt.Errorf("image n must be a positive integer")
		}
		if n > 1 {
			return nil, fmt.Errorf("Responses image generation supports n=1 only")
		}
	}

	modelName := imagesRequestModel(envelope, imagesRequest)
	if modelName == "" {
		return nil, fmt.Errorf("image model is required for Responses bridge")
	}

	imageType, _ := json.Marshal("image_generation")
	imageTool := map[string]json.RawMessage{
		"type": json.RawMessage(imageType),
	}
	for _, field := range []string{
		"size",
		"quality",
		"background",
		"output_format",
		"output_compression",
		"moderation",
		"input_fidelity",
	} {
		if value, ok := imagesRequest[field]; ok {
			imageTool[field] = value
		}
	}

	responsesRequest := map[string]any{
		"model": modelName,
		"input": prompt,
		"tools": []any{imageTool},
	}
	return json.Marshal(responsesRequest)
}

func imagesRequestModel(envelope *modelrouter.RequestEnvelope, raw map[string]json.RawMessage) string {
	if envelope != nil && strings.TrimSpace(envelope.UpstreamModelID) != "" {
		return envelope.UpstreamModelID
	}
	var modelName string
	_ = json.Unmarshal(raw["model"], &modelName)
	if strings.TrimSpace(modelName) != "" {
		return modelName
	}
	if envelope != nil {
		return envelope.Model
	}
	return ""
}

func (a *OpenAIAdapter) TransformResponse(respBody []byte) ([]byte, error) {
	// OpenAI response is already in standard format except for wire-safe tool
	// names, which must be restored to the identity supplied by the client.
	return restoreChatToolNames(respBody, a.toolNames)
}

// TransformImageResponse keeps native Images API responses unchanged and
// extracts image_generation_call results from the Responses bridge format.
func (a *OpenAIAdapter) TransformImageResponse(respBody []byte) ([]byte, error) {
	var response map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("invalid image provider response: %w", err)
	}
	if _, ok := response["data"]; ok {
		return respBody, nil
	}

	var createdAt int64
	_ = json.Unmarshal(response["created_at"], &createdAt)

	var output []map[string]json.RawMessage
	if err := json.Unmarshal(response["output"], &output); err != nil {
		return nil, fmt.Errorf("Responses image output is missing: %w", err)
	}

	data := make([]map[string]string, 0, len(output))
	for _, item := range output {
		var itemType, result string
		_ = json.Unmarshal(item["type"], &itemType)
		_ = json.Unmarshal(item["result"], &result)
		if itemType == "image_generation_call" && strings.TrimSpace(result) != "" {
			data = append(data, map[string]string{"b64_json": result})
		}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("Responses response contains no image_generation_call result")
	}
	if createdAt == 0 {
		createdAt = time.Now().Unix()
	}

	return json.Marshal(map[string]any{
		"created": createdAt,
		"data":    data,
	})
}

// AnthropicAdapter Anthropic 提供商适配器
type AnthropicAdapter struct {
	BaseURL           string
	APIKey            string
	ProxyURL          string
	AuthMode          string
	StreamIdleTimeout time.Duration
	toolNames         *compatibleToolNameMap
}

func (a *AnthropicAdapter) authenticationMode() (string, error) {
	switch strings.ToLower(strings.TrimSpace(a.AuthMode)) {
	case "", "x-api-key", "x_api_key", "api-key", "apikey", "key":
		return "x-api-key", nil
	case "bearer":
		return "bearer", nil
	default:
		return "", fmt.Errorf("unsupported Anthropic authentication mode %q", a.AuthMode)
	}
}

func (a *AnthropicAdapter) Name() string {
	return "anthropic"
}

func (a *AnthropicAdapter) SupportsEndpoint(endpoint string) bool {
	return endpoint == "chat" || endpoint == "messages"
}

func (a *AnthropicAdapter) TransformRequest(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, error) {
	if envelope != nil && envelope.EndpointType == "messages" {
		payload, err := rewriteNativeAnthropicModel(envelope, rawBody)
		if err != nil {
			return nil, err
		}
		// 先按模型 profile 改写 thinking（enabled/disabled/between_tools 各代际不通用），
		// 再收紧 max_tokens 并保证剩余的 budget_tokens 小于它。
		payload, err = applyNativeAnthropicThinkingCompat(payload, envelope)
		if err != nil {
			return nil, err
		}
		return capNativeAnthropicOutputTokens(payload)
	}
	a.toolNames = nil
	request, toolNames, err := transformOpenAIChatToAnthropic(envelope, rawBody)
	if err != nil {
		return nil, err
	}
	a.toolNames = toolNames
	return request, nil
}

func (a *AnthropicAdapter) Call(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) ([]byte, error) {
	authMode, err := a.authenticationMode()
	if err != nil {
		return nil, err
	}
	if envelope.EndpointType == "messages" {
		baseURL := a.BaseURL
		if baseURL == "" {
			baseURL = "https://api.anthropic.com"
		}
		return callNativeAnthropicMessages(ctx, envelope, payload, baseURL, a.APIKey, a.ProxyURL, authMode, false, 0)
	}
	// Anthropic only supports chat endpoint (messages API)
	if envelope.EndpointType != "chat" {
		return nil, fmt.Errorf("%w: anthropic provider only supports chat (got %s)", ErrEndpointNotSupported, envelope.EndpointType)
	}

	baseURL := a.BaseURL
	if baseURL == "" {
		// Only allow fallback to public URL for known public providers
		// Custom/self-hosted providers must have baseURL configured
		baseURL = "https://api.anthropic.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	endpoint := baseURL + "/v1/messages"
	if strings.HasSuffix(baseURL, "/v1") {
		endpoint = baseURL + "/messages"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")

	if a.APIKey == "" {
		return nil, fmt.Errorf("anthropic provider is not configured with an API key")
	}
	if authMode == "bearer" {
		req.Header.Set("Authorization", "Bearer "+a.APIKey)
	} else {
		req.Header.Set("x-api-key", a.APIKey)
	}

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

func joinOpenAIPath(baseURL, endpointSuffix string) string {
	if strings.HasSuffix(baseURL, "/v1") {
		return baseURL + endpointSuffix
	}
	return baseURL + "/v1" + endpointSuffix
}

func (a *AnthropicAdapter) TransformResponse(respBody []byte) ([]byte, error) {
	// Anthropic 响应转 OpenAI 格式。
	// 同时兼容: (1) 非流式 Call 的原生响应; (2) CallStreaming 累积器重组出的等价 Anthropic message JSON。
	var anthropicResp map[string]interface{}
	if err := json.Unmarshal(respBody, &anthropicResp); err != nil {
		return nil, err
	}

	// 转换为 OpenAI 格式
	openaiResp := map[string]interface{}{
		"id":      anthropicResp["id"],
		"object":  "chat.completion",
		"created": 0,
		"model":   anthropicResp["model"],
	}

	// 遍历所有 content block: text 合并、tool_use→OpenAI tool_calls、thinking→reasoning_content。
	// (评审 §1.3: 旧实现只取 content[0].text, 多 block 会丢。)
	if content, ok := anthropicResp["content"].([]interface{}); ok {
		var textParts []string
		var reasoningParts []string
		toolCalls := make([]interface{}, 0)

		for _, item := range content {
			block, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			switch block["type"] {
			case "text":
				if t, ok := block["text"].(string); ok {
					textParts = append(textParts, t)
				}
			case "thinking":
				if t, ok := block["thinking"].(string); ok && t != "" {
					reasoningParts = append(reasoningParts, t)
				}
			case "tool_use":
				// Anthropic tool_use.input(对象) → OpenAI function.arguments(JSON 字符串)
				args := "{}"
				if input, ok := block["input"]; ok && input != nil {
					if b, err := json.Marshal(input); err == nil {
						args = string(b)
					}
				}
				id, _ := block["id"].(string)
				name, _ := block["name"].(string)
				toolCalls = append(toolCalls, map[string]interface{}{
					"id":   id,
					"type": "function",
					"function": map[string]interface{}{
						"name":      name,
						"arguments": args,
					},
				})
			}
		}

		message := map[string]interface{}{
			"role":    "assistant",
			"content": strings.Join(textParts, ""),
		}
		if len(reasoningParts) > 0 {
			message["reasoning_content"] = strings.Join(reasoningParts, "")
		}
		if len(toolCalls) > 0 {
			message["tool_calls"] = toolCalls
			// 有 tool_calls 且无文本时 content 置 null, 更符合 OpenAI 语义
			if len(textParts) == 0 {
				message["content"] = nil
			}
		}

		openaiResp["choices"] = []interface{}{
			map[string]interface{}{
				"index":         0,
				"message":       message,
				"finish_reason": anthropicStopToOpenAI(anthropicResp["stop_reason"], len(toolCalls) > 0),
			},
		}
	}

	// 转换 usage
	if usage, ok := anthropicResp["usage"].(map[string]interface{}); ok {
		inputTokens, _ := toFloat(usage["input_tokens"])
		outputTokens, _ := toFloat(usage["output_tokens"])
		cacheReadTokens, hasCacheRead := toFloat(usage["cache_read_input_tokens"])
		cacheWriteTokens, hasCacheWrite := toFloat(usage["cache_creation_input_tokens"])
		if inputTokens < 0 {
			inputTokens = 0
		}
		if cacheReadTokens < 0 {
			cacheReadTokens = 0
		}
		if cacheWriteTokens < 0 {
			cacheWriteTokens = 0
		}
		totalInputTokens := inputTokens + cacheReadTokens + cacheWriteTokens
		openAIUsage := map[string]interface{}{
			"prompt_tokens":     int(totalInputTokens),
			"completion_tokens": int(outputTokens),
			"total_tokens":      int(totalInputTokens + outputTokens),
		}
		if hasCacheRead || hasCacheWrite {
			openAIUsage["cache_read_input_tokens"] = int(cacheReadTokens)
			openAIUsage["cache_creation_input_tokens"] = int(cacheWriteTokens)
			openAIUsage["prompt_tokens_details"] = map[string]interface{}{
				"cached_tokens":               int(cacheReadTokens),
				"cache_creation_input_tokens": int(cacheWriteTokens),
			}
		}
		openaiResp["usage"] = openAIUsage
	}

	result, err := json.Marshal(openaiResp)
	if err != nil {
		return nil, err
	}
	return restoreChatToolNames(result, a.toolNames)
}

// anthropicStopToOpenAI 把 Anthropic stop_reason 映射成 OpenAI finish_reason。
func anthropicStopToOpenAI(stop interface{}, hasToolCalls bool) string {
	s, _ := stop.(string)
	switch s {
	case "end_turn", "stop_sequence":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	}
	if hasToolCalls {
		return "tool_calls"
	}
	return "stop"
}

// toFloat 把 JSON 数字(float64)或可解析的字符串安全转成 float64。
func toFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

const maxProviderResponseBodyBytes int64 = 64 << 20

func nonStreamingHTTPClient(proxyURL string) (*http.Client, error) {
	transport, err := transportWithConfiguredProxy(proxyURL)
	if err != nil {
		return nil, err
	}
	if transport == nil {
		return &http.Client{Timeout: 10 * time.Minute}, nil
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Minute}, nil
}

// transportWithConfiguredProxy returns a private clone of the default transport
// when a customer-configured outbound proxy is present. A missing proxy keeps
// the previous default transport behaviour, including deployment-level proxy
// environment variables.
func transportWithConfiguredProxy(rawProxyURL string) (*http.Transport, error) {
	if strings.TrimSpace(rawProxyURL) == "" {
		return nil, nil
	}
	proxy, err := parseOutboundProxyURL(rawProxyURL)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxy)
	return transport, nil
}

func parseOutboundProxyURL(rawProxyURL string) (*url.URL, error) {
	proxy, err := url.Parse(strings.TrimSpace(rawProxyURL))
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}
	if proxy.Scheme != "http" && proxy.Scheme != "https" {
		return nil, fmt.Errorf("proxy URL must use http or https")
	}
	if proxy.Host == "" {
		return nil, fmt.Errorf("proxy URL host is required")
	}
	if (proxy.Path != "" && proxy.Path != "/") || proxy.RawQuery != "" || proxy.Fragment != "" {
		return nil, fmt.Errorf("proxy URL must not include a path, query, or fragment")
	}
	return proxy, nil
}

func readResponseBody(resp *http.Response) ([]byte, error) {
	return readResponseBodyWithLimit(resp, maxProviderResponseBodyBytes)
}

func readResponseBodyWithLimit(resp *http.Response, limit int64) ([]byte, error) {
	limited := &io.LimitedReader{R: resp.Body, N: limit + 1}
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("upstream response exceeds %d bytes", limit)
	}

	// Check status code - non-2xx responses are errors
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to extract error message from body
		var message string
		var errResp map[string]interface{}
		if json.Unmarshal(body, &errResp) == nil {
			if msg, ok := errResp["error"].(map[string]interface{}); ok {
				if m, ok := msg["message"].(string); ok {
					message = m
				}
			}
		}
		if message == "" {
			message = string(body)
		}

		return nil, &UpstreamHTTPError{
			StatusCode: resp.StatusCode,
			Body:       body,
			Message:    message,
			Headers:    copyAnthropicResponseHeaders(resp.Header),
		}
	}

	return body, nil
}

func validateNativeResponsesJSONTerminal(raw []byte) error {
	var response struct {
		Object string          `json:"object"`
		Status string          `json:"status"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return fmt.Errorf("invalid native Responses payload: %w", err)
	}
	if response.Object != "response" {
		return fmt.Errorf("invalid native Responses object %q", response.Object)
	}
	switch response.Status {
	case "completed", "incomplete":
		return nil
	case "failed":
		message := "native Responses upstream failed"
		if len(response.Error) > 0 && string(response.Error) != "null" {
			if extracted := extractErrorMessage(response.Error); extracted != "" {
				message = extracted
			}
		}
		return &UpstreamHTTPError{StatusCode: http.StatusBadGateway, Body: append([]byte(nil), raw...), Message: message}
	default:
		return fmt.Errorf("invalid native Responses terminal status %q", response.Status)
	}
}
