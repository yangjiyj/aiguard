package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AnthropicMessagesRequest represents the subset of Anthropic Messages used by Claude Code.
type AnthropicMessagesRequest struct {
	Model       string                    `json:"model"`
	MaxTokens   int                       `json:"max_tokens,omitempty"`
	Messages    []AnthropicRequestMessage `json:"messages"`
	System      interface{}               `json:"system,omitempty"`
	Tools       []AnthropicTool           `json:"tools,omitempty"`
	Stream      bool                      `json:"stream,omitempty"`
	Temperature float64                   `json:"temperature,omitempty"`
}

type AnthropicRequestMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

type AnthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

type AnthropicMessagesResponse struct {
	ID           string                  `json:"id"`
	Type         string                  `json:"type"`
	Role         string                  `json:"role"`
	Content      []AnthropicContentBlock `json:"content"`
	Model        string                  `json:"model"`
	StopReason   string                  `json:"stop_reason,omitempty"`
	StopSequence *string                 `json:"stop_sequence"`
	Usage        AnthropicUsage          `json:"usage"`
}

type AnthropicContentBlock struct {
	Type  string      `json:"type"`
	Text  string      `json:"text,omitempty"`
	ID    string      `json:"id,omitempty"`
	Name  string      `json:"name,omitempty"`
	Input interface{} `json:"input,omitempty"`
}

type AnthropicUsage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
}

// MessagesHandler handles Anthropic-compatible /v1/messages requests.
type MessagesHandler struct {
	cfg                    *config.Config
	modelResolver          ModelResolver
	rateLimiter            RateLimitChecker
	securityClient         SecurityChecker
	auditWriter            AuditWriter
	providerAdapterFactory ProviderAdapterFactory
	toolRiskClient         *ToolRiskClient
	proxyRateLimiter       ProxyRateLimiter
	governor               GovernorDecider
	quotaAdmission         QuotaAdmission
	db                     *pgxpool.Pool // for governor alert_inbox writes; may be nil
	modelRouteEngine       modelrouter.Engine
	billingPreflight       BillingPreflight
	fingerprints           *scanfp.Store // P1-B 已检指纹缓存（模块 2a）；nil=禁用（默认零回归）
	artifactStore          retentionstore.Store
	relayMetrics           *relay.Metrics
}

// SetGovernor injects a governor into the MessagesHandler so it is passed to
// the internal ChatCompletionsHandler used to process each request.
func (h *MessagesHandler) SetGovernor(gov GovernorDecider) {
	h.governor = gov
}

func (h *MessagesHandler) SetQuotaAdmission(admission QuotaAdmission) {
	h.quotaAdmission = admission
}

// SetDB injects the database pool for governor alert_inbox writes.
func (h *MessagesHandler) SetDB(db *pgxpool.Pool) {
	h.db = db
}

// SetRetentionArtifactStore passes the shared content-evidence store to the
// internal ChatCompletionsHandler used for Anthropic-compatible requests.
func (h *MessagesHandler) SetRetentionArtifactStore(store retentionstore.Store) {
	if h != nil {
		h.artifactStore = store
	}
}

func (h *MessagesHandler) SetModelRoutingEngine(engine modelrouter.Engine) {
	h.modelRouteEngine = engine
}

func (h *MessagesHandler) SetBillingPreflight(client BillingPreflight) { h.billingPreflight = client }

func (h *MessagesHandler) SetRelayMetrics(metrics *relay.Metrics) { h.relayMetrics = metrics }

func (h *MessagesHandler) newChatHandler() *ChatCompletionsHandler {
	chatHandler := NewChatCompletionsHandler(h.cfg, h.modelResolver, h.rateLimiter, h.securityClient, h.auditWriter, h.providerAdapterFactory, h.toolRiskClient, h.proxyRateLimiter)
	chatHandler.SetGovernor(h.governor)
	chatHandler.SetQuotaAdmission(h.quotaAdmission)
	chatHandler.SetDB(h.db)
	chatHandler.SetFingerprintStore(h.fingerprints)
	chatHandler.SetRouting(nil, nil, nil, h.modelRouteEngine)
	chatHandler.SetRetentionArtifactStore(h.artifactStore)
	chatHandler.SetBillingPreflight(h.billingPreflight)
	chatHandler.SetRelayMetrics(h.relayMetrics)
	return chatHandler
}

func NewMessagesHandler(
	cfg *config.Config,
	modelResolver ModelResolver,
	rateLimiter RateLimitChecker,
	securityClient SecurityChecker,
	auditWriter AuditWriter,
	providerAdapterFactory ProviderAdapterFactory,
	toolRiskClient *ToolRiskClient,
	proxyRateLimiter ProxyRateLimiter,
) *MessagesHandler {
	if providerAdapterFactory == nil {
		factory := &RealProviderAdapterFactory{}
		if cfg != nil {
			factory.StreamIdleTimeout = cfg.UpstreamStreamIdleTimeout
		}
		providerAdapterFactory = factory
	}
	return &MessagesHandler{
		cfg:                    cfg,
		modelResolver:          modelResolver,
		rateLimiter:            rateLimiter,
		securityClient:         securityClient,
		auditWriter:            auditWriter,
		providerAdapterFactory: providerAdapterFactory,
		toolRiskClient:         toolRiskClient,
		proxyRateLimiter:       proxyRateLimiter,
	}
}

func (h *MessagesHandler) Handler() http.HandlerFunc {
	return h.handleNativeMessagesRequest
}

func (h *MessagesHandler) convertToChatRequest(req *AnthropicMessagesRequest) (*ChatCompletionRequest, error) {
	if req.Model == "" {
		return nil, fmt.Errorf("model must not be empty")
	}

	messages := []Message{}
	if system := anthropicContentToText(req.System); system != "" {
		messages = append(messages, Message{Role: "system", Content: jsonQuote(system), SecuritySource: "system_prompt", SecurityMessageRole: "system", SecuritySourcePath: "/system"})
	}

	for messageIndex, msg := range req.Messages {
		converted, err := anthropicMessageToOpenAIValidated(msg)
		if err != nil {
			return nil, err
		}
		for i := range converted {
			converted[i].SecurityMessageIndex = &messageIndex
			converted[i].SecurityMessageRole = msg.Role
			converted[i].SecuritySourcePath = fmt.Sprintf("/messages/%d", messageIndex)
			if converted[i].SecuritySource == "" {
				converted[i].SecuritySource = messageRoleToSource(converted[i].Role)
			}
		}
		messages = append(messages, converted...)
	}

	if len(messages) == 0 {
		return nil, fmt.Errorf("no valid messages in request")
	}

	tools := make([]ToolDef, 0, len(req.Tools))
	for _, tool := range req.Tools {
		if tool.Name == "" {
			continue
		}
		tools = append(tools, ToolDef{
			Type: "function",
			Function: ToolFunc{
				Name:        tool.Name,
				Description: tool.Description,
				Parameters:  tool.InputSchema,
			},
		})
	}

	return &ChatCompletionRequest{
		Model:       req.Model,
		Messages:    messages,
		Tools:       tools,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		Stream:      false,
	}, nil
}

// anthropicMessageToOpenAI is kept for focused legacy conversion tests. The
// request handler uses the validated variant so malformed images become 400s.
func anthropicMessageToOpenAI(msg AnthropicRequestMessage) []Message {
	messages, _ := anthropicMessageToOpenAIValidated(msg)
	return messages
}

func anthropicMessageToOpenAIValidated(msg AnthropicRequestMessage) ([]Message, error) {
	role := msg.Role
	if role == "" {
		role = "user"
	}

	if content, ok := msg.Content.(string); ok {
		if content == "" {
			return nil, nil
		}
		return []Message{{Role: role, Content: jsonQuote(content)}}, nil
	}

	blocks, ok := msg.Content.([]interface{})
	if !ok {
		text := anthropicContentToText(msg.Content)
		if text == "" {
			return nil, nil
		}
		return []Message{{Role: role, Content: jsonQuote(text)}}, nil
	}

	if role == "assistant" {
		return []Message{anthropicAssistantBlocksToOpenAI(blocks)}, nil
	}

	messages := make([]Message, 0, len(blocks))
	pendingParts := make([]map[string]interface{}, 0, len(blocks))
	pendingHasMedia := false
	flushPending := func() error {
		if len(pendingParts) == 0 {
			return nil
		}
		if pendingHasMedia {
			content, err := json.Marshal(pendingParts)
			if err != nil {
				return fmt.Errorf("failed to encode image content")
			}
			messages = append(messages, Message{Role: role, Content: content})
		} else {
			textParts := make([]string, 0, len(pendingParts))
			for _, part := range pendingParts {
				text, _ := part["text"].(string)
				if text != "" {
					textParts = append(textParts, text)
				}
			}
			if len(textParts) > 0 {
				messages = append(messages, Message{Role: role, Content: jsonQuote(strings.Join(textParts, "\n"))})
			}
		}
		pendingParts = nil
		pendingHasMedia = false
		return nil
	}

	for _, block := range blocks {
		blockMap, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		blockType, _ := blockMap["type"].(string)
		switch blockType {
		case "tool_result":
			if err := flushPending(); err != nil {
				return nil, err
			}
			toolUseID, _ := blockMap["tool_use_id"].(string)
			content, imageParts, err := anthropicToolResultContent(blockMap["content"])
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(toolUseID) != "" {
				isError, _ := blockMap["is_error"].(bool)
				messages = append(messages, Message{Role: "tool", ToolCallID: toolUseID, Content: jsonQuote(content), ToolResultError: isError})
				if len(imageParts) > 0 {
					encoded, err := json.Marshal(imageParts)
					if err != nil {
						return nil, fmt.Errorf("failed to encode image content")
					}
					messages = append(messages, Message{Role: "user", Content: encoded, SecuritySource: "tool_result"})
				}
			}
		default:
			part, image, err := anthropicInputContentPart(blockMap)
			if err != nil {
				return nil, err
			}
			if part != nil {
				pendingParts = append(pendingParts, part)
				pendingHasMedia = pendingHasMedia || image
			}
		}
	}
	if err := flushPending(); err != nil {
		return nil, err
	}
	return messages, nil
}

func anthropicInputContentPart(block map[string]interface{}) (map[string]interface{}, bool, error) {
	blockType, _ := block["type"].(string)
	if blockType == "image" {
		part, err := anthropicImageToOpenAIContentPart(block)
		return part, true, err
	}
	if blockType == "document" || blockType == "file" || blockType == "input_file" || blockType == "input_document" {
		part, err := anthropicFileToOpenAIContentPart(block)
		return part, true, err
	}
	text := anthropicContentToText(block)
	if text == "" {
		return nil, false, nil
	}
	return map[string]interface{}{"type": "text", "text": text}, false, nil
}

func anthropicFileToOpenAIContentPart(block map[string]interface{}) (map[string]interface{}, error) {
	source, ok := block["source"].(map[string]interface{})
	if !ok {
		return block, nil
	}
	filename, _ := block["title"].(string)
	if filename == "" {
		filename, _ = block["filename"].(string)
	}
	sourceType, _ := source["type"].(string)
	switch sourceType {
	case "base64":
		data, _ := source["data"].(string)
		media, _ := source["media_type"].(string)
		return map[string]interface{}{
			"type": "input_file",
			"file_data": map[string]interface{}{
				"base64":    data,
				"mime_type": media,
			},
			"filename": filename,
		}, nil
	case "text":
		text, _ := source["text"].(string)
		if text == "" {
			text, _ = source["data"].(string)
		}
		return map[string]interface{}{
			"type": "input_file",
			"file_data": map[string]interface{}{
				"base64":    base64.StdEncoding.EncodeToString([]byte(text)),
				"mime_type": "text/plain",
			},
			"filename": filename,
		}, nil
	case "file":
		for _, key := range []string{"file_id", "id", "reference_id"} {
			if reference, ok := source[key].(string); ok && reference != "" {
				return map[string]interface{}{"type": "input_file", "file_id": reference, "filename": filename}, nil
			}
		}
	case "url":
		if url, ok := source["url"].(string); ok && url != "" {
			return map[string]interface{}{"type": "input_file", "file_url": url, "filename": filename}, nil
		}
	}
	// 保留未知 source 形态，交由原始请求和附件审计层处理，绝不静默丢弃。
	return block, nil
}

func anthropicToolResultContent(content interface{}) (string, []map[string]interface{}, error) {
	var blocks []interface{}
	switch value := content.(type) {
	case []interface{}:
		blocks = value
	case map[string]interface{}:
		blocks = []interface{}{value}
	default:
		return anthropicContentToText(content), nil, nil
	}

	textParts := make([]string, 0, len(blocks))
	mediaParts := make([]map[string]interface{}, 0, len(blocks))
	for _, block := range blocks {
		blockMap, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		part, image, err := anthropicInputContentPart(blockMap)
		if err != nil {
			return "", nil, err
		}
		if part == nil {
			continue
		}
		if image {
			mediaParts = append(mediaParts, part)
			continue
		}
		if text, _ := part["text"].(string); text != "" {
			textParts = append(textParts, text)
		}
	}
	return strings.Join(textParts, "\n"), mediaParts, nil
}

func anthropicImageToOpenAIContentPart(block map[string]interface{}) (map[string]interface{}, error) {
	source, ok := block["source"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("image source type must be base64")
	}
	sourceType, _ := source["type"].(string)
	if sourceType != "base64" {
		return nil, fmt.Errorf("image source type must be base64")
	}
	mediaType, _ := source["media_type"].(string)
	switch mediaType {
	case "image/jpeg", "image/png", "image/gif", "image/webp":
	default:
		return nil, fmt.Errorf("unsupported image media_type")
	}
	data, _ := source["data"].(string)
	if data == "" {
		return nil, fmt.Errorf("image data must not be empty")
	}
	if _, err := base64.StdEncoding.DecodeString(data); err != nil {
		return nil, fmt.Errorf("invalid image base64 data")
	}
	return map[string]interface{}{
		"type": "image_url",
		"image_url": map[string]interface{}{
			"url": "data:" + mediaType + ";base64," + data,
		},
	}, nil
}

func anthropicAssistantBlocksToOpenAI(blocks []interface{}) Message {
	msg := Message{Role: "assistant"}
	textParts := []string{}
	for _, block := range blocks {
		blockMap, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		blockType, _ := blockMap["type"].(string)
		switch blockType {
		case "tool_use":
			id, _ := blockMap["id"].(string)
			name, _ := blockMap["name"].(string)
			args, _ := json.Marshal(blockMap["input"])
			msg.ToolCalls = append(msg.ToolCalls, ToolCall{
				ID:   id,
				Type: "function",
				Function: ToolCallFunc{
					Name:      name,
					Arguments: string(args),
				},
			})
		default:
			text := anthropicContentToText(block)
			if text != "" {
				textParts = append(textParts, text)
			}
		}
	}
	if len(textParts) > 0 {
		msg.Content = jsonQuote(strings.Join(textParts, "\n"))
	}
	return msg
}

func anthropicContentToText(content interface{}) string {
	switch v := content.(type) {
	case nil:
		return ""
	case string:
		return v
	case []interface{}:
		parts := []string{}
		for _, item := range v {
			text := anthropicContentToText(item)
			if text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n")
	case []map[string]interface{}:
		parts := []string{}
		for _, item := range v {
			text := anthropicContentToText(item)
			if text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n")
	case map[string]interface{}:
		blockType, _ := v["type"].(string)
		switch blockType {
		case "text":
			text, _ := v["text"].(string)
			return text
		case "tool_result":
			return anthropicContentToText(v["content"])
		default:
			text, _ := v["text"].(string)
			return text
		}
	default:
		return ""
	}
}

func (h *MessagesHandler) transformChatToMessagesResponse(chatRespBody []byte, requestID string) *AnthropicMessagesResponse {
	var chatResp ChatCompletionResponse
	_ = json.Unmarshal(chatRespBody, &chatResp)

	respID := chatResp.ID
	if respID == "" {
		respID = "msg_" + requestID
	}

	content := []AnthropicContentBlock{}
	stopReason := "end_turn"
	if len(chatResp.Choices) > 0 {
		choice := chatResp.Choices[0]
		if choice.Message.Content != "" {
			content = append(content, AnthropicContentBlock{
				Type: "text",
				Text: choice.Message.Content,
			})
		}
		for _, toolCall := range choice.Message.ToolCalls {
			content = append(content, AnthropicContentBlock{
				Type:  "tool_use",
				ID:    toolCall.ID,
				Name:  toolCall.Function.Name,
				Input: parseJSONArguments(toolCall.Function.Arguments),
			})
		}
		stopReason = mapOpenAIStopReason(choice.FinishReason, len(choice.Message.ToolCalls) > 0)
	}
	if len(content) == 0 {
		content = append(content, AnthropicContentBlock{Type: "text", Text: ""})
	}

	return &AnthropicMessagesResponse{
		ID:           respID,
		Type:         "message",
		Role:         "assistant",
		Content:      content,
		Model:        chatResp.Model,
		StopReason:   stopReason,
		StopSequence: nil,
		Usage: AnthropicUsage{
			InputTokens:              chatResp.Usage.PromptTokens,
			OutputTokens:             chatResp.Usage.CompletionTokens,
			CacheReadInputTokens:     chatResp.Usage.CacheReadInputTokens,
			CacheCreationInputTokens: chatResp.Usage.CacheCreationInputTokens,
		},
	}
}

func parseJSONArguments(arguments string) interface{} {
	if arguments == "" {
		return map[string]interface{}{}
	}
	// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface -- Go JSON decoding does not instantiate arbitrary types; tool arguments need arbitrary JSON shape.
	var parsed interface{}
	if err := json.Unmarshal([]byte(arguments), &parsed); err == nil {
		return parsed
	}
	return map[string]interface{}{"arguments": arguments}
}

func mapOpenAIStopReason(finishReason string, hasToolCalls bool) string {
	if hasToolCalls || finishReason == "tool_calls" {
		return "tool_use"
	}
	switch finishReason {
	case "length":
		return "max_tokens"
	case "stop", "":
		return "end_turn"
	default:
		return finishReason
	}
}

func writeAnthropicMessagesStream(w http.ResponseWriter, resp *AnthropicMessagesResponse) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	startMessage := *resp
	startMessage.Content = []AnthropicContentBlock{}
	writeAnthropicSSEEvent(w, "message_start", map[string]interface{}{
		"type":    "message_start",
		"message": startMessage,
	})

	for i, block := range resp.Content {
		switch block.Type {
		case "tool_use":
			startBlock := AnthropicContentBlock{
				Type:  "tool_use",
				ID:    block.ID,
				Name:  block.Name,
				Input: map[string]interface{}{},
			}
			writeAnthropicSSEEvent(w, "content_block_start", map[string]interface{}{
				"type":          "content_block_start",
				"index":         i,
				"content_block": startBlock,
			})
			if inputJSON, err := json.Marshal(block.Input); err == nil && string(inputJSON) != "null" {
				writeAnthropicSSEEvent(w, "content_block_delta", map[string]interface{}{
					"type":  "content_block_delta",
					"index": i,
					"delta": map[string]interface{}{
						"type":         "input_json_delta",
						"partial_json": string(inputJSON),
					},
				})
			}
		default:
			writeAnthropicSSEEvent(w, "content_block_start", map[string]interface{}{
				"type":  "content_block_start",
				"index": i,
				"content_block": map[string]interface{}{
					"type": "text",
					"text": "",
				},
			})
			if block.Text != "" {
				writeAnthropicSSEEvent(w, "content_block_delta", map[string]interface{}{
					"type":  "content_block_delta",
					"index": i,
					"delta": map[string]interface{}{
						"type": "text_delta",
						"text": block.Text,
					},
				})
			}
		}
		writeAnthropicSSEEvent(w, "content_block_stop", map[string]interface{}{
			"type":  "content_block_stop",
			"index": i,
		})
	}

	writeAnthropicSSEEvent(w, "message_delta", map[string]interface{}{
		"type": "message_delta",
		"delta": map[string]interface{}{
			"stop_reason":   resp.StopReason,
			"stop_sequence": resp.StopSequence,
		},
		"usage": map[string]interface{}{
			"output_tokens": resp.Usage.OutputTokens,
		},
	})
	writeAnthropicSSEEvent(w, "message_stop", map[string]interface{}{
		"type": "message_stop",
	})

	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func writeAnthropicSSEEvent(w http.ResponseWriter, event string, payload interface{}) {
	data, _ := json.Marshal(payload)
	fmt.Fprintf(w, "event: %s\n", event)         // nosemgrep: go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter -- SSE event name is internally controlled.
	fmt.Fprintf(w, "data: %s\n\n", string(data)) // nosemgrep: go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter -- SSE payload is JSON marshaled.
}
