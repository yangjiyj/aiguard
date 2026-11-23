package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// sseMaxTokenBytes 是 SSE 单帧累积缓冲上限。长 JSON 单帧(含大 tool arguments)很容易超过
// bufio.Scanner 默认的 64KB, 故本实现一律用 bufio.Reader 逐行读 + 自定义分帧, 并对单行设较大上限。
const sseReaderBufBytes = 1 << 20 // 1MB 初始缓冲, bufio.Reader 会按需增长(ReadString 不受固定上限限制)
const maxNativeResponsesSSEBytes = 64 << 20

// streamingHTTPClient 构造一个用于流式中继/累积的 http.Client:
// 不设整请求级 client.Timeout —— 长流式响应(高推理大模型可能跑几分钟)靠数据持续流动保活,
// 总时长交给调用方传入的 ctx 截止时间控制。只在 transport 上设拨号/TLS/首字节(ResponseHeader)超时,
// 防"上游迟迟不回首字节"挂死。与 8082 已合入 main 的 streamingHTTPClientForResolvedEgress 同思路。
func streamingHTTPClient(proxyURL string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.TrimSpace(proxyURL) != "" {
		proxy, err := parseOutboundProxyURL(proxyURL)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	transport.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 60 * time.Second
	transport.IdleConnTimeout = 90 * time.Second
	return &http.Client{
		Transport: transport,
		Timeout:   0, // 流式: 不设整请求超时, 总时长交给 ctx
	}, nil
}

// forceStream 把请求 payload 强制改成 stream:true 并注入 stream_options.include_usage=true,
// 这样不依赖 handler 是否传对 stream 字段, 且保证末帧带 usage(否则计费/日志 token 全归零)。
func forceStream(payload []byte) ([]byte, error) {
	var m map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&m); err != nil {
		return nil, fmt.Errorf("force stream: unmarshal payload: %w", err)
	}
	m["stream"] = true
	// 保留调用方已有的 stream_options(如有), 但强制 include_usage=true
	opts, _ := m["stream_options"].(map[string]interface{})
	if opts == nil {
		opts = map[string]interface{}{}
	}
	opts["include_usage"] = true
	m["stream_options"] = opts
	return json.Marshal(m)
}

// sseEvent 是从 SSE 流里解析出来的一个事件(空行分隔)。
//   - data 是该事件所有 `data:` 行拼接后的负载(去掉 "data:" 前缀)。
//   - event 是 `event:` 行的值(Anthropic 用; OpenAI 一般没有)。
type sseEvent struct {
	event string
	data  string
}

// readSSEEvents 用 bufio.Reader 逐行读, 按空行分事件、拼接多个 data 行、跳过注释行(冒号开头)。
// 不使用 bufio.Scanner(默认 64KB 行上限, 长 JSON 单帧会 ErrTooLong)。
// 对每个完整事件调用 fn; fn 返回 (done, err): done=true 时停止读取(如遇到 [DONE]/message_stop)。
// 若流自然结束(EOF)但 fn 从未发出 done, 由调用方判定是否算"断流"。
func readSSEEvents(r io.Reader, fn func(ev sseEvent) (done bool, err error)) error {
	reader := relay.NewSSEReader(r, relay.SSELimits{MaxLineBytes: 1 << 20, MaxEventBytes: maxNativeResponsesSSEBytes})
	for {
		event, err := reader.Next()
		if err != nil {
			return err
		}
		done, err := fn(sseEvent{event: event.Event, data: event.Data})
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

// ---------------- OpenAI 累积器 ----------------

// openAIStreamAccumulator 把一系列 chat.completion.chunk 累积回一个等价的完整 chat.completion。
type openAIStreamAccumulator struct {
	id      string
	model   string
	object  string
	created int64

	choices map[int]*openAIChoiceAcc
	usage   json.RawMessage // 末帧 usage 原样保留(含 completion_tokens_details 等)

	sawFinish bool
	sawDone   bool
}

type openAIChoiceAcc struct {
	index            int
	role             string
	content          strings.Builder
	reasoningContent strings.Builder
	finishReason     string
	toolCalls        map[int]*openAIToolCallAcc
	toolCallOrder    []int
}

type openAIToolCallAcc struct {
	index      int
	id         string
	typ        string
	name       string
	argsBuf    strings.Builder
	isToolCall bool
}

// openAIStreamChunk 是上游 SSE 单帧的最小解析结构。
type openAIStreamChunk struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role             string  `json:"role"`
			Content          *string `json:"content"`
			ReasoningContent *string `json:"reasoning_content"`
			ToolCalls        []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage json.RawMessage `json:"usage"`
	Error json.RawMessage `json:"error"`
}

func (acc *openAIStreamAccumulator) choice(index int) *openAIChoiceAcc {
	if acc.choices == nil {
		acc.choices = map[int]*openAIChoiceAcc{}
	}
	c, ok := acc.choices[index]
	if !ok {
		c = &openAIChoiceAcc{index: index, toolCalls: map[int]*openAIToolCallAcc{}}
		acc.choices[index] = c
	}
	return c
}

// ingest 处理一个 data 负载。返回 error 表示流内嵌 error 事件(构造为 *UpstreamHTTPError)。
func (acc *openAIStreamAccumulator) ingest(data string) error {
	if strings.TrimSpace(data) == "[DONE]" {
		acc.sawDone = true
		return nil
	}
	var chunk openAIStreamChunk
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		// 非 JSON 的 data 行直接忽略(可能是 keep-alive 残留)
		return nil
	}
	// 200 + SSE 内嵌 error 事件 → 构造等价 *UpstreamHTTPError, 保 GetUpstreamHTTPError 分支。
	if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
		msg := extractErrorMessage(chunk.Error)
		return &UpstreamHTTPError{StatusCode: http.StatusBadGateway, Body: []byte(data), Message: msg}
	}

	if acc.id == "" && chunk.ID != "" {
		acc.id = chunk.ID
	}
	if acc.model == "" && chunk.Model != "" {
		acc.model = chunk.Model
	}
	if acc.object == "" && chunk.Object != "" {
		acc.object = chunk.Object
	}
	if acc.created == 0 && chunk.Created != 0 {
		acc.created = chunk.Created
	}
	if len(chunk.Usage) > 0 && string(chunk.Usage) != "null" {
		var previous, patch map[string]any
		beforeDecoder := json.NewDecoder(bytes.NewReader(acc.usage))
		beforeDecoder.UseNumber()
		_ = beforeDecoder.Decode(&previous)
		patchDecoder := json.NewDecoder(bytes.NewReader(chunk.Usage))
		patchDecoder.UseNumber()
		if patchDecoder.Decode(&patch) == nil && patch != nil {
			acc.usage, _ = json.Marshal(mergeStreamUsageObject(previous, patch))
		}
	}

	for _, ch := range chunk.Choices {
		c := acc.choice(ch.Index)
		if ch.Delta.Role != "" {
			c.role = ch.Delta.Role
		}
		if ch.Delta.Content != nil {
			c.content.WriteString(*ch.Delta.Content)
		}
		if ch.Delta.ReasoningContent != nil {
			c.reasoningContent.WriteString(*ch.Delta.ReasoningContent)
		}
		for _, tc := range ch.Delta.ToolCalls {
			t, ok := c.toolCalls[tc.Index]
			if !ok {
				t = &openAIToolCallAcc{index: tc.Index, isToolCall: true}
				c.toolCalls[tc.Index] = t
				c.toolCallOrder = append(c.toolCallOrder, tc.Index)
			}
			if tc.ID != "" {
				t.id = tc.ID
			}
			if tc.Type != "" {
				t.typ = tc.Type
			}
			if tc.Function.Name != "" {
				t.name = tc.Function.Name
			}
			if tc.Function.Arguments != "" {
				t.argsBuf.WriteString(tc.Function.Arguments)
			}
		}
		if ch.FinishReason != nil && *ch.FinishReason != "" {
			c.finishReason = *ch.FinishReason
			acc.sawFinish = true
		}
	}
	return nil
}

// finalize 把累积结果组装成等价的完整 chat.completion JSON(OpenAI 原生格式)。
func (acc *openAIStreamAccumulator) finalize() ([]byte, error) {
	out := map[string]interface{}{
		"id":      acc.id,
		"object":  "chat.completion",
		"created": acc.created,
		"model":   acc.model,
	}
	// 按 index 升序输出 choices
	maxIdx := -1
	for idx := range acc.choices {
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	choices := make([]interface{}, 0, len(acc.choices))
	for i := 0; i <= maxIdx; i++ {
		c, ok := acc.choices[i]
		if !ok {
			continue
		}
		msg := map[string]interface{}{
			"role": firstNonEmpty(c.role, "assistant"),
		}
		msg["content"] = c.content.String()
		if c.reasoningContent.Len() > 0 {
			msg["reasoning_content"] = c.reasoningContent.String()
		}
		if len(c.toolCallOrder) > 0 {
			tcs := make([]interface{}, 0, len(c.toolCallOrder))
			for _, ti := range c.toolCallOrder {
				t := c.toolCalls[ti]
				tcs = append(tcs, map[string]interface{}{
					"id":   t.id,
					"type": firstNonEmpty(t.typ, "function"),
					"function": map[string]interface{}{
						"name":      t.name,
						"arguments": t.argsBuf.String(),
					},
				})
			}
			msg["tool_calls"] = tcs
			// 有 tool_calls 时 content 为 null 更符合 OpenAI 语义
			if c.content.Len() == 0 {
				msg["content"] = nil
			}
		}
		choice := map[string]interface{}{
			"index":         c.index,
			"message":       msg,
			"finish_reason": firstNonEmpty(c.finishReason, "stop"),
		}
		choices = append(choices, choice)
	}
	out["choices"] = choices

	if len(acc.usage) > 0 {
		var usage interface{}
		if err := json.Unmarshal(acc.usage, &usage); err == nil {
			out["usage"] = usage
		}
	}
	return json.Marshal(out)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func extractErrorMessage(raw json.RawMessage) string {
	// error 可能是 {"message": "..."} 或 {"error": {"message": "..."}} 或字符串
	var asObj map[string]interface{}
	if json.Unmarshal(raw, &asObj) == nil {
		if m, ok := asObj["message"].(string); ok && m != "" {
			return m
		}
		if inner, ok := asObj["error"].(map[string]interface{}); ok {
			if m, ok := inner["message"].(string); ok && m != "" {
				return m
			}
		}
	}
	var asStr string
	if json.Unmarshal(raw, &asStr) == nil && asStr != "" {
		return asStr
	}
	return string(raw)
}

// accumulateOpenAISSE 从 resp.Body 读 OpenAI 兼容 SSE 流并累积成完整 chat.completion JSON。
// 必须在 200 状态码下调用。未见 finish_reason 且未见 [DONE] 就 EOF/断流 → 返回 error(不可把半截当完整)。
func accumulateOpenAISSE(body io.Reader) ([]byte, error) {
	return accumulateOpenAISSEWithFirstEvent(body, nil)
}

func accumulateOpenAISSEWithFirstEvent(body io.Reader, onFirstEvent func()) ([]byte, error) {
	acc := &openAIStreamAccumulator{}
	firstEventSeen := false
	var ingestErr error
	streamErr := readSSEEvents(body, func(ev sseEvent) (bool, error) {
		if err := acc.ingest(ev.data); err != nil {
			ingestErr = err
			return true, err // 内嵌 error: 立即停止
		}
		if !firstEventSeen && semanticOpenAIEvent(ev.data) {
			firstEventSeen = true
			if onFirstEvent != nil {
				onFirstEvent()
			}
		}
		if acc.sawDone {
			return true, nil
		}
		return false, nil
	})
	if ingestErr != nil {
		return nil, ingestErr
	}
	if streamErr != nil && streamErr != io.EOF {
		// 网络读错误等 → 视为断流
		return nil, fmt.Errorf("upstream stream read error: %w", streamErr)
	}
	// 未见结束标志 = 断流, 不能把半截当完整
	if !acc.sawDone && !acc.sawFinish {
		return nil, fmt.Errorf("upstream stream ended without finish_reason or [DONE] (truncated)")
	}
	return acc.finalize()
}

func semanticOpenAIEvent(data string) bool {
	var chunk openAIStreamChunk
	if json.Unmarshal([]byte(data), &chunk) != nil || len(chunk.Error) > 0 && string(chunk.Error) != "null" {
		return false
	}
	for _, choice := range chunk.Choices {
		if choice.Delta.Content != nil && *choice.Delta.Content != "" || choice.Delta.ReasoningContent != nil && *choice.Delta.ReasoningContent != "" {
			return true
		}
		for _, tool := range choice.Delta.ToolCalls {
			if tool.ID != "" || tool.Function.Name != "" || tool.Function.Arguments != "" {
				return true
			}
		}
	}
	return false
}

// CallStreaming(OpenAI) 向上游发 stream:true, 边收 SSE 边累积, 返回等价的完整 chat.completion JSON。
func (a *OpenAIAdapter) CallStreaming(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) ([]byte, error) {
	startedAt := time.Now()
	baseURL := a.BaseURL
	if baseURL == "" {
		baseURL = "https://api.openai.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	var endpoint string
	switch envelope.EndpointType {
	case "embeddings":
		// embeddings 不支持流式, 退回非流式 Call(累积无意义)
		return a.Call(ctx, envelope, payload)
	case "messages":
		if !usesMessagesOpenAIBridge(envelope) {
			return callNativeAnthropicMessages(ctx, envelope, payload, baseURL, a.APIKey, a.ProxyURL, "bearer", true, a.StreamIdleTimeout)
		}
		var err error
		endpoint, err = a.endpointForEnvelope(baseURL, envelope)
		if err != nil {
			return nil, err
		}
	default:
		var err error
		endpoint, err = a.endpointForEnvelope(baseURL, envelope)
		if err != nil {
			return nil, err
		}
	}

	if usesOpenAIResponsesBridge(envelope) {
		log.Printf("[responses.bridge] endpoint=/responses model=%s", strings.TrimSpace(envelope.UpstreamModelID))
	}
	var streamPayload []byte
	var err error
	if envelope.EndpointType == "responses" || usesOpenAIResponsesBridge(envelope) {
		streamPayload, err = forceResponsesStream(payload)
	} else {
		streamPayload, err = forceStream(payload)
	}
	if err != nil {
		return nil, err
	}

	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(attemptCtx, "POST", endpoint, bytes.NewReader(streamPayload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if a.APIKey == "" {
		return nil, fmt.Errorf("openai provider is not configured with an API key")
	}
	if err := a.setAuthentication(req); err != nil {
		return nil, err
	}
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

	// 非 2xx: 上游首包就是错误(非 SSE body) → 走 readResponseBody 风格产出 *UpstreamHTTPError。
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readResponseBody(resp)
	}

	if envelope.EndpointType == "responses" || usesOpenAIResponsesBridge(envelope) {
		raw, readErr := readNativeResponsesSSE(resp.Body, func() { recordUpstreamTTFT(envelope, startedAt) })
		if readErr != nil {
			return nil, readErr
		}
		if terminalErr := validateNativeResponsesSSETerminal(raw); terminalErr != nil {
			return nil, terminalErr
		}
		if usesOpenAIResponsesBridge(envelope) {
			return responsesBridgeStreamToJSON(raw)
		}
		return raw, nil
	}

	return accumulateOpenAISSEWithFirstEvent(resp.Body, func() { recordUpstreamTTFT(envelope, startedAt) })
}

func forceResponsesStream(payload []byte) ([]byte, error) {
	var rawFields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &rawFields); err != nil {
		return nil, fmt.Errorf("force Responses stream: unmarshal payload: %w", err)
	}
	if streamRaw, ok := rawFields["stream"]; ok && strings.TrimSpace(string(streamRaw)) == "true" {
		return append([]byte(nil), payload...), nil
	}
	var body map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		return nil, fmt.Errorf("force Responses stream: unmarshal payload: %w", err)
	}
	body["stream"] = true
	return json.Marshal(body)
}

func readNativeResponsesSSE(r io.Reader, onFirstBytes func()) ([]byte, error) {
	limited := &io.LimitedReader{R: r, N: maxNativeResponsesSSEBytes + 1}
	var out bytes.Buffer
	buf := make([]byte, 32*1024)
	recordedFirstBytes := false
	for {
		n, err := limited.Read(buf)
		if n > 0 {
			if !recordedFirstBytes {
				recordedFirstBytes = true
				if onFirstBytes != nil {
					onFirstBytes()
				}
			}
			_, _ = out.Write(buf[:n])
			if out.Len() > maxNativeResponsesSSEBytes {
				return nil, fmt.Errorf("native Responses SSE exceeds %d bytes", maxNativeResponsesSSEBytes)
			}
		}
		if err != nil {
			if err == io.EOF {
				return out.Bytes(), nil
			}
			return nil, err
		}
	}
}
func validateNativeResponsesSSETerminal(raw []byte) error {
	normalized := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, block := range strings.Split(normalized, "\n\n") {
		var dataLines []string
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "data:") {
				dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			}
		}
		if len(dataLines) == 0 {
			continue
		}
		data := strings.Join(dataLines, "\n")
		var event struct {
			Type     string `json:"type"`
			Response struct {
				Error json.RawMessage `json:"error"`
			} `json:"response"`
		}
		if json.Unmarshal([]byte(data), &event) != nil {
			continue
		}
		switch event.Type {
		case "response.completed", "response.done", "response.incomplete":
			return nil
		case "response.failed", "response.error":
			message := "native Responses upstream failed"
			if len(event.Response.Error) > 0 && string(event.Response.Error) != "null" {
				if extracted := extractErrorMessage(event.Response.Error); extracted != "" {
					message = extracted
				}
			}
			log.Printf("[responses.bridge.error] message=%q", boundedResponsesBridgeErrorMessage(message))
			return &UpstreamHTTPError{StatusCode: http.StatusBadGateway, Body: []byte(data), Message: message}
		}
	}
	return fmt.Errorf("native Responses SSE ended without a terminal event")
}

// ---------------- Anthropic 累积器 ----------------
func boundedResponsesBridgeErrorMessage(message string) string {
	message = strings.TrimSpace(message)
	message = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(message)
	const maxRunes = 512
	runes := []rune(message)
	if len(runes) <= maxRunes {
		return message
	}
	return string(runes[:maxRunes]) + "..."
}

//
// Anthropic 的 Messages SSE 与 OpenAI 不同构: 每个事件是 "event: <type>\n" + "data: {json}\n"。
// 事件类型按顺序大致是:
//   message_start          → message.id / message.model / message.usage.input_tokens
//   content_block_start    → 在 index 处新建一个 block(text / tool_use / thinking)
//   content_block_delta    → text_delta(拼 text) / input_json_delta(按 index 续接 tool_use 的 partial_json)
//                            / thinking_delta(拼 thinking)
//   content_block_stop     → 该 block 结束
//   message_delta          → usage.output_tokens / stop_reason
//   message_stop           → 整条消息结束
// 累积器内部只把流重组回一段"等价的完整 Anthropic message JSON"(content[] + usage + stop_reason),
// 不在这里转 OpenAI —— 交给下游既有的 AnthropicAdapter.TransformResponse 转(评审契约 §1.3)。

// anthropicBlockAcc 累积单个 content block(按 SSE 的 index 归并)。
type anthropicBlockAcc struct {
	index       int
	typ         string          // "text" / "tool_use" / "thinking" / "redacted_thinking" 等
	text        strings.Builder // text_delta 累积
	thinking    strings.Builder // thinking_delta 累积
	partialJSON strings.Builder // input_json_delta 累积(tool_use 的 input)
	toolID      string          // tool_use 的 id
	toolName    string          // tool_use 的 name
	signature   string          // thinking 的 signature(如有)
}

// anthropicStreamAccumulator 把 Anthropic SSE 重组回完整 message JSON。
type anthropicStreamAccumulator struct {
	id               string
	model            string
	role             string
	stopReason       json.RawMessage // 末尾 message_delta 给出, 保留原值(可能是 null)
	inputTok         *int64
	cacheReadTok     *int64
	cacheCreationTok *int64
	outputTok        *int64

	blocks     map[int]*anthropicBlockAcc
	blockOrder []int
	sawStart   bool
	sawStop    bool
}

func (acc *anthropicStreamAccumulator) block(index int) *anthropicBlockAcc {
	if acc.blocks == nil {
		acc.blocks = map[int]*anthropicBlockAcc{}
	}
	b, ok := acc.blocks[index]
	if !ok {
		b = &anthropicBlockAcc{index: index}
		acc.blocks[index] = b
		acc.blockOrder = append(acc.blockOrder, index)
	}
	return b
}

// anthropicSSEEvent 是 Anthropic SSE data 负载的最小解析结构(各事件类型字段交集)。
type anthropicSSEEvent struct {
	Type    string `json:"type"`
	Message *struct {
		ID    string `json:"id"`
		Model string `json:"model"`
		Role  string `json:"role"`
		Usage *struct {
			InputTokens              *int64 `json:"input_tokens"`
			CacheReadInputTokens     *int64 `json:"cache_read_input_tokens"`
			CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
			OutputTokens             *int64 `json:"output_tokens"`
		} `json:"usage"`
	} `json:"message"`
	Index        *int `json:"index"`
	ContentBlock *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"content_block"`
	Delta *struct {
		Type        string          `json:"type"` // text_delta / input_json_delta / thinking_delta / signature_delta
		Text        string          `json:"text"`
		PartialJSON string          `json:"partial_json"`
		Thinking    string          `json:"thinking"`
		Signature   string          `json:"signature"`
		StopReason  json.RawMessage `json:"stop_reason"` // 在 message_delta 的 delta 内
	} `json:"delta"`
	Usage *struct {
		InputTokens              *int64 `json:"input_tokens"`
		CacheReadInputTokens     *int64 `json:"cache_read_input_tokens"`
		CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
		OutputTokens             *int64 `json:"output_tokens"`
	} `json:"usage"` // message_delta 顶层 usage(累计 output_tokens)
	Error json.RawMessage `json:"error"`
}

// ingest 处理一个 Anthropic SSE data 负载。返回 error 表示流内嵌 error 事件。
func (acc *anthropicStreamAccumulator) ingest(data string) error {
	if strings.TrimSpace(data) == "" {
		return nil
	}
	var ev anthropicSSEEvent
	if err := json.Unmarshal([]byte(data), &ev); err != nil {
		// 非 JSON 的 data 行忽略(keep-alive 残留等)
		return nil
	}

	// error 事件 → 构造等价 *UpstreamHTTPError, 保 GetUpstreamHTTPError 分支语义。
	if ev.Type == "error" || (len(ev.Error) > 0 && string(ev.Error) != "null") {
		msg := extractErrorMessage(ev.Error)
		return &UpstreamHTTPError{StatusCode: http.StatusBadGateway, Body: []byte(data), Message: msg}
	}

	switch ev.Type {
	case "message_start":
		acc.sawStart = true
		if ev.Message != nil {
			if acc.id == "" {
				acc.id = ev.Message.ID
			}
			if acc.model == "" {
				acc.model = ev.Message.Model
			}
			if acc.role == "" {
				acc.role = ev.Message.Role
			}
			if ev.Message.Usage != nil {
				if ev.Message.Usage.InputTokens != nil {
					acc.inputTok = ev.Message.Usage.InputTokens
				}
				if ev.Message.Usage.CacheReadInputTokens != nil {
					acc.cacheReadTok = ev.Message.Usage.CacheReadInputTokens
				}
				if ev.Message.Usage.CacheCreationInputTokens != nil {
					acc.cacheCreationTok = ev.Message.Usage.CacheCreationInputTokens
				}
				if ev.Message.Usage.OutputTokens != nil {
					acc.outputTok = ev.Message.Usage.OutputTokens
				}
			}
		}
	case "content_block_start":
		if ev.Index != nil && ev.ContentBlock != nil {
			b := acc.block(*ev.Index)
			b.typ = ev.ContentBlock.Type
			if ev.ContentBlock.ID != "" {
				b.toolID = ev.ContentBlock.ID
			}
			if ev.ContentBlock.Name != "" {
				b.toolName = ev.ContentBlock.Name
			}
		}
	case "content_block_delta":
		if ev.Index != nil && ev.Delta != nil {
			b := acc.block(*ev.Index)
			switch ev.Delta.Type {
			case "text_delta":
				b.text.WriteString(ev.Delta.Text)
				if b.typ == "" {
					b.typ = "text"
				}
			case "input_json_delta":
				b.partialJSON.WriteString(ev.Delta.PartialJSON)
				if b.typ == "" {
					b.typ = "tool_use"
				}
			case "thinking_delta":
				b.thinking.WriteString(ev.Delta.Thinking)
				if b.typ == "" {
					b.typ = "thinking"
				}
			case "signature_delta":
				b.signature += ev.Delta.Signature
			}
		}
	case "content_block_stop":
		// 无需处理: block 已在 start/delta 建好
	case "message_delta":
		if ev.Delta != nil && len(ev.Delta.StopReason) > 0 && string(ev.Delta.StopReason) != "null" {
			acc.stopReason = ev.Delta.StopReason
		}
		if ev.Usage != nil {
			if ev.Usage.InputTokens != nil {
				acc.inputTok = ev.Usage.InputTokens
			}
			if ev.Usage.CacheReadInputTokens != nil {
				acc.cacheReadTok = ev.Usage.CacheReadInputTokens
			}
			if ev.Usage.CacheCreationInputTokens != nil {
				acc.cacheCreationTok = ev.Usage.CacheCreationInputTokens
			}
			if ev.Usage.OutputTokens != nil {
				acc.outputTok = ev.Usage.OutputTokens
			}
		}
	case "message_stop":
		acc.sawStop = true
	case "ping":
		// keep-alive, 忽略
	}
	return nil
}

// finalize 把累积结果组装成等价的完整 Anthropic message JSON(上游原生格式)。
func (acc *anthropicStreamAccumulator) finalize() ([]byte, error) {
	out := map[string]interface{}{
		"id":    acc.id,
		"type":  "message",
		"role":  firstNonEmpty(acc.role, "assistant"),
		"model": acc.model,
	}

	// 按 index 升序输出 content blocks
	indices := make([]int, 0, len(acc.blocks))
	for idx := range acc.blocks {
		indices = append(indices, idx)
	}
	sortInts(indices)
	content := make([]interface{}, 0, len(indices))
	for _, idx := range indices {
		b := acc.blocks[idx]
		switch b.typ {
		case "tool_use":
			var input interface{}
			raw := b.partialJSON.String()
			if strings.TrimSpace(raw) == "" {
				input = map[string]interface{}{}
			} else if err := json.Unmarshal([]byte(raw), &input); err != nil {
				// partial_json 拼出来不是合法 JSON: 退回空对象, 避免下游解析失败
				input = map[string]interface{}{}
			}
			content = append(content, map[string]interface{}{
				"type":  "tool_use",
				"id":    b.toolID,
				"name":  b.toolName,
				"input": input,
			})
		case "thinking":
			blk := map[string]interface{}{
				"type":     "thinking",
				"thinking": b.thinking.String(),
			}
			if b.signature != "" {
				blk["signature"] = b.signature
			}
			content = append(content, blk)
		case "redacted_thinking":
			content = append(content, map[string]interface{}{
				"type": "redacted_thinking",
				"data": b.text.String(),
			})
		default: // text
			content = append(content, map[string]interface{}{
				"type": "text",
				"text": b.text.String(),
			})
		}
	}
	out["content"] = content

	if len(acc.stopReason) > 0 {
		var sr interface{}
		if err := json.Unmarshal(acc.stopReason, &sr); err == nil {
			out["stop_reason"] = sr
		}
	}

	usage := map[string]interface{}{}
	if acc.inputTok != nil {
		usage["input_tokens"] = *acc.inputTok
	}
	if acc.cacheReadTok != nil {
		usage["cache_read_input_tokens"] = *acc.cacheReadTok
	}
	if acc.cacheCreationTok != nil {
		usage["cache_creation_input_tokens"] = *acc.cacheCreationTok
	}
	if acc.outputTok != nil {
		usage["output_tokens"] = *acc.outputTok
	}
	if len(usage) > 0 {
		out["usage"] = usage
	}

	return json.Marshal(out)
}

// sortInts 升序排序小切片(插入排序, 避免为单点引入额外依赖)。
func sortInts(s []int) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// accumulateAnthropicSSE 从 resp.Body 读 Anthropic Messages SSE 流并重组成完整 Anthropic message JSON。
// 必须在 200 状态码下调用。未见 message_stop 即 EOF/断流 → 返回 error(不可把半截当完整)。
func accumulateAnthropicSSE(body io.Reader) ([]byte, error) {
	return accumulateAnthropicSSEWithFirstEvent(body, nil)
}

func accumulateAnthropicSSEWithFirstEvent(body io.Reader, onFirstEvent func()) ([]byte, error) {
	acc := &anthropicStreamAccumulator{}
	firstEventSeen := false
	var ingestErr error
	streamErr := readSSEEvents(body, func(ev sseEvent) (bool, error) {
		if err := acc.ingest(ev.data); err != nil {
			ingestErr = err
			return true, err
		}
		if !firstEventSeen && semanticAnthropicEvent(ev.data) {
			firstEventSeen = true
			if onFirstEvent != nil {
				onFirstEvent()
			}
		}
		if acc.sawStop {
			return true, nil
		}
		return false, nil
	})
	if ingestErr != nil {
		return nil, ingestErr
	}
	if streamErr != nil && streamErr != io.EOF {
		return nil, fmt.Errorf("upstream anthropic stream read error: %w", streamErr)
	}
	// 未见 message_stop = 断流, 不能把半截当完整
	if !acc.sawStop {
		return nil, fmt.Errorf("upstream anthropic stream ended without message_stop (truncated): %w", io.ErrUnexpectedEOF)
	}
	return acc.finalize()
}

func semanticAnthropicEvent(data string) bool {
	var event anthropicSSEEvent
	if json.Unmarshal([]byte(data), &event) != nil || event.Type != "content_block_delta" || event.Delta == nil {
		return false
	}
	return event.Delta.Text != "" || event.Delta.PartialJSON != "" || event.Delta.Thinking != "" || event.Delta.Signature != ""
}

func (a *AnthropicAdapter) OpenStream(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) (relay.StreamReader, StreamResponseMeta, error) {
	if envelope == nil {
		return nil, StreamResponseMeta{}, fmt.Errorf("stream envelope is required")
	}
	if envelope.EndpointType != "chat" && envelope.EndpointType != "messages" {
		return nil, StreamResponseMeta{}, fmt.Errorf("%w: endpoint %s", ErrEndpointNotSupported, envelope.EndpointType)
	}
	baseURL := strings.TrimRight(a.BaseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}
	reader, meta, err := openNativeAnthropicMessagesStream(ctx, envelope, payload, baseURL, a.APIKey, a.ProxyURL, "x-api-key", a.StreamIdleTimeout)
	if streamReader, ok := reader.(*nativeAnthropicStreamReader); ok {
		streamReader.toolNames = a.toolNames
	}
	return reader, meta, err
}

// CallStreaming(Anthropic) 向上游发 stream:true + Accept: text/event-stream, 边收 SSE 边累积,
// 返回与 Call 等价的、上游原生 Anthropic message JSON(content[] + usage + stop_reason)。
// 下游 AnthropicAdapter.TransformResponse 照旧把它转成 OpenAI(评审契约: 不在累积器里转格式)。
func (a *AnthropicAdapter) CallStreaming(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) ([]byte, error) {
	startedAt := time.Now()
	authMode, err := a.authenticationMode()
	if err != nil {
		return nil, err
	}
	if envelope.EndpointType == "messages" {
		baseURL := a.BaseURL
		if baseURL == "" {
			baseURL = "https://api.anthropic.com"
		}
		return callNativeAnthropicMessages(ctx, envelope, payload, baseURL, a.APIKey, a.ProxyURL, authMode, true, a.StreamIdleTimeout)
	}
	// Anthropic 只支持 chat(messages API), 非 chat 走非流式 Call。
	if envelope.EndpointType != "chat" {
		return a.Call(ctx, envelope, payload)
	}

	baseURL := a.BaseURL
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	endpoint := baseURL + "/v1/messages"
	if strings.HasSuffix(baseURL, "/v1") {
		endpoint = baseURL + "/messages"
	}

	// payload 已是 TransformRequest 产物(Anthropic 格式), 强制加 stream:true。
	streamPayload, err := forceAnthropicStream(payload)
	if err != nil {
		return nil, err
	}

	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(attemptCtx, "POST", endpoint, bytes.NewReader(streamPayload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("anthropic-version", "2023-06-01")
	if a.APIKey == "" {
		return nil, fmt.Errorf("anthropic provider is not configured with an API key")
	}
	if authMode == "bearer" {
		req.Header.Set("Authorization", "Bearer "+a.APIKey)
	} else {
		req.Header.Set("x-api-key", a.APIKey)
	}
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

	// 非 2xx: 上游首包就是错误(非 SSE body) → *UpstreamHTTPError。
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readResponseBody(resp)
	}

	return accumulateAnthropicSSEWithFirstEvent(resp.Body, func() { recordUpstreamTTFT(envelope, startedAt) })
}

func recordUpstreamTTFT(envelope *modelrouter.RequestEnvelope, startedAt time.Time) {
	if envelope == nil || envelope.UpstreamTTFTMs != nil {
		return
	}
	elapsed := time.Since(startedAt).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	envelope.UpstreamTTFTMs = &elapsed
}

// forceAnthropicStream 把 Anthropic 请求 payload 强制改成 stream:true。
// Anthropic 流式 usage 由 message_start(input)/message_delta(output) 给出, 无需 stream_options。
func forceAnthropicStream(payload []byte) ([]byte, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, fmt.Errorf("force anthropic stream: unmarshal payload: %w", err)
	}
	m["stream"] = true
	return json.Marshal(m)
}
