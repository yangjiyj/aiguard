package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

type StreamResponseMeta struct {
	StatusCode int
	Header     http.Header
}

// StreamAdapter is optional so existing non-streaming test doubles and
// provider implementations remain source-compatible while the data plane
// migrates to event reads.
type StreamAdapter interface {
	OpenStream(context.Context, *modelrouter.RequestEnvelope, []byte) (relay.StreamReader, StreamResponseMeta, error)
}

func (a *OpenAIAdapter) OpenStream(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload []byte) (relay.StreamReader, StreamResponseMeta, error) {
	if envelope == nil {
		return nil, StreamResponseMeta{}, fmt.Errorf("stream envelope is required")
	}
	if usesMessagesOpenAIBridge(envelope) {
		envelope = chatBridgeEnvelope(envelope)
	}
	if envelope.EndpointType == "messages" {
		baseURL := strings.TrimRight(a.BaseURL, "/")
		if baseURL == "" {
			baseURL = "https://api.openai.com"
		}
		return openNativeAnthropicMessagesStream(ctx, envelope, payload, baseURL, a.APIKey, a.ProxyURL, "bearer", a.StreamIdleTimeout)
	}
	if envelope.EndpointType == "embeddings" {
		return nil, StreamResponseMeta{}, fmt.Errorf("%w: endpoint %s", ErrEndpointNotSupported, envelope.EndpointType)
	}
	baseURL := strings.TrimRight(a.BaseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.openai.com"
	}
	endpoint, err := a.endpointForEnvelope(baseURL, envelope)
	if err != nil {
		return nil, StreamResponseMeta{}, err
	}
	responses := envelope.EndpointType == "responses" || usesChatResponsesBridge(envelope)
	var streamPayload []byte
	if responses {
		streamPayload, err = forceResponsesStream(payload)
	} else {
		streamPayload, err = forceStream(payload)
	}
	if err != nil {
		return nil, StreamResponseMeta{}, err
	}
	attemptCtx, cancel := context.WithCancel(ctx)
	cancelOnReturn := true
	defer func() {
		if cancelOnReturn {
			cancel()
		}
	}()
	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, endpoint, bytes.NewReader(streamPayload))
	if err != nil {
		return nil, StreamResponseMeta{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if err := a.setAuthentication(req); err != nil {
		return nil, StreamResponseMeta{}, err
	}
	setVerifiedIdempotencyHeader(req, envelope)
	client, err := streamingHTTPClient(a.ProxyURL)
	if err != nil {
		return nil, StreamResponseMeta{}, fmt.Errorf("invalid configured outbound proxy: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, StreamResponseMeta{}, err
	}
	meta := StreamResponseMeta{StatusCode: resp.StatusCode, Header: resp.Header.Clone()}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, readErr := readResponseBody(resp)
		_ = resp.Body.Close()
		return nil, meta, readErr
	}
	resp.Body = newByteIdleReadCloser(resp.Body, a.StreamIdleTimeout, cancel)
	cancelOnReturn = false
	return &httpStreamReader{
		body:      resp.Body,
		events:    relay.NewSSEReader(resp.Body, relay.SSELimits{MaxLineBytes: 1 << 20, MaxEventBytes: 64 << 20}),
		responses: responses,
		pending:   make([]relay.StreamEvent, 0, 2),
		toolNames: a.toolNames,
		envelope:  envelope,
		startedAt: time.Now(),
	}, meta, nil
}

type httpStreamReader struct {
	body              io.ReadCloser
	events            *relay.SSEReader
	responses         bool
	responseText      strings.Builder
	responseBytes     int
	responseArguments map[string]*strings.Builder
	responseTools     map[string]bool
	responseItemIDs   map[string]string
	pending           []relay.StreamEvent
	sawTerminal       bool
	// heldTerminal 是 OpenAI Chat 流里 finish_reason 产生的结束事件。官方顺序是
	// finish_reason 块 → include_usage 的 usage 块（choices 为空）→ [DONE]，
	// 所以读到 finish_reason 时先压住结束事件，继续读到 usage 块 / [DONE] / 连接关闭，
	// 再把 usage 放在结束事件之前交出去；否则权威 usage 会被丢掉。
	usageSnapshot map[string]any
	heldTerminal  []relay.StreamEvent
	closeOnce     sync.Once
	toolNames     *compatibleToolNameMap
	envelope      *modelrouter.RequestEnvelope
	startedAt     time.Time
}

func (r *httpStreamReader) Next(ctx context.Context) (relay.StreamEvent, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return relay.StreamEvent{}, ctx.Err()
		default:
		}
	}
	if len(r.pending) > 0 {
		event := r.pending[0]
		r.pending = r.pending[1:]
		return event, nil
	}
	if r.sawTerminal {
		return relay.StreamEvent{}, io.EOF
	}
	sseEvent, err := r.events.Next()
	if err != nil {
		if len(r.heldTerminal) > 0 {
			// finish_reason 之后连接关闭（没有 usage 块也没有 [DONE]）：照常结束。
			return r.releaseHeldTerminal(), nil
		}
		if errors.Is(err, io.EOF) {
			return relay.StreamEvent{}, fmt.Errorf("upstream stream ended before terminal event")
		}
		return relay.StreamEvent{}, err
	}
	if r.responses {
		event, err := relay.ResponsesSSEToEvent(sseEvent)
		if err != nil {
			return relay.StreamEvent{}, err
		}
		if event.Type == relay.EventMessageEnd {
			r.sawTerminal = true
		}
		if usesChatResponsesBridge(r.envelope) {
			events, bridgeErr := r.responsesBridgeEvents(event, sseEvent.Data)
			if bridgeErr != nil {
				return relay.StreamEvent{}, bridgeErr
			}
			if len(events) > 1 {
				r.pending = append(r.pending, events[1:]...)
			}
			event = events[0]
		}
		if event.Type == relay.EventMessageEnd {
			r.sawTerminal = true
		}
		restoreStreamToolName(&event, r.toolNames)
		recordStreamTTFT(r.envelope, r.startedAt, event)
		return event, nil
	}
	done := strings.TrimSpace(sseEvent.Data) == "[DONE]"
	if done && len(r.heldTerminal) > 0 {
		return r.releaseHeldTerminal(), nil
	}
	// Retain field presence before normalization; partial usage must not clear input/cache.
	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(sseEvent.Data))
	decoder.UseNumber()
	if decoder.Decode(&document) == nil {
		if patch, ok := document["usage"].(map[string]any); ok {
			r.usageSnapshot = mergeStreamUsageObject(r.usageSnapshot, patch)
			document["usage"] = r.usageSnapshot
			raw, _ := json.Marshal(document)
			sseEvent.Data = string(raw)
		}
	}
	events, err := openAIChatSSEToEvents(sseEvent)
	if err != nil {
		return relay.StreamEvent{}, err
	}
	out := make([]relay.StreamEvent, 0, len(events))
	for _, event := range events {
		restoreStreamToolName(&event, r.toolNames)
		recordStreamTTFT(r.envelope, r.startedAt, event)
		if event.Type == relay.EventMessageEnd {
			if done {
				r.sawTerminal = true
				out = append(out, event)
				continue
			}
			r.heldTerminal = append(r.heldTerminal, event)
			continue
		}
		out = append(out, event)
	}

	if len(out) == 0 {
		return r.Next(ctx)
	}
	r.pending = append(r.pending, out[1:]...)
	return out[0], nil
}

// releaseHeldTerminal 交出第一个压住的结束事件，其余（多 choice 时）排进 pending。
func (r *httpStreamReader) releaseHeldTerminal() relay.StreamEvent {
	held := r.heldTerminal
	r.heldTerminal = nil
	r.sawTerminal = true
	r.pending = append(r.pending, held[1:]...)
	return held[0]
}

func restoreStreamToolName(event *relay.StreamEvent, nameMap *compatibleToolNameMap) {
	if event == nil || event.ToolCall == nil || nameMap == nil {
		return
	}
	event.ToolCall.Name = nameMap.original(event.ToolCall.Name)
}

func recordStreamTTFT(envelope *modelrouter.RequestEnvelope, startedAt time.Time, event relay.StreamEvent) {
	switch event.Type {
	case relay.EventTextDelta, relay.EventReasoningDelta, relay.EventToolCallStart,
		relay.EventToolArgumentsDelta, relay.EventToolArgumentsDone:
		recordUpstreamTTFT(envelope, startedAt)
	}
}

func (r *httpStreamReader) Close() error {
	var err error
	r.closeOnce.Do(func() { err = r.body.Close() })
	return err
}

func openAIChatSSEToEvents(input relay.SSEEvent) ([]relay.StreamEvent, error) {
	if strings.TrimSpace(input.Data) == "[DONE]" {
		return []relay.StreamEvent{{Type: relay.EventMessageEnd, FinishReason: "stop"}}, nil
	}
	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(input.Data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode OpenAI Chat SSE event: %w", err)
	}
	id, _ := document["id"].(string)
	model, _ := document["model"].(string)
	events := make([]relay.StreamEvent, 0, 2)
	choices, _ := document["choices"].([]any)
	for _, rawChoice := range choices {
		choice, _ := rawChoice.(map[string]any)
		index := int64Value(choice, "index")
		delta, _ := choice["delta"].(map[string]any)
		if role, _ := delta["role"].(string); role != "" {
			events = append(events, relay.StreamEvent{Type: relay.EventMessageStart, ID: id, Model: model, Index: int(index)})
		}
		if content, ok := delta["content"].(string); ok && content != "" {
			events = append(events, relay.StreamEvent{Type: relay.EventTextDelta, ID: id, Model: model, Index: int(index), Delta: content})
		}
		if reasoning, ok := delta["reasoning_content"].(string); ok && reasoning != "" {
			events = append(events, relay.StreamEvent{Type: relay.EventReasoningDelta, ID: id, Model: model, Index: int(index), Delta: reasoning})
		}
		toolCalls, _ := delta["tool_calls"].([]any)
		for _, rawTool := range toolCalls {
			tool, _ := rawTool.(map[string]any)
			function, _ := tool["function"].(map[string]any)
			call := &relay.ToolCall{ID: stringValue(tool, "id"), Name: stringValue(function, "name"), Arguments: stringValue(function, "arguments"), Index: int(int64Value(tool, "index"))}
			if call.ID != "" || call.Name != "" {
				startCall := *call
				startCall.Arguments = ""
				events = append(events, relay.StreamEvent{Type: relay.EventToolCallStart, ID: id, Model: model, Index: int(index), ToolCall: &startCall})
			}
			if call.Arguments != "" {
				events = append(events, relay.StreamEvent{Type: relay.EventToolArgumentsDelta, ID: id, Model: model, Index: int(index), ToolCall: call, Delta: call.Arguments})
			}
		}
		if finish, ok := choice["finish_reason"].(string); ok && finish != "" {
			events = append(events, relay.StreamEvent{Type: relay.EventMessageEnd, ID: id, Model: model, Index: int(index), FinishReason: finish})
		}
	}
	if rawUsage, ok := document["usage"].(map[string]any); ok {
		events = append(events, relay.StreamEvent{Type: relay.EventUsageFinal, ID: id, Model: model, Usage: openAIStreamUsage(rawUsage)})
	}
	return events, nil
}

func mergeStreamUsageObject(current, patch map[string]any) map[string]any {
	next := make(map[string]any, len(current)+len(patch))
	for key, value := range current {
		next[key] = value
	}
	if _, present := patch["total_tokens"]; !present {
		for _, key := range []string{"prompt_tokens", "input_tokens", "completion_tokens", "output_tokens"} {
			if value, ok := patch[key]; ok && value != nil {
				delete(next, "total_tokens")
				break
			}
		}
	}
	for key, value := range patch {
		if value == nil {
			continue
		}
		if strings.HasSuffix(key, "_details") {
			if fields, ok := value.(map[string]any); ok {
				merged := map[string]any{}
				if old, ok := next[key].(map[string]any); ok {
					for k, v := range old {
						merged[k] = v
					}
				}
				for k, v := range fields {
					if v != nil {
						merged[k] = v
					}
				}
				next[key] = merged
				continue
			}
		}
		next[key] = value
	}
	return next
}

func openAIStreamUsage(raw map[string]any) *relay.Usage {
	if raw == nil {
		return nil
	}
	inputTokens := maxPositiveStreamInt64(int64Value(raw, "prompt_tokens"), int64Value(raw, "input_tokens"))
	cacheReadTokens := maxPositiveStreamInt64(
		int64Value(raw, "cache_read_input_tokens"),
		int64Value(raw, "cached_tokens"),
		int64Value(raw, "input_cached_tokens"),
		int64Value(raw, "prompt_cache_hit_tokens"),
	)
	cacheMissTokens := maxPositiveStreamInt64(int64Value(raw, "prompt_cache_miss_tokens"))
	_, promptPresent := raw["prompt_tokens"]
	_, inputPresent := raw["input_tokens"]
	if inputTokens == 0 && !promptPresent && !inputPresent {
		inputTokens = cacheReadTokens + cacheMissTokens
	}
	usage := &relay.Usage{
		InputTokens:          inputTokens,
		OutputTokens:         maxPositiveStreamInt64(int64Value(raw, "completion_tokens"), int64Value(raw, "output_tokens")),
		CacheReadInputTokens: cacheReadTokens,
		CacheCreationInputTokens: maxPositiveStreamInt64(
			int64Value(raw, "cache_creation_input_tokens"),
		),
		CacheMissInputTokens: cacheMissTokens,
	}
	for _, key := range []string{"prompt_tokens_details", "input_tokens_details"} {
		if details, ok := raw[key].(map[string]any); ok {
			usage.CacheReadInputTokens = maxPositiveStreamInt64(usage.CacheReadInputTokens, int64Value(details, "cached_tokens"), int64Value(details, "cache_read_tokens"))
			usage.CacheCreationInputTokens = maxPositiveStreamInt64(usage.CacheCreationInputTokens,
				int64Value(details, "cache_creation_input_tokens"), int64Value(details, "cache_creation_tokens"), int64Value(details, "cached_creation_tokens"), int64Value(details, "cache_write_tokens"))
		}
	}
	for _, key := range []string{"completion_tokens_details", "output_tokens_details"} {
		if details, ok := raw[key].(map[string]any); ok {
			usage.ReasoningTokens = maxPositiveStreamInt64(usage.ReasoningTokens, int64Value(details, "reasoning_tokens"))
		}
	}

	if usage.CacheReadInputTokens > usage.InputTokens {
		usage.CacheReadInputTokens = usage.InputTokens
	}
	if remaining := usage.InputTokens - usage.CacheReadInputTokens; usage.CacheCreationInputTokens > remaining {
		usage.CacheCreationInputTokens = remaining
	}
	if usage.ReasoningTokens > usage.OutputTokens {
		usage.ReasoningTokens = usage.OutputTokens
	}
	return usage
}

func maxPositiveStreamInt64(values ...int64) int64 {
	var result int64
	for _, value := range values {
		if value > result {
			result = value
		}
	}
	return result
}

func stringValue(document map[string]any, key string) string {
	if document == nil {
		return ""
	}
	value, _ := document[key].(string)
	return value
}

func int64Value(document map[string]any, key string) int64 {
	if document == nil {
		return 0
	}
	switch value := document[key].(type) {
	case json.Number:
		result, _ := value.Int64()
		return result
	case float64:
		return int64(value)
	default:
		return 0
	}
}

type anthropicStreamBlock struct {
	id   string
	name string
	typ  string
}

type nativeAnthropicStreamReader struct {
	body       io.ReadCloser
	cancel     context.CancelFunc
	events     *relay.SSEReader
	pending    []relay.StreamEvent
	blocks     map[int]anthropicStreamBlock
	stopReason string
	usage      *relay.Usage
	sawStop    bool
	closeOnce  sync.Once
	envelope   *modelrouter.RequestEnvelope
	startedAt  time.Time
	toolNames  *compatibleToolNameMap
}

func (r *nativeAnthropicStreamReader) Next(ctx context.Context) (relay.StreamEvent, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return relay.StreamEvent{}, ctx.Err()
		default:
		}
	}
	if len(r.pending) > 0 {
		event := r.pending[0]
		r.pending = r.pending[1:]
		return event, nil
	}
	if r.sawStop {
		return relay.StreamEvent{}, io.EOF
	}
	sseEvent, err := r.events.Next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return relay.StreamEvent{}, fmt.Errorf("upstream Anthropic stream ended before message_stop")
		}
		return relay.StreamEvent{}, err
	}
	event, err := r.anthropicEventToRelay(sseEvent)
	if err != nil {
		return relay.StreamEvent{}, err
	}
	if event.Type == relay.EventUnknown {
		return event, nil
	}
	return event, nil
}

func (r *nativeAnthropicStreamReader) anthropicEventToRelay(input relay.SSEEvent) (relay.StreamEvent, error) {
	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(input.Data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return relay.StreamEvent{Type: relay.EventUnknown, Raw: []byte(input.Data)}, nil
	}
	eventType := stringValue(document, "type")
	if eventType == "" {
		eventType = input.Event
	}
	event := relay.StreamEvent{Raw: []byte(input.Data)}
	switch eventType {
	case "message_start":
		message, _ := document["message"].(map[string]any)
		event.Type = relay.EventMessageStart
		event.ID = stringValue(message, "id")
		event.Model = stringValue(message, "model")
		if usage := anthropicRelayUsage(message["usage"]); usage != nil {
			r.mergeUsage(message["usage"])
			event.Usage = r.usage
		}
	case "content_block_start":
		index := int(int64Value(document, "index"))
		block, _ := document["content_block"].(map[string]any)
		meta := anthropicStreamBlock{
			id: stringValue(block, "id"), name: stringValue(block, "name"), typ: stringValue(block, "type"),
		}
		if r.blocks == nil {
			r.blocks = make(map[int]anthropicStreamBlock)
		}
		r.blocks[index] = meta
		if meta.typ == "tool_use" || meta.typ == "server_tool_use" {
			event.Type = relay.EventToolCallStart
			event.ToolCall = &relay.ToolCall{ID: meta.id, Name: meta.name, Index: index, ProviderExecuted: meta.typ != "tool_use"}
		} else {
			event.Type = relay.EventUnknown
		}
	case "content_block_delta":
		index := int(int64Value(document, "index"))
		delta, _ := document["delta"].(map[string]any)
		block := r.blocks[index]
		switch stringValue(delta, "type") {
		case "text_delta":
			event.Type = relay.EventTextDelta
			event.Delta = stringValue(delta, "text")
		case "thinking_delta":
			event.Type = relay.EventReasoningDelta
			event.Delta = stringValue(delta, "thinking")
		case "input_json_delta":
			event.Type = relay.EventToolArgumentsDelta
			event.Delta = stringValue(delta, "partial_json")
			// 只有 tool_use 块由客户端在本机执行；server_tool_use、mcp_tool_use 以及没见过开始帧的块都按服务方执行算。
			event.ToolCall = &relay.ToolCall{ID: block.id, Name: block.name, Index: index, ProviderExecuted: block.typ != "tool_use"}
		default:
			event.Type = relay.EventUnknown
		}
	case "message_delta":
		event.Type = relay.EventUsageFinal
		if usage := anthropicRelayUsage(document["usage"]); usage != nil {
			r.mergeUsage(document["usage"])
			event.Usage = r.usage
		}
		delta, _ := document["delta"].(map[string]any)
		if reason := stringValue(delta, "stop_reason"); reason != "" {
			r.stopReason = reason
		}
	case "message_stop":
		r.sawStop = true
		event.Type = relay.EventMessageEnd
		event.FinishReason = firstNonEmptyStream(r.stopReason, "end_turn")
		event.Usage = r.usage
	case "error":
		event.Type = relay.EventStreamError
		event.Err = fmt.Errorf("Anthropic upstream event: %s", extractErrorMessage(json.RawMessage(input.Data)))
	default:
		event.Type = relay.EventUnknown
	}
	switch event.Type {
	case relay.EventTextDelta, relay.EventReasoningDelta, relay.EventToolCallStart, relay.EventToolArgumentsDelta:
		recordUpstreamTTFT(r.envelope, r.startedAt)
	}
	restoreStreamToolName(&event, r.toolNames)
	return event, nil
}

// Anthropic usage frames are cumulative partial snapshots. Preserve omitted fields,
// but replace explicitly reported values (including a correction down to zero).
func (r *nativeAnthropicStreamReader) mergeUsage(value any) {
	document, ok := value.(map[string]any)
	if !ok {
		return
	}
	if _, present := document["cache_read_input_tokens"]; !present {
		if alias, ok := document["cached_tokens"]; ok {
			copyDocument := make(map[string]any, len(document)+1)
			for key, value := range document {
				copyDocument[key] = value
			}
			copyDocument["cache_read_input_tokens"] = alias
			document = copyDocument
		}
	}
	next := relay.Usage{}
	if r.usage != nil {
		next = *r.usage
	}
	for _, field := range []struct {
		key    string
		target *int64
	}{
		{"input_tokens", &next.InputTokens}, {"output_tokens", &next.OutputTokens},
		{"reasoning_tokens", &next.ReasoningTokens}, {"cache_read_input_tokens", &next.CacheReadInputTokens},
		{"cache_creation_input_tokens", &next.CacheCreationInputTokens},
	} {
		raw, present := document[field.key]
		if !present || raw == nil {
			continue
		}
		number, valid := raw.(json.Number)
		if !valid {
			continue
		}
		count, err := number.Int64()
		if err == nil && count >= 0 && count <= 1<<53-1 {
			*field.target = count
		}
	}
	r.usage = &next
}

func (r *nativeAnthropicStreamReader) Close() error {
	var err error
	r.closeOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		if r.body != nil {
			err = r.body.Close()
		}
	})
	return err
}

func anthropicRelayUsage(value any) *relay.Usage {
	document, _ := value.(map[string]any)
	if document == nil {
		return nil
	}
	return &relay.Usage{
		InputTokens:     int64Value(document, "input_tokens"),
		OutputTokens:    int64Value(document, "output_tokens"),
		ReasoningTokens: int64Value(document, "reasoning_tokens"),
		CacheReadInputTokens: maxPositiveStreamInt64(
			int64Value(document, "cache_read_input_tokens"),
			int64Value(document, "cached_tokens"),
		),
		CacheCreationInputTokens: int64Value(document, "cache_creation_input_tokens"),
	}
}

func firstNonEmptyStream(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// Responses permits a terminal response carrying the complete output, even
// without preceding deltas. Hydrate only missing content on the Chat bridge;
// native Responses frames are forwarded unchanged.
func (r *httpStreamReader) responsesBridgeEvents(event relay.StreamEvent, raw string) ([]relay.StreamEvent, error) {
	if r.responseTools == nil {
		r.responseTools = map[string]bool{}
		r.responseItemIDs = map[string]string{}
		r.responseArguments = map[string]*strings.Builder{}
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return nil, err
	}
	if event.Type == relay.EventTextDelta {
		if err := r.appendResponsesBridge(&r.responseText, event.Delta); err != nil {
			return nil, err
		}
	}
	if event.ToolCall != nil {
		if event.Type == relay.EventToolCallStart {
			item, _ := document["item"].(map[string]any)
			id := compatStringValue(item["call_id"])
			itemID := compatStringValue(item["id"])
			if len(id) > 4096 || len(itemID) > 4096 || len(event.ToolCall.Name) > 4096 {
				return nil, errors.New("Responses bridge tool identity exceeds bounded size")
			}
			if id != "" {
				event.ToolCall.ID = id
				if itemID != "" {
					if _, known := r.responseItemIDs[itemID]; !known && len(r.responseItemIDs) >= 64 {
						return nil, errors.New("Responses bridge exceeds 64 tool item identities")
					}
					r.responseItemIDs[itemID] = id
				}
			}
		} else if id := r.responseItemIDs[event.ToolCall.ID]; id != "" {
			event.ToolCall.ID = id
		}
		id := event.ToolCall.ID
		if len(id) > 4096 || len(event.ToolCall.Name) > 4096 {
			return nil, errors.New("Responses bridge tool identity exceeds bounded size")
		}
		if !r.responseTools[id] && len(r.responseTools) >= 64 {
			return nil, errors.New("Responses bridge exceeds 64 tools")
		}
		r.responseTools[id] = true
		args := r.responseArguments[id]
		if args == nil {
			args = &strings.Builder{}
			r.responseArguments[id] = args
		}
		if event.Type == relay.EventToolArgumentsDelta {
			if args.Len()+len(event.Delta) > 1<<20 {
				return nil, errors.New("Responses bridge tool arguments exceed 1 MiB")
			}
			if err := r.appendResponsesBridge(args, event.Delta); err != nil {
				return nil, err
			}
		}
		if event.Type == relay.EventToolArgumentsDone {
			before := args.String()
			if !strings.HasPrefix(event.Delta, before) {
				return nil, fmt.Errorf("Responses final arguments conflict with streamed arguments")
			}
			event.Delta = strings.TrimPrefix(event.Delta, before)
			if args.Len()+len(event.Delta) > 1<<20 {
				return nil, errors.New("Responses bridge tool arguments exceed 1 MiB")
			}
			if err := r.appendResponsesBridge(args, event.Delta); err != nil {
				return nil, err
			}
			event.Type = relay.EventToolArgumentsDelta
		}
	}
	if event.Type != relay.EventMessageEnd {
		return []relay.StreamEvent{event}, nil
	}
	response, _ := document["response"].(map[string]any)
	out := make([]relay.StreamEvent, 0)
	var finalText strings.Builder
	for index, rawItem := range anySlice(response["output"]) {
		item, _ := rawItem.(map[string]any)
		switch compatStringValue(item["type"]) {
		case "message":
			for _, rawContent := range anySlice(item["content"]) {
				content, _ := rawContent.(map[string]any)
				if compatStringValue(content["type"]) == "output_text" {
					text := compatStringValue(content["text"])
					if finalText.Len()+len(text) > 4<<20 {
						return nil, errors.New("Responses bridge terminal text exceeds 4 MiB")
					}
					finalText.WriteString(text)
				}
			}
		case "function_call":
			id := compatStringValue(item["call_id"])
			if id == "" {
				id = compatStringValue(item["id"])
			}
			call := &relay.ToolCall{ID: id, Name: compatStringValue(item["name"]), Index: index}
			if !r.responseTools[id] {
				if len(r.responseTools) >= 64 {
					return nil, errors.New("Responses bridge exceeds 64 tools")
				}
				start := relay.StreamEvent{Type: relay.EventToolCallStart, ToolCall: call}
				restoreStreamToolName(&start, r.toolNames)
				out = append(out, start)
				r.responseTools[id] = true
			}
			arguments := compatStringValue(item["arguments"])
			if len(arguments) > 1<<20 {
				return nil, errors.New("Responses bridge tool arguments exceed 1 MiB")
			}
			args := r.responseArguments[id]
			if args == nil {
				args = &strings.Builder{}
				r.responseArguments[id] = args
			}
			before := args.String()
			if !strings.HasPrefix(arguments, before) {
				return nil, fmt.Errorf("Responses terminal arguments conflict with streamed arguments")
			}
			if suffix := strings.TrimPrefix(arguments, before); suffix != "" {
				out = append(out, relay.StreamEvent{Type: relay.EventToolArgumentsDelta, ToolCall: call, Delta: suffix})
			}
			if err := r.appendResponsesBridge(args, strings.TrimPrefix(arguments, before)); err != nil {
				return nil, err
			}
		}
	}
	// If an upstream omits response.output_text.done, the terminal response
	// remains authoritative for the complete visible text.
	if text := finalText.String(); text != "" {
		if !strings.HasPrefix(text, r.responseText.String()) {
			return nil, fmt.Errorf("Responses terminal text conflicts with streamed text")
		}
		if suffix := strings.TrimPrefix(text, r.responseText.String()); suffix != "" {
			if err := r.appendResponsesBridge(&r.responseText, suffix); err != nil {
				return nil, err
			}
			out = append([]relay.StreamEvent{{Type: relay.EventTextDelta, Delta: suffix}}, out...)
		}
	}

	if event.FinishReason == "completed" {
		event.FinishReason = "stop"
		if len(r.responseTools) > 0 {
			event.FinishReason = "tool_calls"
		}
	}
	if event.FinishReason == "incomplete" {
		event.FinishReason = "length"
	}
	out = append(out, event)
	return out, nil
}

func (r *httpStreamReader) appendResponsesBridge(buffer *strings.Builder, delta string) error {
	if r.responseBytes+len(delta) > 4<<20 {
		return errors.New("Responses bridge output exceeds 4 MiB bounded buffer")
	}
	buffer.WriteString(delta)
	r.responseBytes += len(delta)
	return nil
}
