package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// ErrInvalidAnthropicMessagesResponse marks an HTTP 200 response that does not
// satisfy the minimum native Anthropic Messages success envelope.
var ErrInvalidAnthropicMessagesResponse = errors.New("invalid Anthropic Messages response")

func validateNativeAnthropicMessagesResponse(raw []byte) error {
	var response struct {
		Type    string          `json:"type"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return fmt.Errorf("%w: invalid JSON: %v", ErrInvalidAnthropicMessagesResponse, err)
	}
	if response.Type != "message" {
		return fmt.Errorf("%w: response type is %q", ErrInvalidAnthropicMessagesResponse, response.Type)
	}
	var content []json.RawMessage
	if len(response.Content) == 0 || bytes.Equal(bytes.TrimSpace(response.Content), []byte("null")) {
		return fmt.Errorf("%w: response content is not an array", ErrInvalidAnthropicMessagesResponse)
	}
	if err := json.Unmarshal(response.Content, &content); err != nil {
		return fmt.Errorf("%w: response content is not an array", ErrInvalidAnthropicMessagesResponse)
	}
	return nil
}

type anthropicTransportMetadataKey struct{}

// AnthropicTransportMetadata carries request-scoped protocol metadata without
// adding client headers or query strings to the persistent routing envelope.
type AnthropicTransportMetadata struct {
	RequestHeaders  http.Header
	RawQuery        string
	ResponseHeaders http.Header
}

func WithAnthropicTransportMetadata(ctx context.Context, metadata *AnthropicTransportMetadata) context.Context {
	if metadata == nil {
		return ctx
	}
	return context.WithValue(ctx, anthropicTransportMetadataKey{}, metadata)
}

func anthropicTransportMetadata(ctx context.Context) *AnthropicTransportMetadata {
	metadata, _ := ctx.Value(anthropicTransportMetadataKey{}).(*AnthropicTransportMetadata)
	return metadata
}

func rewriteNativeAnthropicModel(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, error) {
	if envelope == nil || envelope.UpstreamModelID == "" || envelope.UpstreamModelID == envelope.Model {
		return append([]byte(nil), rawBody...), nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &fields); err != nil {
		return nil, fmt.Errorf("failed to parse native Messages request for model rewrite: %w", err)
	}
	model, err := json.Marshal(envelope.UpstreamModelID)
	if err != nil {
		return nil, fmt.Errorf("failed to encode native Messages model: %w", err)
	}
	fields["model"] = model
	return json.Marshal(fields)
}

func nativeAnthropicMessagesURL(baseURL string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, fmt.Errorf("invalid configured upstream URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("configured upstream URL must use http or https")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("configured upstream URL must have a host and no credentials or fragment")
	}
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	if strings.HasSuffix(path, "/v1") {
		path += "/messages"
	} else {
		path += "/v1/messages"
	}
	unescapedPath, err := url.PathUnescape(path)
	if err != nil {
		return nil, fmt.Errorf("invalid configured upstream path: %w", err)
	}
	parsed.Path = unescapedPath
	parsed.RawPath = path
	return parsed, nil
}

var anthropicCredentialQueryKeys = map[string]struct{}{
	"api_key":       {},
	"x-api-key":     {},
	"authorization": {},
	"access_token":  {},
	"token":         {},
}

func appendSafeAnthropicQuery(upstream *url.URL, rawQuery string) error {
	rawQuery = strings.TrimPrefix(strings.TrimSpace(rawQuery), "?")
	if rawQuery == "" {
		return nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return fmt.Errorf("invalid Messages query: %w", err)
	}
	for key := range values {
		if _, forbidden := anthropicCredentialQueryKeys[strings.ToLower(strings.TrimSpace(key))]; forbidden {
			return fmt.Errorf("credential query parameter %q is not allowed", key)
		}
	}
	if upstream.RawQuery == "" {
		upstream.RawQuery = rawQuery
	} else {
		upstream.RawQuery += "&" + rawQuery
	}
	return nil
}

// ValidateAnthropicTransportQuery rejects credentials before any upstream
// request is attempted. Non-credential parameters retain their raw encoding,
// duplicates, and order when the adapter appends them later.
func ValidateAnthropicTransportQuery(rawQuery string) error {
	return appendSafeAnthropicQuery(&url.URL{}, rawQuery)
}

func safeAnthropicRequestHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "anthropic-version", "anthropic-beta", "anthropic-dangerous-direct-browser-access", "accept", "user-agent", "x-app", "x-session-id", "x-claude-code-session-id":
		return true
	}
	return strings.HasPrefix(name, "x-claude-") ||
		strings.HasPrefix(name, "x-stainless-") ||
		strings.HasPrefix(name, "anthropic-client-")
}

func copyAnthropicRequestHeaders(dst, src http.Header) {
	for name, values := range src {
		if !safeAnthropicRequestHeader(name) {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func safeAnthropicResponseHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "content-type", "cache-control", "retry-after", "request-id", "anthropic-request-id":
		return true
	}
	return strings.HasPrefix(name, "anthropic-ratelimit-") || strings.HasPrefix(name, "x-ratelimit-")
}

func copyAnthropicResponseHeaders(src http.Header) http.Header {
	dst := make(http.Header)
	for name, values := range src {
		if !safeAnthropicResponseHeader(name) {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
	return dst
}

// SafeAnthropicResponseHeaders returns only protocol-relevant response
// metadata that can cross the gateway boundary.
func SafeAnthropicResponseHeaders(src http.Header) http.Header {
	return copyAnthropicResponseHeaders(src)
}

func captureAnthropicResponseHeaders(ctx context.Context, headers http.Header) http.Header {
	safe := copyAnthropicResponseHeaders(headers)
	if metadata := anthropicTransportMetadata(ctx); metadata != nil {
		metadata.ResponseHeaders = safe.Clone()
	}
	return safe
}

func anthropicMessagesHTTPClient(proxyURL string, streaming bool) (*http.Client, error) {
	if !streaming {
		return nonStreamingHTTPClient(proxyURL)
	}
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
	transport.ResponseHeaderTimeout = 10 * time.Minute
	transport.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: transport, Timeout: 0}, nil
}

func forceNativeAnthropicStream(payload []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("force native Messages stream: unmarshal payload: %w", err)
	}
	if stream, ok := fields["stream"]; ok && strings.TrimSpace(string(stream)) == "true" {
		return append([]byte(nil), payload...), nil
	}
	fields["stream"] = json.RawMessage("true")
	return json.Marshal(fields)
}

func openNativeAnthropicMessagesStream(
	ctx context.Context,
	envelope *modelrouter.RequestEnvelope,
	payload []byte,
	baseURL string,
	apiKey string,
	proxyURL string,
	authMode string,
	streamIdleTimeout time.Duration,
) (relay.StreamReader, StreamResponseMeta, error) {
	if apiKey == "" {
		return nil, StreamResponseMeta{}, fmt.Errorf("Messages provider is not configured with an API key")
	}
	requestPayload, err := forceNativeAnthropicStream(payload)
	if err != nil {
		return nil, StreamResponseMeta{}, err
	}
	attemptCtx, cancel := context.WithCancel(ctx)
	req, err := buildNativeAnthropicRequest(attemptCtx, baseURL, apiKey, authMode, requestPayload, true)
	if err != nil {
		cancel()
		return nil, StreamResponseMeta{}, err
	}
	setVerifiedIdempotencyHeader(req, envelope)
	client, err := anthropicMessagesHTTPClient(proxyURL, true)
	if err != nil {
		cancel()
		return nil, StreamResponseMeta{}, fmt.Errorf("invalid configured outbound proxy: %w", err)
	}
	startedAt := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, StreamResponseMeta{}, err
	}
	meta := StreamResponseMeta{StatusCode: resp.StatusCode, Header: resp.Header.Clone()}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, readErr := readResponseBody(resp)
		_ = resp.Body.Close()
		cancel()
		return nil, meta, readErr
	}
	resp.Body = newByteIdleReadCloser(resp.Body, streamIdleTimeout, cancel)
	return &nativeAnthropicStreamReader{
		body: resp.Body, cancel: cancel,
		events:   relay.NewSSEReader(resp.Body, relay.SSELimits{MaxLineBytes: 1 << 20, MaxEventBytes: 64 << 20}),
		blocks:   make(map[int]anthropicStreamBlock),
		envelope: envelope, startedAt: startedAt,
	}, meta, nil
}

func buildNativeAnthropicRequest(
	ctx context.Context,
	baseURL string,
	apiKey string,
	authMode string,
	payload []byte,
	streaming bool,
) (*http.Request, error) {
	endpoint, err := nativeAnthropicMessagesURL(baseURL)
	if err != nil {
		return nil, err
	}
	metadata := anthropicTransportMetadata(ctx)
	if metadata != nil {
		if err := appendSafeAnthropicQuery(endpoint, metadata.RawQuery); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	if metadata != nil {
		copyAnthropicRequestHeaders(req.Header, metadata.RequestHeaders)
	}
	req.Header.Set("Content-Type", "application/json")
	if req.Header.Get("Anthropic-Version") == "" {
		req.Header.Set("Anthropic-Version", "2023-06-01")
	}
	if streaming {
		req.Header.Set("Accept", "text/event-stream")
	}
	switch authMode {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+apiKey)
	case "x-api-key":
		req.Header.Set("X-Api-Key", apiKey)
	default:
		return nil, fmt.Errorf("unsupported Messages authentication mode %q", authMode)
	}
	return req, nil
}

func callNativeAnthropicMessages(
	ctx context.Context,
	envelope *modelrouter.RequestEnvelope,
	payload []byte,
	baseURL string,
	apiKey string,
	proxyURL string,
	authMode string,
	streaming bool,
	streamIdleTimeout time.Duration,
) ([]byte, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("Messages provider is not configured with an API key")
	}
	requestPayload := payload
	var err error
	if streaming {
		requestPayload, err = forceNativeAnthropicStream(payload)
		if err != nil {
			return nil, err
		}
	}
	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := buildNativeAnthropicRequest(attemptCtx, baseURL, apiKey, authMode, requestPayload, streaming)
	if err != nil {
		return nil, err
	}
	setVerifiedIdempotencyHeader(req, envelope)
	client, err := anthropicMessagesHTTPClient(proxyURL, streaming)
	if err != nil {
		return nil, fmt.Errorf("invalid configured outbound proxy: %w", err)
	}
	startedAt := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if streaming {
		resp.Body = newByteIdleReadCloser(resp.Body, streamIdleTimeout, cancel)
	}
	defer resp.Body.Close()
	safeHeaders := captureAnthropicResponseHeaders(ctx, resp.Header)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, readErr := readResponseBody(resp)
		if upstreamErr := GetUpstreamHTTPError(readErr); upstreamErr != nil {
			upstreamErr.Headers = safeHeaders
		}
		return nil, readErr
	}
	if !streaming {
		body, err := readResponseBody(resp)
		if err != nil {
			return nil, err
		}
		if err := validateNativeAnthropicMessagesResponse(body); err != nil {
			return nil, err
		}
		return body, nil
	}
	raw, err := readNativeResponsesSSE(resp.Body, func() { recordUpstreamTTFT(envelope, startedAt) })
	if err != nil {
		return nil, err
	}
	if _, err := accumulateAnthropicSSE(bytes.NewReader(raw)); err != nil {
		if upstreamErr := GetUpstreamHTTPError(err); upstreamErr != nil {
			upstreamErr.Headers = safeHeaders
		}
		return nil, err
	}
	return raw, nil
}

// capNativeAnthropicOutputTokens 只用于 Anthropic 类型上游，保持原生工具 schema 不变。
// 未设置输出上限时不注入；发生收紧时同步维护思考预算的硬约束。
func capNativeAnthropicOutputTokens(payload []byte) ([]byte, error) {
	var request map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&request); err != nil {
		return nil, fmt.Errorf("解析原生 Messages 输出上限: %w", err)
	}
	model, _ := request["model"].(string)
	if !clampAnthropicMaxTokens(request, anthropicRequestModelProfile(model)) {
		return payload, nil
	}
	limit, _ := anthropicIntValue(request["max_tokens"])
	if thinking, ok := request["thinking"].(map[string]any); ok {
		budget, hasBudget := anthropicIntValue(thinking["budget_tokens"])
		if thinking["type"] == "enabled" && hasBudget && budget >= limit {
			if limit <= 1024 {
				delete(request, "thinking")
			} else {
				thinking["budget_tokens"] = limit - 1
			}
		}
	}
	return json.Marshal(request)
}
