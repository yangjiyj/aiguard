package catalog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

const (
	ModelProbeErrorUnauthorized   = "unauthorized"
	ModelProbeErrorNotDeployed    = "not_deployed"
	ModelProbeErrorRateLimited    = "rate_limited"
	ModelProbeErrorUpstream       = "upstream_error"
	ModelProbeErrorTimeout        = "timeout"
	ModelProbeErrorCancelled      = "cancelled"
	ModelProbeErrorInvalidRequest = "invalid_request"

	modelProbeTimeout = 15 * time.Second
	// Responses payloads can legitimately include tens of kilobytes of
	// reasoning and usage metadata even for a one-word visible answer. Keep a
	// firm bound, but do not reject valid OpenAI-compatible responses solely
	// because their envelope exceeds the old 8 KiB limit.
	modelProbeResponseBodyLimit      = 256 << 10
	modelProbeImageResponseBodyLimit = 16 << 20

	// Reasoning models count hidden reasoning against the completion budget.
	// 1024 leaves room for that reasoning plus the requested short visible reply,
	// while keeping each probe's output-token cost and rate-limit impact bounded.
	modelProbeMaxCompletionTokens = 1024
	// Native Messages probing establishes protocol compatibility only, so keep
	// its billable output deliberately small; unlike the Chat probe it is not
	// used to validate a reasoning deployment.
	modelProbeMessagesMaxTokens = 16
)

type ModelProbeRequest struct {
	ProviderType    string
	BaseURL         string
	APIKey          string
	AuthMode        string
	DeploymentName  string
	Protocol        string
	MaxOutputTokens int
	Timeout         time.Duration
}

type ModelProbeResult struct {
	OK               bool
	ErrorKind        string
	Message          string
	HTTPStatus       int
	LatencyMS        int64
	PayloadValidated bool
}

type ModelProber interface {
	Probe(context.Context, ModelProbeRequest) ModelProbeResult
}

type httpModelProber struct {
	baseClient *http.Client
}

func NewHTTPModelProber() ModelProber {
	return &httpModelProber{}
}

// newHTTPModelProberWithClient keeps local HTTP tests deterministic without
// weakening the production constructor's safetarget DNS and IP pinning.
func newHTTPModelProberWithClient(client *http.Client) ModelProber {
	return &httpModelProber{baseClient: client}
}

func (p *httpModelProber) Probe(ctx context.Context, probe ModelProbeRequest) (result ModelProbeResult) {
	if nativeProbeProvider(probe.ProviderType) {
		return p.probeNative(ctx, probe)
	}
	started := time.Now()
	var httpStatus int
	defer func() {
		result.LatencyMS = time.Since(started).Milliseconds()
		result.HTTPStatus = httpStatus
	}()
	baseURL, authMode, protocol, err := validateModelProbeRequest(probe)
	if err != nil {
		return modelProbeFailure(ModelProbeErrorInvalidRequest)
	}

	timeout := modelProbeTimeout
	if probe.Timeout > 0 {
		timeout = probe.Timeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := p.clientFor(probeCtx, baseURL, authMode == "authorization_raw")
	if err != nil {
		return classifyModelProbeError(probeCtx, err)
	}
	client.Timeout = timeout

	payloadFields := map[string]interface{}{
		"model":  probe.DeploymentName,
		"stream": false,
	}
	if protocol == "images" {
		payloadFields = map[string]interface{}{"model": probe.DeploymentName, "prompt": "A plain white square, no text.", "n": 1, "size": "1024x1024"}
		if strings.HasPrefix(strings.ToLower(probe.DeploymentName), "gpt-image") {
			payloadFields["quality"] = "low"
		}
	} else if protocol == "responses" {
		payloadFields["input"] = "Reply OK."
		payloadFields["max_output_tokens"] = modelProbeMaxCompletionTokens
	} else if protocol == "messages" {
		payloadFields["messages"] = []map[string]string{{"role": "user", "content": "Reply OK."}}
		payloadFields["max_tokens"] = modelProbeMessagesMaxTokens
	} else {
		payloadFields["messages"] = []map[string]string{{"role": "user", "content": "Reply OK."}}
		payloadFields["max_completion_tokens"] = modelProbeMaxCompletionTokens
	}
	if probe.MaxOutputTokens > 0 && protocol != "images" {
		if protocol == "responses" {
			payloadFields["max_output_tokens"] = probe.MaxOutputTokens
		} else if protocol == "messages" {
			payloadFields["max_tokens"] = probe.MaxOutputTokens
		} else {
			payloadFields["max_completion_tokens"] = probe.MaxOutputTokens
		}
	}
	payload, err := json.Marshal(payloadFields)
	if err != nil {
		return modelProbeFailure(ModelProbeErrorInvalidRequest)
	}

	endpoint := baseURL
	if authMode != "authorization_raw" {
		endpoint = joinModelProbePath(baseURL, probe.DeploymentName, protocol)
	}
	request, err := http.NewRequestWithContext(probeCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return modelProbeFailure(ModelProbeErrorInvalidRequest)
	}
	request.Header.Set("Content-Type", "application/json")
	if protocol == "messages" {
		request.Header.Set("Anthropic-Version", "2023-06-01")
	}
	switch authMode {
	case "authorization_raw":
		request.Header.Set("Authorization", probe.APIKey)
	case "bearer", "api_key":
		// api_key is the persisted legacy value. The current Azure/OpenAI
		// runtime ignores ProviderAuthMode and sends Bearer, so probes must do
		// the same to verify the path customers actually use.
		request.Header.Set("Authorization", "Bearer "+probe.APIKey)
	case "api-key":
		request.Header.Set("api-key", probe.APIKey)
	case "x-api-key":
		request.Header.Set("x-api-key", probe.APIKey)
	}

	response, err := client.Do(request)
	if err != nil {
		return classifyModelProbeError(probeCtx, err)
	}
	defer response.Body.Close()
	httpStatus = response.StatusCode

	switch {
	case response.StatusCode == http.StatusOK:
		if validModelProbeSuccessBody(response.Body, protocol) {
			return ModelProbeResult{OK: true, Message: "部署探测成功", PayloadValidated: true}
		}
		if probeCtx.Err() != nil {
			return classifyModelProbeError(probeCtx, probeCtx.Err())
		}
		return modelProbeFailure(ModelProbeErrorUpstream)
	case response.StatusCode >= 200 && response.StatusCode < 300:
		return modelProbeFailure(ModelProbeErrorUpstream)
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return modelProbeFailure(ModelProbeErrorUnauthorized)
	case response.StatusCode == http.StatusTooManyRequests:
		return modelProbeFailure(ModelProbeErrorRateLimited)
	case response.StatusCode != http.StatusNotFound:
		return modelProbeFailure(ModelProbeErrorUpstream)
	}

	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, modelProbeResponseBodyLimit))
	if readErr != nil {
		return classifyModelProbeError(probeCtx, readErr)
	}
	if bytes.Contains(bytes.ToLower(responseBody), []byte("deploymentnotfound")) {
		return modelProbeFailure(ModelProbeErrorNotDeployed)
	}
	return modelProbeFailure(ModelProbeErrorUpstream)
}

func validModelProbeSuccessBody(reader io.Reader, protocol string) bool {
	limit := modelProbeResponseBodyLimit
	if protocol == "images" {
		limit = modelProbeImageResponseBodyLimit
	}
	body, err := io.ReadAll(io.LimitReader(reader, int64(limit+1)))
	if err != nil || len(body) == 0 || len(body) > limit {
		return false
	}
	var payload struct {
		ID      string            `json:"id"`
		Type    string            `json:"type"`
		Status  string            `json:"status"`
		Error   json.RawMessage   `json:"error"`
		Output  []json.RawMessage `json:"output"`
		Content []json.RawMessage `json:"content"`
		Data    []struct {
			URL    string `json:"url"`
			Base64 string `json:"b64_json"`
		} `json:"data"`
		Choices []struct {
			Message *struct {
				Content *string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	if errorPayload := bytes.TrimSpace(payload.Error); len(errorPayload) > 0 && !bytes.Equal(errorPayload, []byte("null")) {
		return false
	}
	if protocol == "images" {
		for _, item := range payload.Data {
			if item.Base64 != "" {
				decoded, err := base64.StdEncoding.DecodeString(item.Base64)
				if err != nil {
					continue
				}
				config, _, err := image.DecodeConfig(bytes.NewReader(decoded))
				if err == nil && config.Width > 0 && config.Height > 0 {
					return true
				}
			}
			if parsed, err := url.Parse(item.URL); err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.Fragment == "" {
				return true
			}
		}
		return false
	}
	if protocol == "responses" {
		if payload.ID == "" || (payload.Status != "" && payload.Status != "completed") {
			return false
		}
		for _, raw := range payload.Output {
			var item struct {
				Type    string            `json:"type"`
				Content []json.RawMessage `json:"content"`
			}
			if json.Unmarshal(raw, &item) == nil && item.Type == "message" && validProbeTextContent(item.Content) {
				return true
			}
		}
		return false
	}
	if protocol == "messages" {
		return payload.ID != "" && payload.Type == "message" && validProbeTextContent(payload.Content)
	}
	for _, choice := range payload.Choices {
		if choice.Message != nil && choice.Message.Content != nil && strings.TrimSpace(*choice.Message.Content) != "" {
			return true
		}
	}
	return false
}

func validProbeTextContent(items []json.RawMessage) bool {
	for _, raw := range items {
		var item struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(raw, &item) == nil && (item.Type == "text" || item.Type == "output_text") && strings.TrimSpace(item.Text) != "" {
			return true
		}
	}
	return false
}

func (p *httpModelProber) clientFor(ctx context.Context, baseURL string, allowPrivate bool) (*http.Client, error) {
	if p.baseClient != nil {
		client := *p.baseClient
		client.Timeout = modelProbeTimeout
		if proxy := outboundProxyURL(ctx); proxy != "" {
			var err error
			configured, err := httpClientWithOutboundProxy(&client, proxy)
			if err != nil {
				return nil, err
			}
			client = *configured
		}
		client.CheckRedirect = noModelProbeRedirects
		return &client, nil
	}

	target, err := safetarget.Resolve(ctx, baseURL, allowPrivate, nil)
	if err != nil {
		return nil, err
	}
	client := safetarget.Client(&http.Client{Timeout: modelProbeTimeout}, target, false)
	if proxy := outboundProxyURL(ctx); proxy != "" {
		client, err = anthropicPinnedProxyClient(nil, target, proxy)
		if err != nil {
			return nil, err
		}
	}
	client.Timeout = modelProbeTimeout
	client.CheckRedirect = noModelProbeRedirects
	return client, nil
}

func noModelProbeRedirects(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func validateModelProbeRequest(probe ModelProbeRequest) (string, string, string, error) {
	if probe.MaxOutputTokens < 0 || probe.MaxOutputTokens > modelProbeMaxCompletionTokens || probe.Timeout < 0 || probe.Timeout > 120*time.Second {
		return "", "", "", errors.New("invalid probe budget")
	}
	baseURL := probe.BaseURL
	if baseURL != strings.TrimSpace(baseURL) {
		return "", "", "", errors.New("base URL contains surrounding whitespace")
	}
	authMode := probe.AuthMode
	if authMode != strings.TrimSpace(authMode) {
		return "", "", "", errors.New("auth mode contains surrounding whitespace")
	}
	authMode = strings.ToLower(authMode)
	if baseURL == "" || strings.TrimSpace(probe.APIKey) == "" || strings.TrimSpace(probe.DeploymentName) == "" {
		return "", "", "", errors.New("required probe field is empty")
	}
	protocol := strings.ToLower(strings.TrimSpace(probe.Protocol))
	if protocol == "" {
		protocol = "chat_completions"
	}
	if protocol == "chat" {
		protocol = "chat_completions"
	}
	if protocol == "anthropic_messages" {
		protocol = "messages"
	}
	if protocol != "chat_completions" && protocol != "responses" && protocol != "messages" && protocol != "images" {
		return "", "", "", errors.New("unsupported probe protocol")
	}
	switch authMode {
	case "bearer", "api_key", "api-key", "x-api-key", "authorization_raw":
	default:
		return "", "", "", errors.New("unsupported auth mode")
	}

	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Opaque != "" || !parsed.IsAbs() || parsed.Host == "" {
		return "", "", "", errors.New("base URL must be absolute")
	}
	if authMode == "authorization_raw" {
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return "", "", "", errors.New("unsupported URL scheme")
		}
	} else if parsed.Scheme != "https" {
		return "", "", "", errors.New("unsupported URL scheme")
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" {
		return "", "", "", errors.New("unsafe URL component")
	}
	if authMode != "authorization_raw" && (parsed.RawQuery != "" || parsed.ForceQuery) {
		return "", "", "", errors.New("base URL query is not allowed")
	}

	hostname := strings.TrimRight(strings.ToLower(strings.TrimSpace(parsed.Hostname())), ".")
	if hostname == "" || hostname == "metadata.azure.internal" {
		return "", "", "", errors.New("forbidden target")
	}
	if address, parseErr := netip.ParseAddr(hostname); parseErr == nil && address.Unmap() == netip.MustParseAddr("169.254.169.254") {
		return "", "", "", errors.New("forbidden target")
	}

	return baseURL, authMode, protocol, nil
}

func joinModelProbePath(baseURL, deploymentName, protocol string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	parsed, err := url.Parse(baseURL)
	if err == nil {
		host := strings.TrimRight(strings.ToLower(parsed.Hostname()), ".")
		isOpenAI := strings.HasSuffix(host, ".openai.azure.com")
		isCognitive := strings.HasSuffix(host, ".cognitiveservices.azure.com")
		if isOpenAI || isCognitive {
			version := "2024-10-21"
			parsed.RawPath = ""
			parsed.Path = normalizeAzureProbeBasePath(parsed.Path)
			parsed.ForceQuery = false
			if protocol == "responses" {
				if isOpenAI {
					parsed.Path += "/openai/v1/responses"
					parsed.RawQuery = ""
				} else {
					parsed.Path += "/openai/responses"
					parsed.RawQuery = "api-version=" + url.QueryEscape(version)
				}
			} else {
				suffix := "/chat/completions"
				if protocol == "images" {
					suffix = "/images/generations"
				}
				parsed.Path += "/openai/deployments/" + url.PathEscape(deploymentName) + suffix
				parsed.RawQuery = "api-version=" + url.QueryEscape(version)
			}
			return parsed.String()
		}
	}
	suffix := "/chat/completions"
	switch protocol {
	case "responses":
		suffix = "/responses"
	case "messages":
		suffix = "/messages"
	case "images":
		suffix = "/images/generations"
	}
	if strings.HasSuffix(baseURL, "/v1") {
		return baseURL + suffix
	}
	return baseURL + "/v1" + suffix
}

func normalizeAzureProbeBasePath(path string) string {
	path = strings.TrimRight(path, "/")
	switch path {
	case "", "/openai", "/openai/v1":
		return ""
	default:
		return path
	}
}

func classifyModelProbeError(ctx context.Context, err error) ModelProbeResult {
	switch {
	case errors.Is(ctx.Err(), context.Canceled), errors.Is(err, context.Canceled):
		return modelProbeFailure(ModelProbeErrorCancelled)
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return modelProbeFailure(ModelProbeErrorTimeout)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return modelProbeFailure(ModelProbeErrorTimeout)
	}
	if errors.Is(err, safetarget.ErrInvalidURL) ||
		errors.Is(err, safetarget.ErrForbiddenAddress) ||
		errors.Is(err, safetarget.ErrPrivateAddress) {
		return modelProbeFailure(ModelProbeErrorInvalidRequest)
	}
	return modelProbeFailure(ModelProbeErrorUpstream)
}

func modelProbeFailure(kind string) ModelProbeResult {
	messages := map[string]string{
		ModelProbeErrorUnauthorized:   "上游认证失败",
		ModelProbeErrorNotDeployed:    "Azure 部署不存在",
		ModelProbeErrorRateLimited:    "上游请求频率受限",
		ModelProbeErrorUpstream:       "上游服务异常",
		ModelProbeErrorTimeout:        "上游探测超时",
		ModelProbeErrorCancelled:      "探测已取消",
		ModelProbeErrorInvalidRequest: "探测配置无效",
	}
	return ModelProbeResult{ErrorKind: kind, Message: messages[kind]}
}
