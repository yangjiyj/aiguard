package handler

// 响应缓存（一期：精确匹配，只做 OpenAI Chat）。
//
// 问题相同（输入检测后发往上游的请求体逐字节相同、同一隔离范围、同一检测版本）时直接返回
// 上次的回答，不调上游、不计费。默认按用户隔离；管理员把应用（project）加入共享名单后，
// 同应用内共享，命中时按本次请求身份重跑输出检测。缓存存的是输出检测之后、还原脱敏之前的版本；
// 有可还原脱敏的请求不缓存（占位符里的随机数每次不同）。存储是独立的 redis-cache 实例，
// 任何错误都按未命中处理，不影响正常请求。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/redis/go-redis/v9"
	"golang.org/x/text/unicode/norm"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 系统设置键。
const (
	responseCacheEnabledKey        = "response_cache_enabled"
	responseCacheTTLKey            = "response_cache_ttl_seconds"
	responseCacheMaxEntryBytesKey  = "response_cache_max_entry_bytes"
	responseCacheMaxTemperatureKey = "response_cache_max_temperature"
	responseCacheSharedProjectsKey = "response_cache_shared_project_ids"
	responseCacheGenerationKey     = "response_cache_generation"

	responseCacheKeyPrefix       = "jjd:rc:v1:"
	responseCacheMaxRequestBytes = 256 << 10
	responseCacheOpTimeout       = 50 * time.Millisecond
	responseCacheWriteTimeout    = 2 * time.Second
)

// responseCacheSettings 是网关生效的缓存配置；零值表示关闭。
type responseCacheSettings struct {
	Enabled          bool
	TTL              time.Duration
	MaxEntryBytes    int
	MaxTemperature   float64
	SharedProjectIDs map[string]bool
	Generation       int64
}

func defaultResponseCacheSettings() responseCacheSettings {
	return responseCacheSettings{TTL: time.Hour, MaxEntryBytes: 64 << 10, MaxTemperature: 1.0, SharedProjectIDs: map[string]bool{}}
}

// parseResponseCacheSettings 从系统设置读出缓存配置；非法值回落默认，不报错。
func parseResponseCacheSettings(values map[string]string) responseCacheSettings {
	s := defaultResponseCacheSettings()
	s.Enabled = strings.EqualFold(strings.TrimSpace(values[responseCacheEnabledKey]), "true")
	if n, err := strconv.Atoi(strings.TrimSpace(values[responseCacheTTLKey])); err == nil && n >= 60 && n <= 86400 {
		s.TTL = time.Duration(n) * time.Second
	}
	if n, err := strconv.Atoi(strings.TrimSpace(values[responseCacheMaxEntryBytesKey])); err == nil && n >= 1<<10 && n <= 1<<20 {
		s.MaxEntryBytes = n
	}
	if f, err := strconv.ParseFloat(strings.TrimSpace(values[responseCacheMaxTemperatureKey]), 64); err == nil && f >= 0 && f <= 2 {
		s.MaxTemperature = f
	}
	if raw := strings.TrimSpace(values[responseCacheSharedProjectsKey]); raw != "" {
		var ids []string
		if json.Unmarshal([]byte(raw), &ids) == nil {
			for _, id := range ids {
				if id = strings.TrimSpace(id); id != "" {
					s.SharedProjectIDs[id] = true
				}
			}
		}
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(values[responseCacheGenerationKey]), 10, 64); err == nil && n >= 0 {
		s.Generation = n
	}
	return s
}

type responseCacheSettingsCache struct {
	mu    sync.Mutex
	value *responseCacheSettings
}

// ResponseCacheSettings 返回后台轮询拿到的最近一次配置；首次加载前为关闭。
func (c *ToolRiskClient) ResponseCacheSettings() responseCacheSettings {
	if c == nil {
		return responseCacheSettings{}
	}
	c.responseCacheCache.mu.Lock()
	defer c.responseCacheCache.mu.Unlock()
	if c.responseCacheCache.value == nil {
		return responseCacheSettings{}
	}
	return *c.responseCacheCache.value
}

func (c *ToolRiskClient) setResponseCacheSettings(settings responseCacheSettings) {
	if c == nil {
		return
	}
	c.responseCacheCache.mu.Lock()
	defer c.responseCacheCache.mu.Unlock()
	c.responseCacheCache.value = &settings
}

// ---- 存储 ----

// ResponseCache 是缓存存储；实现必须在超时或出错时返回未命中，不能阻塞请求。
type ResponseCache interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration)
}

// redisResponseCache 是独立 redis-cache 实例上的实现。
type redisResponseCache struct{ client redis.UniversalClient }

// NewRedisResponseCache 包装缓存专用的 Redis 客户端；client 为 nil 时返回 nil（缓存不可用）。
func NewRedisResponseCache(client redis.UniversalClient) ResponseCache {
	if client == nil {
		return nil
	}
	return &redisResponseCache{client: client}
}

func (c *redisResponseCache) Get(ctx context.Context, key string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(ctx, responseCacheOpTimeout)
	defer cancel()
	value, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		return nil, false
	}
	return value, true
}

func (c *redisResponseCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, responseCacheWriteTimeout)
	defer cancel()
	_ = c.client.Set(ctx, key, value, ttl).Err()
}

// SetResponseCache 注入缓存存储（nil = 禁用）。
func (h *ChatCompletionsHandler) SetResponseCache(cache ResponseCache) { h.responseCache = cache }

// ---- 条目 ----

// responseCacheEntry 是缓存的回答：输出检测之后的 choices 与原始用量、成本。
type responseCacheEntry struct {
	Model           string          `json:"model"`
	Choices         json.RawMessage `json:"choices"`
	Usage           json.RawMessage `json:"usage,omitempty"`
	CostMicros      int64           `json:"cost_micros,omitempty"`
	CostAvailable   bool            `json:"cost_available,omitempty"`
	Currency        string          `json:"currency,omitempty"`
	SourceRequestID string          `json:"source_request_id"`
	CreatedAt       time.Time       `json:"created_at"`
}

// responseCacheLookup 是一次请求的缓存判定结果。
type responseCacheLookup struct {
	key      string
	shared   bool
	entry    *responseCacheEntry
	settings responseCacheSettings
}

var errResponseCacheIneligible = errors.New("response cache: request not eligible")

// responseCacheKey 计算缓存键。返回错误表示本请求不缓存（查找和写入都跳过）。
func responseCacheKey(settings responseCacheSettings, envelope *modelrouter.RequestEnvelope, versions responseCacheVersions, securedBody []byte) (string, bool, error) {
	if envelope == nil || versions.rulePack == "" || versions.engineBuild == "" {
		return "", false, errResponseCacheIneligible
	}
	canonical, err := canonicalResponseCacheBody(securedBody)
	if err != nil {
		return "", false, err
	}
	shared := envelope.ProjectID != "" && settings.SharedProjectIDs[envelope.ProjectID]
	principal := envelope.UserID
	if principal == "" {
		principal = "key:" + envelope.ClientID
	}
	if principal == "key:" {
		return "", false, errResponseCacheIneligible
	}
	scope := "user|" + principal
	if shared {
		scope = "shared"
	}
	h := sha256.New()
	for _, part := range []string{
		"v1", strconv.FormatInt(settings.Generation, 10),
		envelope.TenantID, envelope.ProjectID, scope,
		envelope.EnvironmentScope, envelope.ModelID, envelope.Model,
		versions.rulePack, versions.engineBuild, versions.semantic, versions.gatewayRevision,
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write(canonical)
	return responseCacheKeyPrefix + hex.EncodeToString(h.Sum(nil)), shared, nil
}

// responseCacheVersions 是参与缓存键的检测版本；任何一个变化旧缓存自然失效。
type responseCacheVersions struct {
	rulePack, engineBuild, semantic, gatewayRevision string
}

// canonicalResponseCacheBody 规范化请求体：去掉 stream 与 stream_options（流式与非流式共用），
// 消息文本做 NFC 并去首尾空白，键排序后序列化。
func canonicalResponseCacheBody(body []byte) ([]byte, error) {
	if len(body) == 0 || len(body) > responseCacheMaxRequestBytes {
		return nil, errResponseCacheIneligible
	}
	value, err := decodeRedactionJSON(body)
	if err != nil {
		return nil, errResponseCacheIneligible
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, errResponseCacheIneligible
	}
	delete(root, "stream")
	delete(root, "stream_options")
	for _, raw := range asSlice(root["messages"]) {
		msg, _ := raw.(map[string]any)
		if msg == nil {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			msg["content"] = normalizeCacheText(content)
		case []any:
			for _, part := range content {
				if p, _ := part.(map[string]any); p != nil {
					if text, ok := p["text"].(string); ok {
						p["text"] = normalizeCacheText(text)
					}
				}
			}
		}
	}
	// encoding/json 对 map 按键排序输出，得到稳定的规范形式。
	return json.Marshal(root)
}

func normalizeCacheText(text string) string {
	return strings.TrimFunc(norm.NFC.String(text), unicode.IsSpace)
}

// responseCacheRequestEligible 判断请求本身能否参与缓存（与身份、版本无关的条件）。
func responseCacheRequestEligible(ctx context.Context, envelope *modelrouter.RequestEnvelope, req *ChatCompletionRequest, cacheControl string, settings responseCacheSettings) bool {
	if !settings.Enabled || envelope == nil || req == nil {
		return false
	}
	if envelope.EndpointType != "" && envelope.EndpointType != "chat" {
		return false
	}
	if req.PreserveOriginalBody || isProxyRequest(ctx) || envelope.LSEEvalRunID != "" {
		return false
	}
	if hasRequestRedaction(ctx, envelope) {
		return false
	}
	cc := strings.ToLower(cacheControl)
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") {
		return false
	}
	if len(req.Tools) > 0 || req.ToolChoice != nil {
		return false
	}
	temperature := 1.0
	if req.Temperature > 0 {
		temperature = req.Temperature
	}
	if temperature > settings.MaxTemperature {
		return false
	}
	for _, msg := range req.Messages {
		role := strings.ToLower(msg.Role)
		if role == "tool" || role == "function" || len(msg.ToolCalls) > 0 || msg.ToolCallID != "" {
			return false
		}
		if !textOnlyContent(msg.Content) {
			return false
		}
	}
	return true
}

// textOnlyContent 判断消息内容是字符串，或只含 text 块的数组。
func textOnlyContent(content json.RawMessage) bool {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 || trimmed[0] == '"' || bytes.Equal(trimmed, []byte("null")) {
		return true
	}
	var parts []map[string]any
	if json.Unmarshal(trimmed, &parts) != nil {
		return false
	}
	for _, p := range parts {
		if t, _ := p["type"].(string); t != "text" {
			return false
		}
	}
	return true
}

// rawBodyRequestsMultipleOrLogprobs 检查未类型化的字段：n>1、logprobs 都不缓存。
func rawBodyRequestsMultipleOrLogprobs(body []byte) bool {
	var fields struct {
		N           *int            `json:"n"`
		Logprobs    json.RawMessage `json:"logprobs"`
		TopLogprobs json.RawMessage `json:"top_logprobs"`
	}
	if json.Unmarshal(body, &fields) != nil {
		return true
	}
	if fields.N != nil && *fields.N > 1 {
		return true
	}
	lp := strings.TrimSpace(string(fields.Logprobs))
	return (lp != "" && lp != "false" && lp != "null") || len(bytes.TrimSpace(fields.TopLogprobs)) > 0 && string(bytes.TrimSpace(fields.TopLogprobs)) != "null"
}

// ---- 写入条件与编码 ----

// responseCacheStorable 判断一次成功回复能否写入缓存，返回要存的条目。
func responseCacheStorable(settings responseCacheSettings, envelope *modelrouter.RequestEnvelope, respBody []byte, audit *AuditResult) (*responseCacheEntry, bool) {
	if envelope == nil || len(respBody) == 0 || len(respBody) > settings.MaxEntryBytes {
		return nil, false
	}
	if audit != nil {
		if a := outputActionOf(audit); a != "" && a != "allow" {
			return nil, false
		}
		if len(audit.OutputFindings) > 0 || len(audit.InputFindings) > 0 {
			return nil, false
		}
		if v, _ := audit.ResponseMetadata["output_scan_incomplete"].(bool); v {
			return nil, false
		}
	}
	var resp struct {
		Model   string          `json:"model"`
		Choices json.RawMessage `json:"choices"`
		Usage   json.RawMessage `json:"usage"`
	}
	if json.Unmarshal(respBody, &resp) != nil {
		return nil, false
	}
	var choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content   *string         `json:"content"`
			ToolCalls json.RawMessage `json:"tool_calls"`
		} `json:"message"`
	}
	if json.Unmarshal(resp.Choices, &choices) != nil || len(choices) == 0 {
		return nil, false
	}
	for _, c := range choices {
		if c.FinishReason != "stop" || c.Message.Content == nil || strings.TrimSpace(*c.Message.Content) == "" {
			return nil, false
		}
		if tc := bytes.TrimSpace(c.Message.ToolCalls); len(tc) > 0 && !bytes.Equal(tc, []byte("null")) && !bytes.Equal(tc, []byte("[]")) {
			return nil, false
		}
	}
	return &responseCacheEntry{
		Model: resp.Model, Choices: resp.Choices, Usage: resp.Usage,
		CostMicros: envelope.QuotaActualCostMicros, CostAvailable: envelope.QuotaActualCostAvailable,
		Currency: envelope.QuotaCostCurrency, SourceRequestID: envelope.RequestID, CreatedAt: time.Now().UTC(),
	}, true
}

// buildCacheHitResponse 用缓存条目拼出本次请求的 chat completion：id、created 换成本次的。
func buildCacheHitResponse(envelope *modelrouter.RequestEnvelope, entry *responseCacheEntry) []byte {
	model := entry.Model
	if model == "" && envelope != nil {
		model = envelope.Model
	}
	resp := map[string]any{
		"id":      "chatcmpl-" + envelope.RequestID,
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": entry.Choices,
	}
	if len(entry.Usage) > 0 {
		resp["usage"] = entry.Usage
	}
	body, _ := json.Marshal(resp)
	return body
}

// cacheHitMetadata 写进 output_audit_result.response_metadata.cache，节省报表据此计算。
func cacheHitMetadata(entry *responseCacheEntry, shared bool) map[string]any {
	var usage struct {
		Prompt     int64 `json:"prompt_tokens"`
		Completion int64 `json:"completion_tokens"`
	}
	_ = json.Unmarshal(entry.Usage, &usage)
	meta := map[string]any{
		"hit":                 true,
		"shared":              shared,
		"source_request_id":   entry.SourceRequestID,
		"saved_input_tokens":  usage.Prompt,
		"saved_output_tokens": usage.Completion,
	}
	if entry.CostAvailable {
		meta["saved_cost_micros"] = entry.CostMicros
		meta["currency"] = entry.Currency
	}
	return meta
}

// sortedKeys 仅供测试打印稳定输出。
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
