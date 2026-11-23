package handler

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/billingmedia"
	"strings"
)

type measuredUsageExtensions struct {
	ImageOutputMeasured    bool                             `json:"-"`
	ImageSize              string                           `json:"image_size,omitempty"`
	ImageQuality           string                           `json:"image_quality,omitempty"`
	ImageVariants          []billingmedia.ImageVariantUsage `json:"image_variants,omitempty"`
	ImageOutputTokens      int64                            `json:"image_output_tokens,omitempty"`
	ImageInputTokens       int64                            `json:"image_input_tokens,omitempty"`
	CachedImageInputTokens int64                            `json:"cached_image_input_tokens,omitempty"`
	ImageCountMeasured     bool                             `json:"image_count_measured,omitempty"`
	ImageCount             int64                            `json:"image_count,omitempty"`
	ToolCalls              map[string]int64                 `json:"tool_calls,omitempty"`
}

type toolUsageEnvelope struct {
	Usage struct {
		PromptDetails     imageTokenDetails `json:"prompt_tokens_details"`
		InputDetails      imageTokenDetails `json:"input_tokens_details"`
		OutputDetails     imageTokenDetails `json:"output_tokens_details"`
		CompletionDetails imageTokenDetails `json:"completion_tokens_details"`
		ImageCount        *int64            `json:"image_count"`
		ToolCalls         map[string]int64  `json:"tool_calls"`
		ServerToolUse     map[string]int64  `json:"server_tool_use"`
	} `json:"usage"`
	ToolUsage struct {
		WebSearch struct {
			NumRequests *int64 `json:"num_requests"`
		} `json:"web_search"`
	} `json:"tool_usage"`
	ImageCount    *int64                           `json:"image_count"`
	ImageSize     string                           `json:"image_size"`
	ImageQuality  string                           `json:"image_quality"`
	ImageVariants []billingmedia.ImageVariantUsage `json:"image_variants"`
	Candidates    []struct {
		Grounding struct {
			Queries []string `json:"webSearchQueries"`
		} `json:"groundingMetadata"`
	} `json:"candidates"`
	Data []struct {
		URL string `json:"url"`
		B64 string `json:"b64_json"`
	} `json:"data"`
	Output       []serverToolItem `json:"output"`
	Content      []serverToolItem `json:"content"`
	Item         *serverToolItem  `json:"item"`
	ContentBlock *serverToolItem  `json:"content_block"`
	Response     json.RawMessage  `json:"response"`
}
type imageTokenDetails struct {
	ImageTokens         *int64 `json:"image_tokens"`
	CachedTokensDetails struct {
		ImageTokens *int64 `json:"image_tokens"`
	} `json:"cached_tokens_details"`
}
type serverToolItem struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

func billableServerToolName(item serverToolItem) string {
	switch item.Type {
	case "web_search_call":
		return "web_search"
	case "web_search_preview_call":
		return "web_search_preview"
	case "file_search_call":
		return "file_search"
	case "image_generation_call":
		return "image_generation"
	case "server_tool_use":
		if strings.HasPrefix(item.Name, "web_search") {
			return "web_search"
		}
		if strings.HasPrefix(item.Name, "web_fetch") {
			return "web_fetch"
		}
	}
	return ""
}

func responseUsageExtensions(response []byte) measuredUsageExtensions {
	result, _ := parseResponseUsageExtensions(response)
	return result
}

func parseResponseUsageExtensions(response []byte) (measuredUsageExtensions, bool) {
	result := measuredUsageExtensions{}
	var raw toolUsageEnvelope
	if len(response) == 0 || json.Unmarshal(response, &raw) != nil {
		return result, false
	}
	if valueOrZero(raw.Usage.ImageCount) < 0 || valueOrZero(raw.ImageCount) < 0 {
		return result, true
	}
	for _, value := range []*int64{raw.Usage.PromptDetails.ImageTokens, raw.Usage.InputDetails.ImageTokens, raw.Usage.PromptDetails.CachedTokensDetails.ImageTokens, raw.Usage.InputDetails.CachedTokensDetails.ImageTokens} {
		if value != nil && (*value < 0 || *value > maxExactTokenCount) {
			return result, true
		}
	}
	result.ImageSize = billingmedia.Dimension(raw.ImageSize)
	result.ImageQuality = billingmedia.Dimension(raw.ImageQuality)
	result.ImageVariants = raw.ImageVariants
	if !billingmedia.ValidDimension(result.ImageSize, false) || !billingmedia.ValidDimension(result.ImageQuality, false) || len(result.ImageVariants) > 128 {
		return result, true
	}
	for _, v := range result.ImageVariants {
		if v.Count < 0 || !billingmedia.ValidDimension(v.Size, false) || !billingmedia.ValidDimension(v.Quality, false) {
			return result, true
		}
	}
	for _, v := range []*int64{raw.Usage.OutputDetails.ImageTokens, raw.Usage.CompletionDetails.ImageTokens} {
		if v != nil && (*v < 0 || *v > maxExactTokenCount) {
			return result, true
		}
	}
	result.ImageOutputMeasured = raw.Usage.OutputDetails.ImageTokens != nil || raw.Usage.CompletionDetails.ImageTokens != nil
	result.ImageOutputTokens = maxTokenValues(raw.Usage.OutputDetails.ImageTokens, raw.Usage.CompletionDetails.ImageTokens)
	result.ImageInputTokens = maxTokenValues(raw.Usage.PromptDetails.ImageTokens, raw.Usage.InputDetails.ImageTokens)
	result.CachedImageInputTokens = maxTokenValues(raw.Usage.PromptDetails.CachedTokensDetails.ImageTokens, raw.Usage.InputDetails.CachedTokensDetails.ImageTokens)
	if result.CachedImageInputTokens > result.ImageInputTokens {
		return result, true
	}
	result.ImageCountMeasured = raw.Usage.ImageCount != nil || raw.ImageCount != nil || raw.Data != nil
	result.ImageCount = maxInt64(valueOrZero(raw.Usage.ImageCount), valueOrZero(raw.ImageCount))
	var dataCount int64
	for _, item := range raw.Data {
		if item.URL != "" || item.B64 != "" {
			dataCount++
		}
	}
	result.ImageCount = maxInt64(result.ImageCount, dataCount)
	// Explicit usage counters and output evidence describe the same calls:
	// use their maximum, never add the two representations together.
	counts := map[string]int64{}
	for name, count := range raw.Usage.ToolCalls {
		if count < 0 || count > maxExactTokenCount || len(name) > 96 {
			return result, true
		}
		counts[name] = count
	}
	for name, count := range raw.Usage.ServerToolUse {
		if count < 0 || count > maxExactTokenCount {
			return result, true
		}
		switch name {
		case "web_search_requests":
			name = "web_search"
		case "web_fetch_requests":
			name = "web_fetch"
		default:
			continue
		}
		counts[name] = maxInt64(counts[name], count)
	}
	items := append(raw.Output, raw.Content...)
	if raw.Item != nil {
		items = append(items, *raw.Item)
	}
	if raw.ContentBlock != nil {
		items = append(items, *raw.ContentBlock)
	}
	evidence := map[string]int64{}
	seen := map[string]bool{}
	for _, item := range items {
		name := billableServerToolName(item)
		if name == "" {
			continue
		}
		if item.Status == "failed" || item.Status == "incomplete" {
			continue
		}
		if item.ID != "" {
			if seen[item.ID] {
				continue
			}
			seen[item.ID] = true
		}
		evidence[name]++
	}
	for name, count := range evidence {
		counts[name] = maxInt64(counts[name], count)
	}
	if raw.ToolUsage.WebSearch.NumRequests != nil {
		count := *raw.ToolUsage.WebSearch.NumRequests
		if count < 0 || count > maxExactTokenCount {
			return result, true
		}
		counts["bing_web_search"] = count
		delete(counts, "web_search")
		delete(counts, "web_search_preview")
	}
	queries := map[string]bool{}
	for _, candidate := range raw.Candidates {
		for _, query := range candidate.Grounding.Queries {
			if query != "" {
				queries[query] = true
			}
		}
	}
	if len(queries) > 0 {
		counts["google_search"] = maxInt64(counts["google_search"], int64(len(queries)))
		counts["google_search_grounded_prompt"] = maxInt64(counts["google_search_grounded_prompt"], 1)
	}
	if len(counts) > 64 || result.ImageCount > maxExactTokenCount {
		return result, true
	}
	if len(counts) > 0 {
		result.ToolCalls = counts
	}
	if len(raw.Response) > 0 {
		nested, invalid := parseResponseUsageExtensions(raw.Response)
		if invalid {
			return result, true
		}
		result.ImageCount = maxInt64(result.ImageCount, nested.ImageCount)
		result.ImageInputTokens = maxInt64(result.ImageInputTokens, nested.ImageInputTokens)
		result.CachedImageInputTokens = maxInt64(result.CachedImageInputTokens, nested.CachedImageInputTokens)
		result.ImageOutputTokens = maxInt64(result.ImageOutputTokens, nested.ImageOutputTokens)
		result.ImageOutputMeasured = result.ImageOutputMeasured || nested.ImageOutputMeasured
		if nested.ImageSize != "" {
			result.ImageSize = nested.ImageSize
		}
		if nested.ImageQuality != "" {
			result.ImageQuality = nested.ImageQuality
		}
		if len(nested.ImageVariants) > 0 {
			result.ImageVariants = nested.ImageVariants
		}
		if result.CachedImageInputTokens > result.ImageInputTokens {
			return result, true
		}
		result.ImageCountMeasured = result.ImageCountMeasured || nested.ImageCountMeasured
		for name, count := range nested.ToolCalls {
			if result.ToolCalls == nil {
				result.ToolCalls = map[string]int64{}
			}
			result.ToolCalls[name] = maxInt64(result.ToolCalls[name], count)
		}
	}
	if _, azure := result.ToolCalls["bing_web_search"]; azure {
		delete(result.ToolCalls, "web_search")
		delete(result.ToolCalls, "web_search_preview")
	}
	return result, false
}

func canonicalizeResponseUsage(response []byte) canonicalResponseUsage {
	result := canonicalizeTokenUsage(response)
	extras, invalid := parseResponseUsageExtensions(response)
	if invalid {
		return canonicalResponseUsage{State: "invalid"}
	}
	result.ImageCount = extras.ImageCount
	result.ToolCalls = extras.ToolCalls
	result.ImageInputTokens = extras.ImageInputTokens
	result.CachedImageInputTokens = extras.CachedImageInputTokens
	result.ImageOutputTokens = extras.ImageOutputTokens
	return result
}

func extendedBillingUsage(response []byte) map[string]any {
	usage := canonicalizeResponseUsage(response)
	result := map[string]any{
		"prompt_tokens": usage.PromptTokens, "cached_input_tokens": usage.CachedInputTokens,
		"cache_write_input_tokens": usage.CacheWriteTokens, "output_tokens": usage.OutputTokens,
		"reasoning_tokens": usage.ReasoningTokens, "image_count": usage.ImageCount,
		"image_input_tokens": usage.ImageInputTokens, "cached_image_input_tokens": usage.CachedImageInputTokens, "image_output_tokens": usage.ImageOutputTokens,
	}
	if len(usage.ToolCalls) > 0 {
		result["tool_calls"] = usage.ToolCalls
	}
	return result
}

// The stream accumulator sees repeated snapshots and item lifecycle events.
// Count stable upstream item IDs once, and reconcile them with usage totals.
func (a *liveStreamAccumulator) observeBillingTools(event relay.StreamEvent) {
	if a == nil || len(event.Raw) == 0 {
		return
	}
	var raw toolUsageEnvelope
	if json.Unmarshal(event.Raw, &raw) != nil {
		return
	}
	extras, invalid := parseResponseUsageExtensions(event.Raw)
	if invalid {
		return
	}
	if a.billingToolCounts == nil {
		a.billingToolCounts = map[string]int64{}
	}
	for name, count := range extras.ToolCalls {
		a.billingToolCounts[name] = maxInt64(a.billingToolCounts[name], count)
	}
	items := append(raw.Output, raw.Content...)
	if raw.Item != nil {
		items = append(items, *raw.Item)
	}
	if raw.ContentBlock != nil {
		items = append(items, *raw.ContentBlock)
	}
	if len(raw.Response) > 0 {
		var nested toolUsageEnvelope
		if json.Unmarshal(raw.Response, &nested) == nil {
			items = append(items, nested.Output...)
		}
	}
	if a.billingToolIDs == nil {
		a.billingToolIDs = map[string]string{}
	}
	for _, item := range items {
		name := billableServerToolName(item)
		if name != "" && item.ID != "" && len(a.billingToolIDs) < 4096 && item.Status != "failed" {
			a.billingToolIDs[item.ID] = name
		}
	}
	counts := map[string]int64{}
	for _, name := range a.billingToolIDs {
		counts[name]++
	}
	for name, count := range counts {
		a.billingToolCounts[name] = maxInt64(a.billingToolCounts[name], count)
	}
	// Azure's transaction counter is authoritative for the same search calls,
	// including an explicit zero. Keep this suppression across later events.
	if _, azure := a.billingToolCounts["bing_web_search"]; azure {
		delete(a.billingToolCounts, "web_search")
		delete(a.billingToolCounts, "web_search_preview")
	}
}

func addStreamBillingTools(body []byte, counts map[string]int64) []byte {
	if len(counts) == 0 {
		return body
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(body, &root) != nil {
		return body
	}
	usage := map[string]json.RawMessage{}
	if raw := root["usage"]; len(raw) > 0 {
		if json.Unmarshal(raw, &usage) != nil {
			return body
		}
	}
	usage["tool_calls"], _ = json.Marshal(counts)
	root["usage"], _ = json.Marshal(usage)
	encoded, err := json.Marshal(root)
	if err != nil {
		return body
	}
	return encoded
}
