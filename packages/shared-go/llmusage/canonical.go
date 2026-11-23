// Package llmusage 是网关与正向代理共用的大模型 token 用量规范化解析。
// 原实现位于 gateway-core internal/handler/usage_canonical.go，P1 原样迁出以便 proxy-server 复用，
// 算法与口径未改，gateway-core 侧改为调用本包。
package llmusage

import (
	"encoding/json"
	"math"
)

const MaxExactTokenCount int64 = 1<<53 - 1

// Usage 是规范化后的 token 用量。PromptTokens 含全部计入额度的输入；缓存与推理是子集。
// State：upstream / upstream_total_adjusted 为可信用量，missing 为没有 usage，invalid 为数值非法。
type Usage struct {
	PromptTokens      int64
	CachedInputTokens int64
	CacheWriteTokens  int64
	OutputTokens      int64
	ReasoningTokens   int64
	State             string
}

type upstreamUsageFields struct {
	PromptTokens             *int64 `json:"prompt_tokens"`
	CompletionTokens         *int64 `json:"completion_tokens"`
	InputTokens              *int64 `json:"input_tokens"`
	OutputTokens             *int64 `json:"output_tokens"`
	TotalTokens              *int64 `json:"total_tokens"`
	CachedTokens             *int64 `json:"cached_tokens"`
	InputCachedTokens        *int64 `json:"input_cached_tokens"`
	PromptCacheHitTokens     *int64 `json:"prompt_cache_hit_tokens"`
	PromptCacheMissTokens    *int64 `json:"prompt_cache_miss_tokens"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens"`
	PromptTokensDetails      struct {
		CachedTokens             *int64 `json:"cached_tokens"`
		CacheCreationTokens      *int64 `json:"cache_creation_tokens"`
		CachedCreationTokens     *int64 `json:"cached_creation_tokens"`
		CacheWriteTokens         *int64 `json:"cache_write_tokens"`
		CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
	} `json:"prompt_tokens_details"`
	InputTokensDetails struct {
		CachedTokens             *int64 `json:"cached_tokens"`
		CacheReadTokens          *int64 `json:"cache_read_tokens"`
		CacheCreationTokens      *int64 `json:"cache_creation_tokens"`
		CachedCreationTokens     *int64 `json:"cached_creation_tokens"`
		CacheWriteTokens         *int64 `json:"cache_write_tokens"`
		CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
	} `json:"input_tokens_details"`
	CompletionTokensDetails struct {
		ReasoningTokens *int64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
	OutputTokensDetails struct {
		ReasoningTokens *int64 `json:"reasoning_tokens"`
	} `json:"output_tokens_details"`
}

// Canonicalize is the only provider-usage accounting parser (moved verbatim from
// gateway-core so the forward proxy reuses it instead of re-implementing it).
// PromptTokens includes every input category that consumes quota. Cache and
// reasoning fields remain subsets used by billing price tiers.
func Canonicalize(response []byte) Usage {
	missing := Usage{State: "missing"}
	var root struct {
		Usage json.RawMessage `json:"usage"`
	}
	if len(response) == 0 || json.Unmarshal(response, &root) != nil || len(root.Usage) == 0 || string(root.Usage) == "null" {
		return missing
	}
	var raw upstreamUsageFields
	if err := json.Unmarshal(root.Usage, &raw); err != nil {
		return Usage{State: "invalid"}
	}
	all := []*int64{
		raw.PromptTokens, raw.CompletionTokens, raw.InputTokens, raw.OutputTokens, raw.TotalTokens,
		raw.CachedTokens, raw.InputCachedTokens, raw.PromptCacheHitTokens, raw.PromptCacheMissTokens,
		raw.CacheCreationInputTokens, raw.CacheReadInputTokens,
		raw.PromptTokensDetails.CachedTokens, raw.PromptTokensDetails.CacheCreationTokens,
		raw.PromptTokensDetails.CacheCreationInputTokens, raw.InputTokensDetails.CachedTokens,
		raw.InputTokensDetails.CacheReadTokens, raw.InputTokensDetails.CacheCreationTokens,
		raw.InputTokensDetails.CacheCreationInputTokens, raw.PromptTokensDetails.CachedCreationTokens, raw.PromptTokensDetails.CacheWriteTokens,
		raw.InputTokensDetails.CachedCreationTokens, raw.InputTokensDetails.CacheWriteTokens,
		raw.CompletionTokensDetails.ReasoningTokens, raw.OutputTokensDetails.ReasoningTokens,
	}
	for _, value := range all {
		if value != nil && (*value < 0 || *value > MaxExactTokenCount) {
			return Usage{State: "invalid"}
		}
	}

	cacheRead := maxTokenValues(
		raw.CacheReadInputTokens, raw.PromptCacheHitTokens, raw.CachedTokens, raw.InputCachedTokens,
		raw.PromptTokensDetails.CachedTokens, raw.InputTokensDetails.CachedTokens,
		raw.InputTokensDetails.CacheReadTokens,
	)
	cacheWrite := maxTokenValues(
		raw.CacheCreationInputTokens, raw.PromptTokensDetails.CacheCreationTokens,
		raw.PromptTokensDetails.CacheCreationInputTokens, raw.InputTokensDetails.CacheCreationTokens,
		raw.InputTokensDetails.CacheCreationInputTokens, raw.PromptTokensDetails.CachedCreationTokens, raw.PromptTokensDetails.CacheWriteTokens,
		raw.InputTokensDetails.CachedCreationTokens, raw.InputTokensDetails.CacheWriteTokens,
	)

	promptCandidate, promptPresent := tokenValue(raw.PromptTokens)
	hit, hitPresent := tokenValue(raw.PromptCacheHitTokens)
	miss, missPresent := tokenValue(raw.PromptCacheMissTokens)
	if promptPresent {
		if promptCandidate == 0 && (hitPresent || missPresent) {
			var ok bool
			promptCandidate, ok = checkedTokenSum(hit, miss)
			if !ok {
				return Usage{State: "invalid"}
			}
		}
	}
	inputCandidate, inputPresent := tokenValue(raw.InputTokens)
	if inputPresent {
		// Anthropic top-level cache counters are additive to uncached input.
		if raw.CacheReadInputTokens != nil || raw.CacheCreationInputTokens != nil {
			var ok bool
			inputCandidate, ok = checkedTokenSum(inputCandidate, valueOrZero(raw.CacheReadInputTokens), valueOrZero(raw.CacheCreationInputTokens))
			if !ok {
				return Usage{State: "invalid"}
			}
		}
	}
	prompt := promptCandidate
	if inputPresent && (!promptPresent || inputCandidate > prompt) {
		prompt = inputCandidate
	}
	promptPresent = promptPresent || inputPresent
	if !promptPresent && (hitPresent || missPresent) {
		var ok bool
		prompt, ok = checkedTokenSum(hit, miss)
		if !ok {
			return Usage{State: "invalid"}
		}
		promptPresent = true
	} else if !promptPresent && (raw.CacheReadInputTokens != nil || raw.CacheCreationInputTokens != nil) {
		var ok bool
		prompt, ok = checkedTokenSum(valueOrZero(raw.CacheReadInputTokens), valueOrZero(raw.CacheCreationInputTokens))
		if !ok {
			return Usage{State: "invalid"}
		}
		promptPresent = true
	}

	completionCandidate, completionPresent := tokenValue(raw.CompletionTokens)
	outputCandidate, outputPresent := tokenValue(raw.OutputTokens)
	output := completionCandidate
	if outputPresent && (!completionPresent || outputCandidate > output) {
		output = outputCandidate
	}
	outputPresent = completionPresent || outputPresent
	total, totalPresent := tokenValue(raw.TotalTokens)
	if !promptPresent && !outputPresent && !totalPresent {
		return missing
	}
	componentTotal, ok := checkedTokenSum(prompt, output)
	if !ok {
		return Usage{State: "invalid"}
	}
	state := "upstream"
	if totalPresent {
		if !promptPresent && !outputPresent {
			prompt = total
		} else if total < componentTotal {
			return Usage{State: "invalid"}
		} else if total > componentTotal {
			prompt, ok = checkedTokenSum(prompt, total-componentTotal)
			if !ok {
				return Usage{State: "invalid"}
			}
			state = "upstream_total_adjusted"
		}
	}
	if cacheRead > prompt {
		cacheRead = prompt
	}
	if cacheWrite > prompt-cacheRead {
		cacheWrite = prompt - cacheRead
	}
	reasoning := maxTokenValues(raw.CompletionTokensDetails.ReasoningTokens, raw.OutputTokensDetails.ReasoningTokens)
	if reasoning > output {
		reasoning = output
	}
	return Usage{
		PromptTokens: prompt, CachedInputTokens: cacheRead, CacheWriteTokens: cacheWrite,
		OutputTokens: output, ReasoningTokens: reasoning, State: state,
	}
}

func tokenValue(value *int64) (int64, bool) {
	if value == nil {
		return 0, false
	}
	return *value, true
}

func valueOrZero(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func maxTokenValues(values ...*int64) int64 {
	var result int64
	for _, value := range values {
		if value != nil && *value > result {
			result = *value
		}
	}
	return result
}

func checkedTokenSum(values ...int64) (int64, bool) {
	var result int64
	for _, value := range values {
		if value < 0 || value > math.MaxInt64-result {
			return 0, false
		}
		result += value
	}
	return result, true
}
