package handler

import (
	"math"

	"github.com/yangjiyj/aiguard/packages/shared-go/llmusage"
)

const maxExactTokenCount int64 = llmusage.MaxExactTokenCount

type canonicalResponseUsage struct {
	PromptTokens           int64
	CachedInputTokens      int64
	CacheWriteTokens       int64
	OutputTokens           int64
	ReasoningTokens        int64
	ImageInputTokens       int64
	CachedImageInputTokens int64
	ImageOutputTokens      int64
	ImageCount             int64
	ToolCalls              map[string]int64
	State                  string
}

// canonicalizeTokenUsage 委托给 packages/shared-go/llmusage（P1 把原实现原样迁出，供正向代理复用）。
// 口径与之前完全一致：PromptTokens 含全部计入额度的输入，缓存与推理是计价分层用的子集。
func canonicalizeTokenUsage(response []byte) canonicalResponseUsage {
	usage := llmusage.Canonicalize(response)
	return canonicalResponseUsage{
		PromptTokens: usage.PromptTokens, CachedInputTokens: usage.CachedInputTokens, CacheWriteTokens: usage.CacheWriteTokens,
		OutputTokens: usage.OutputTokens, ReasoningTokens: usage.ReasoningTokens, State: usage.State,
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
