package repository

import (
	"encoding/json"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/llmusage"
)

// IntegrationUsage exposes only native, verified counts. A missing counter is
// null, including when billing stored a default zero. Cache is an input subset.
type IntegrationUsage struct {
	MeasurementState      string `json:"measurement_state"`
	UsageSource           string `json:"usage_source"`
	InputTokens           *int64 `json:"input_tokens"`
	OutputTokens          *int64 `json:"output_tokens"`
	CacheReadInputTokens  *int64 `json:"cache_read_input_tokens"`
	CacheWriteInputTokens *int64 `json:"cache_write_input_tokens"`
}

// The platform DTO accepts at most this many tokens per native field.
const integrationMaxTokens int64 = 1_000_000_000_000

func projectIntegrationUsage(source string, evidence []byte, loggedInput, loggedOutput *int64, estimated bool) IntegrationUsage {
	unknown := IntegrationUsage{MeasurementState: "uncollected", UsageSource: "unverified"}
	if estimated || (source != "upstream" && source != "upstream_total_adjusted") {
		return unknown
	}
	for _, n := range []*int64{loggedInput, loggedOutput} {
		if n != nil && (*n < 0 || *n > integrationMaxTokens) {
			return unknown
		}
	}
	var proof struct {
		Source    string          `json:"usage_source"`
		Usage     json.RawMessage `json:"upstream_usage"`
		Available *bool           `json:"upstream_usage_available"`
	}
	if json.Unmarshal(evidence, &proof) != nil || proof.Source != source || (proof.Available != nil && !*proof.Available) {
		return unknown
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(proof.Usage, &fields) != nil || fields == nil {
		return unknown
	}
	valid := true
	// Access only recognized numeric paths. Unknown upstream extension fields are
	// never reflected into the public DTO; explicit null means absent.
	count := func(path string) *int64 {
		obj := fields
		parts := strings.Split(path, ".")
		for i, key := range parts {
			raw, ok := obj[key]
			if !ok || string(raw) == "null" {
				return nil
			}
			if i == len(parts)-1 {
				var n int64
				if json.Unmarshal(raw, &n) != nil || n < 0 || n > integrationMaxTokens {
					valid = false
					return nil
				}
				return &n
			}
			var nested map[string]json.RawMessage
			if json.Unmarshal(raw, &nested) != nil || nested == nil {
				valid = false
				return nil
			}
			obj = nested
		}
		return nil
	}
	equalAliases := func(paths ...string) *int64 {
		var n *int64
		for _, path := range paths {
			v := count(path)
			if v != nil {
				if n != nil && *n != *v {
					valid = false
				}
				n = v
			}
		}
		return n
	}
	read := equalAliases("cache_read_input_tokens", "prompt_cache_hit_tokens", "cached_tokens", "input_cached_tokens", "prompt_tokens_details.cached_tokens", "input_tokens_details.cached_tokens", "input_tokens_details.cache_read_tokens")
	write := equalAliases("cache_creation_input_tokens", "prompt_tokens_details.cache_creation_tokens", "prompt_tokens_details.cache_creation_input_tokens", "prompt_tokens_details.cached_creation_tokens", "prompt_tokens_details.cache_write_tokens", "input_tokens_details.cache_creation_tokens", "input_tokens_details.cache_creation_input_tokens", "input_tokens_details.cached_creation_tokens", "input_tokens_details.cache_write_tokens")
	sum := func(values ...*int64) *int64 {
		var total int64
		for _, v := range values {
			if v != nil {
				if *v > integrationMaxTokens-total {
					valid = false
					return nil
				}
				total += *v
			}
		}
		return &total
	}
	input := count("prompt_tokens")
	nativeInput := count("input_tokens")
	topRead, topWrite := count("cache_read_input_tokens"), count("cache_creation_input_tokens")
	if nativeInput != nil && (topRead != nil || topWrite != nil) {
		nativeInput = sum(nativeInput, topRead, topWrite)
	}
	if input != nil && nativeInput != nil && *input != *nativeInput {
		valid = false
	}
	if input == nil {
		input = nativeInput
	}
	hit, miss := count("prompt_cache_hit_tokens"), count("prompt_cache_miss_tokens")
	// Cache-read aliases and a present miss are disjoint input subsets.
	// Check only known counters; an absent read remains null in the DTO.
	if input != nil && miss != nil {
		if *miss > *input || (read != nil && *read > *input-*miss) {
			valid = false
		}
	}
	if hit != nil && miss != nil {
		combined := sum(hit, miss)
		if input != nil && combined != nil && *input != *combined {
			valid = false
		}
		if input == nil {
			input = combined
		}
	}
	output := equalAliases("completion_tokens", "output_tokens")
	// Validate even fields that do not enter this minimal DTO.
	_ = count("total_tokens")
	reasoning := equalAliases("completion_tokens_details.reasoning_tokens", "output_tokens_details.reasoning_tokens")
	if reasoning != nil && output != nil && *reasoning > *output {
		valid = false
	}
	if input != nil {
		cached := sum(read, write)
		if cached == nil || *cached > *input {
			valid = false
		}
	}
	if !valid || (input == nil && output == nil) {
		return unknown
	}
	// Reuse the existing accounting normalization only to verify the native row.
	// Its zero defaults, clipped caches and total residual are never projected.
	canonical := llmusage.Canonicalize(append(append([]byte(`{"usage":`), proof.Usage...), '}'))
	if canonical.State != source {
		return unknown
	}
	if (input != nil && loggedInput != nil && *loggedInput != canonical.PromptTokens) || (output != nil && loggedOutput != nil && *loggedOutput != canonical.OutputTokens) {
		return unknown
	}
	return IntegrationUsage{MeasurementState: "actual", UsageSource: source, InputTokens: input, OutputTokens: output, CacheReadInputTokens: read, CacheWriteInputTokens: write}
}
