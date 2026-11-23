package repository

import "encoding/json"

// RequestTiming 仅用于管理员接口；空指针表示未采集，不能用零代替。
type RequestTiming struct {
	InputSecurityMS    *int64   `json:"input_security_ms"`
	OutputSecurityMS   *int64   `json:"output_security_ms"`
	PreUpstreamMS      *int64   `json:"pre_upstream_ms"`
	GenerationMS       *int64   `json:"generation_ms"`
	UpstreamTTFTMS     *int64   `json:"upstream_ttft_ms"`
	LatencyMS          int      `json:"latency_ms"`
	OutputTokensPerSec *float64 `json:"output_tokens_per_sec"`
}

func parseRequestTiming(raw []byte, latency int, ttft *int64, outputTokens int64) RequestTiming {
	result := RequestTiming{LatencyMS: latency, UpstreamTTFTMS: ttft}
	var values map[string]json.RawMessage
	// 独立读取每个数值，历史脏字段不能使其他有效分段一起丢失。
	if json.Unmarshal(raw, &values) == nil {
		for name, target := range map[string]**int64{"input_security_ms": &result.InputSecurityMS, "output_security_ms": &result.OutputSecurityMS, "pre_upstream_ms": &result.PreUpstreamMS, "generation_ms": &result.GenerationMS} {
			var value int64
			if data := values[name]; len(data) > 0 && string(data) != "null" && json.Unmarshal(data, &value) == nil && value >= 0 {
				*target = &value
			}
		}
	}
	var denominator int64
	if result.GenerationMS != nil {
		denominator = *result.GenerationMS
	} else if ttft != nil && *ttft >= 0 {
		denominator = int64(latency) - *ttft
	}
	if denominator >= 200 && outputTokens > 0 {
		speed := float64(outputTokens) * 1000 / float64(denominator)
		result.OutputTokensPerSec = &speed
	}
	return result
}
