package modelops

import "time"

// MinMetricSamples 是汇总指标的最小有效样本数；不足时返回 null，避免几条请求给出误导性数字。
const MinMetricSamples = 5

func gated(v *float64, n int64) *float64 {
	if v == nil || n < MinMetricSamples {
		return nil
	}
	return v
}

// portalPerformanceWindow 返回门户窗口小时数、趋势桶宽（秒）和桶数；只允许 24 与 168。
func portalPerformanceWindow(hours int) (int, int, int, error) {
	switch hours {
	case 0, 168:
		return 168, 21600, 28, nil
	case 24:
		return 24, 3600, 24, nil
	}
	return 0, 0, 0, ErrInvalid
}

type ErrorBreakdown struct {
	HTTP5xx     int64 `json:"http_5xx"`
	RateLimited int64 `json:"rate_limited"`
	Rejected    int64 `json:"rejected"`
	Network     int64 `json:"network"`
	Other       int64 `json:"other"`
}

type ProviderModelStat struct {
	ModelID     string   `json:"model_id"`
	ModelName   string   `json:"model_name"`
	Attempts    int64    `json:"attempts"`
	SuccessRate *float64 `json:"success_rate"`
}

type ProviderPoint struct {
	At           time.Time `json:"at"`
	Attempts     int64     `json:"attempts"`
	SuccessRate  *float64  `json:"success_rate"`
	LatencyP95MS *float64  `json:"latency_p95_ms"`
}

type ProviderStat struct {
	ProviderID   string              `json:"provider_id"`
	ProviderName string              `json:"provider_name"`
	Attempts     int64               `json:"attempts"`
	Successes    int64               `json:"successes"`
	SuccessRate  *float64            `json:"success_rate"`
	LatencyP50MS *float64            `json:"latency_p50_ms"`
	LatencyP95MS *float64            `json:"latency_p95_ms"`
	TTFTP50MS    *float64            `json:"ttft_p50_ms"`
	Errors       ErrorBreakdown      `json:"errors"`
	FallbackOut  int64               `json:"fallback_out"`
	FallbackIn   int64               `json:"fallback_in"`
	ModelCount   int64               `json:"model_count"`
	Models       []ProviderModelStat `json:"models"`
	Hourly       []ProviderPoint     `json:"hourly"`
}

type ProviderTotals struct {
	Attempts    int64    `json:"attempts"`
	SuccessRate *float64 `json:"success_rate"`
	Fallbacks   int64    `json:"fallbacks"`
	TTFTP50MS   *float64 `json:"ttft_p50_ms"`
}

type ProviderMonitor struct {
	Items       []ProviderStat `json:"items"`
	Totals      ProviderTotals `json:"totals"`
	WindowHours int            `json:"window_hours"`
	GeneratedAt time.Time      `json:"generated_at"`
}

type PerformancePoint struct {
	At          time.Time `json:"at"`
	Samples     int64     `json:"samples"`
	SuccessRate *float64  `json:"success_rate"`
	TTFTP50MS   *float64  `json:"ttft_p50_ms"`
	TPSP50      *float64  `json:"tps_p50"`
}

// ModelPerformance 是门户可见的按模型聚合视图，刻意不含任何渠道字段。
type ModelPerformance struct {
	ModelName    string             `json:"model_name"`
	Protocols    []string           `json:"protocols"`
	Samples      int64              `json:"samples"`
	SuccessRate  *float64           `json:"success_rate"`
	TTFTP50MS    *float64           `json:"ttft_p50_ms"`
	TTFTP95MS    *float64           `json:"ttft_p95_ms"`
	TPSP50       *float64           `json:"tps_p50"`
	LatencyP50MS *float64           `json:"latency_p50_ms"`
	LatencyP95MS *float64           `json:"latency_p95_ms"`
	Hourly       []PerformancePoint `json:"hourly"`
}

type ModelPerformanceReport struct {
	Data        []ModelPerformance `json:"data"`
	WindowHours int                `json:"window_hours"`
	GeneratedAt time.Time          `json:"generated_at"`
}
