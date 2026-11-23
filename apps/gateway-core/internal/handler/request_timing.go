package handler

import (
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// 同一份 duration 同时计入进程指标与请求审计，累计时保留亚毫秒精度。
func recordSecurityTiming(envelope *modelrouter.RequestEnvelope, metrics *relay.Metrics, name string, elapsed time.Duration) {
	if metrics != nil {
		metrics.Add(name, durationMetricValue(elapsed))
	}
	if envelope == nil {
		return
	}
	if envelope.Timing == nil {
		envelope.Timing = make(map[string]int64)
	}
	envelope.Timing[name] += int64(elapsed)
}

// 每次尝试重新采集首事件与生成时间；前置处理仍使用首次发送的口径。
func recordPreUpstreamTiming(envelope *modelrouter.RequestEnvelope, started time.Time) {
	if envelope == nil {
		return
	}
	envelope.UpstreamTTFTMs = nil
	// 路由重试会复制 envelope，独立副本避免失败尝试污染下一次生成时间。
	timing := make(map[string]int64, len(envelope.Timing)+1)
	for key, value := range envelope.Timing {
		if key != "generation_ms" {
			timing[key] = value
		}
	}
	envelope.Timing = timing
	if _, exists := timing["pre_upstream_ms"]; !exists && !envelope.RequestStartedAt.IsZero() {
		timing["pre_upstream_ms"] = int64(started.Sub(envelope.RequestStartedAt))
	}
}

// 没有可观测首事件时不推测生成耗时；只在上游结束时记录一次。
func recordGenerationTiming(envelope *modelrouter.RequestEnvelope, started, ended time.Time) {
	if envelope == nil || envelope.UpstreamTTFTMs == nil {
		return
	}
	if envelope.Timing == nil {
		envelope.Timing = make(map[string]int64)
	}
	if _, exists := envelope.Timing["generation_ms"]; exists {
		return
	}
	elapsed := ended.Sub(started) - time.Duration(*envelope.UpstreamTTFTMs)*time.Millisecond
	if elapsed < 0 {
		return
	}
	envelope.Timing["generation_ms"] = int64(elapsed)
}

func withRequestTiming(envelope *modelrouter.RequestEnvelope, audit *AuditResult) *AuditResult {
	if envelope == nil || len(envelope.Timing) == 0 {
		return audit
	}
	if audit == nil {
		audit = &AuditResult{}
	}
	if audit.ResponseMetadata == nil {
		audit.ResponseMetadata = make(map[string]interface{})
	}
	timing := make(map[string]int64, len(envelope.Timing))
	for name, elapsed := range envelope.Timing {
		timing[name] = time.Duration(elapsed).Milliseconds()
	}
	audit.ResponseMetadata["timing"] = timing
	return audit
}
