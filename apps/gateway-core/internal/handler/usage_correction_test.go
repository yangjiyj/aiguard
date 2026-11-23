package handler

import (
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"testing"
)

func TestLiveFinalUsageReplacesHighWaterMark(t *testing.T) {
	a := newLiveStreamAccumulator()
	a.observeEvent(relay.StreamEvent{Type: relay.EventMessageStart, Usage: &relay.Usage{InputTokens: 100, OutputTokens: 20, CacheReadInputTokens: 80}})
	a.observeEvent(relay.StreamEvent{Type: relay.EventUsageFinal, Usage: &relay.Usage{InputTokens: 10, OutputTokens: 0, CacheReadInputTokens: 0}})
	if a.usage.InputTokens != 10 || a.usage.OutputTokens != 0 || a.usage.CacheReadInputTokens != 0 {
		t.Fatalf("%+v", a.usage)
	}
	a.observeEvent(relay.StreamEvent{Type: relay.EventCacheUsage, CacheUsage: &relay.CacheUsage{ReadTokens: 2}})
	if a.usage.InputTokens != 10 || a.usage.CacheReadInputTokens != 2 {
		t.Fatalf("%+v", a.usage)
	}
}
