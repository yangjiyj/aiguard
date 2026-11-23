package handler

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestMapForwardProxySummaryIncludesRetentionOverview(t *testing.T) {
	bucket := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	info := mapForwardProxySummaryToInfo(repository.ForwardProxyAccessSummary{
		Total:            6,
		UniqueModelCount: 2,
		EvidenceQuality: repository.ForwardProxyEvidenceQuality{
			CompleteCount:     3,
			RequestOnlyCount:  1,
			ResponseOnlyCount: 1,
			MetadataOnlyCount: 1,
		},
		Timeline: []repository.ForwardProxyAccessTimelinePoint{
			{Bucket: bucket, TotalCount: 6, NormalCount: 3, RiskCount: 2, BlockedCount: 1},
		},
		TopRiskCategories: []repository.ForwardProxyRiskCategory{
			{Name: "secret", Count: 2},
		},
	})

	if info.UniqueModelCount != 2 {
		t.Fatalf("unique model count=%d want 2", info.UniqueModelCount)
	}
	if info.EvidenceQuality.CompleteCount != 3 || info.EvidenceQuality.MetadataOnlyCount != 1 {
		t.Fatalf("unexpected evidence quality: %+v", info.EvidenceQuality)
	}
	if len(info.Timeline) != 1 || info.Timeline[0].Bucket != "2026-07-11T08:00:00Z" || info.Timeline[0].BlockedCount != 1 {
		t.Fatalf("unexpected timeline: %+v", info.Timeline)
	}
	if len(info.TopRiskCategories) != 1 || info.TopRiskCategories[0].Name != "secret" || info.TopRiskCategories[0].Count != 2 {
		t.Fatalf("unexpected risk categories: %+v", info.TopRiskCategories)
	}
}

func TestMapForwardProxySummarySerializesEmptyOverviewArrays(t *testing.T) {
	info := mapForwardProxySummaryToInfo(repository.ForwardProxyAccessSummary{})
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	jsonText := string(raw)
	if !strings.Contains(jsonText, `"timeline":[]`) {
		t.Fatalf("timeline must serialize as an empty array: %s", jsonText)
	}
	if !strings.Contains(jsonText, `"top_risk_categories":[]`) {
		t.Fatalf("top_risk_categories must serialize as an empty array: %s", jsonText)
	}
}
