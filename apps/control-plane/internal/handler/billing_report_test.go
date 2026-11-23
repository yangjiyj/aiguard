package handler

import (
	"encoding/csv"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func TestRenderBillingReportCSVSeparatesBillableAndUpstreamAmounts(t *testing.T) {
	summary := &billing.AnalyticsSummary{
		Requests:                  2,
		PromptTokens:              10,
		CachedInputTokens:         2,
		CacheWriteInputTokens:     1,
		OutputTokens:              4,
		ReasoningTokens:           1,
		TotalTokens:               14,
		BillableMicros:            1_250_000,
		UpstreamCostMicros:        1_000_000,
		UpstreamCostKnownRequests: 2,
	}
	sections := []billingReportSection{{
		Dimension: "部门",
		Rows: []billing.AnalyticsBreakdown{{
			ID:                        "dept-internal-id",
			Name:                      "研发部",
			Secondary:                 "研发中心",
			Requests:                  2,
			PromptTokens:              10,
			CachedInputTokens:         2,
			CacheWriteInputTokens:     1,
			OutputTokens:              4,
			ReasoningTokens:           1,
			TotalTokens:               14,
			BillableMicros:            1_250_000,
			UpstreamCostMicros:        1_000_000,
			UpstreamCostKnownRequests: 2,
		}},
	}}

	output, err := renderBillingReportCSV(summary, sections)
	if err != nil {
		t.Fatalf("render report: %v", err)
	}
	csvOutput := string(output)
	for _, expected := range []string{
		"内部结算金额(CNY)",
		"采购成本(CNY)",
		"成本差额(CNY)",
		"缓存命中Token",
		"缓存写入Token",
		"推理Token",
		"研发部",
		"研发中心",
		"1.25",
		"1.00",
		"0.25",
	} {
		if !strings.Contains(csvOutput, expected) {
			t.Fatalf("report missing %q:\n%s", expected, csvOutput)
		}
	}
	if strings.Contains(csvOutput, "dept-internal-id") {
		t.Fatalf("report leaked internal dimension id: %s", csvOutput)
	}
}

func TestBillingReportIncludesApplicationAndAgentDimensions(t *testing.T) {
	want := map[string]bool{"department": false, "user": false, "project": false, "provider": false, "model": false, "agent": false}
	for _, dimension := range billingReportDimensions {
		if _, ok := want[dimension.Key]; ok {
			want[dimension.Key] = true
		}
	}
	for dimension, present := range want {
		if !present {
			t.Fatalf("billing report dimension %q is missing", dimension)
		}
	}
}

func TestRenderBillingReportCSVLeavesUnknownUpstreamCostBlank(t *testing.T) {
	summary := &billing.AnalyticsSummary{
		Requests:       1,
		TotalTokens:    3,
		BillableMicros: 500_000,
		Currency:       "CNY",
	}

	output, err := renderBillingReportCSV(summary, nil)
	if err != nil {
		t.Fatalf("render report: %v", err)
	}
	records, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(output), "\ufeff"))).ReadAll()
	if err != nil {
		t.Fatalf("parse report: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records=%v", records)
	}
	header := map[string]int{}
	for index, column := range records[0] {
		header[column] = index
	}
	for _, column := range []string{"采购成本(CNY)", "成本差额(CNY)"} {
		if records[1][header[column]] != "" {
			t.Fatalf("unknown upstream cost must stay blank for %s: %v", column, records[1])
		}
	}
}

func TestRenderBillingReportCSVLeavesCostDifferenceBlankWhenCoverageIsPartial(t *testing.T) {
	summary := &billing.AnalyticsSummary{
		Requests:                  2,
		BillableMicros:            1_250_000,
		UpstreamCostMicros:        500_000,
		UpstreamCostKnownRequests: 1,
		Currency:                  "CNY",
	}

	output, err := renderBillingReportCSV(summary, nil)
	if err != nil {
		t.Fatalf("render report: %v", err)
	}
	records, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(output), "\ufeff"))).ReadAll()
	if err != nil {
		t.Fatalf("parse report: %v", err)
	}
	header := map[string]int{}
	for index, column := range records[0] {
		header[column] = index
	}
	if records[1][header["采购成本(CNY)"]] != "0.50" {
		t.Fatalf("known upstream cost should remain visible: %v", records[1])
	}
	if records[1][header["成本差额(CNY)"]] != "" {
		t.Fatalf("partial upstream coverage must not show a full-period difference: %v", records[1])
	}
	if records[1][header["上游成本覆盖率"]] != "50.00%" {
		t.Fatalf("coverage=%v, want 50.00%%", records[1][header["上游成本覆盖率"]])
	}
}
