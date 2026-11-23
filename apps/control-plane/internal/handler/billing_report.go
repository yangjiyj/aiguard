package handler

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

type billingReportSection struct {
	Dimension string
	Rows      []billing.AnalyticsBreakdown
}

var billingReportDimensions = []struct {
	Key   string
	Label string
}{
	{Key: "department", Label: "部门"},
	{Key: "user", Label: "人员"},
	{Key: "project", Label: "应用"},
	{Key: "provider", Label: "渠道"},
	{Key: "model", Label: "模型"},
	{Key: "agent", Label: "智能体"},
}

func GetBillingReport(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing report")
			return
		}
		filter, ok := billingAnalyticsFilter(w, r, deps)
		if !ok {
			return
		}
		summary, err := store.GetAnalyticsSummary(r.Context(), filter)
		if err != nil {
			billingHTTPError(w, err)
			return
		}

		sections := make([]billingReportSection, 0, len(billingReportDimensions))
		for _, dimension := range billingReportDimensions {
			rows, err := store.GetAnalyticsBreakdown(r.Context(), filter, dimension.Key, 500)
			if err != nil {
				billingHTTPError(w, err)
				return
			}
			sections = append(sections, billingReportSection{Dimension: dimension.Label, Rows: rows})
		}
		if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("format")), "xlsx") {
			content, err := renderBillingReportXLSX(summary, sections)
			if err != nil {
				billingHTTPError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			w.Header().Set("Content-Disposition", fmt.Sprintf(
				"attachment; filename=\"billing-report-%s-%s.xlsx\"",
				filter.Start.Format("20060102"), filter.End.Add(-1).Format("20060102"),
			))
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_, _ = w.Write(content)
			return
		}
		content, err := renderBillingReportCSV(summary, sections)
		if err != nil {
			billingHTTPError(w, err)
			return
		}

		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(
			"attachment; filename=\"billing-report-%s-%s.csv\"",
			filter.Start.Format("20060102"), filter.End.Add(-1).Format("20060102"),
		))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(content)
	}
}

func renderBillingReportCSV(summary *billing.AnalyticsSummary, sections []billingReportSection) ([]byte, error) {
	header, rows, err := billingReportTable(summary, sections)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.WriteString("\xEF\xBB\xBF")
	writer := csv.NewWriter(&buffer)
	if err := writer.Write(header); err != nil {
		return nil, err
	}
	for _, row := range rows {
		// CSV is a presentation report: round money to cents without changing
		// the immutable billing facts or the exact values in the XLSX workbook.
		for col := 11; col <= 13; col++ {
			if row[col] == "" {
				continue
			}
			micros, err := strconv.ParseInt(strings.Replace(row[col], ".", "", 1), 10, 64)
			if err != nil {
				return nil, err
			}
			row[col] = formatBillingCents(billing.Micros(micros))
		}
		// Only free-text columns can carry a spreadsheet formula prefix.
		for i := 0; i < billingReportTextColumns; i++ {
			row[i] = csvText(row[i])
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// billingReportTextColumns is the number of leading free-text columns
// (dimension, name, secondary); every later column is numeric or blank.
const billingReportTextColumns = 3

// billingReportTable returns the report as raw (unescaped) cells shared by the
// CSV and XLSX renderers, so both formats always carry identical figures.
func billingReportTable(summary *billing.AnalyticsSummary, sections []billingReportSection) ([]string, [][]string, error) {
	if summary == nil {
		return nil, nil, billing.ErrInvalidUsage
	}
	currency := strings.ToUpper(strings.TrimSpace(summary.Currency))
	if currency == "" {
		currency = "CNY"
	}
	header := []string{
		"维度", "名称", "辅助归属", "请求数", "已计费请求数",
		"提示Token", "缓存命中Token", "缓存写入Token", "输出Token", "推理Token", "总Token",
		"内部结算金额(" + currency + ")", "采购成本(" + currency + ")", "成本差额(" + currency + ")",
		"上游成本覆盖率",
	}
	rows := [][]string{billingReportRow("合计", "", "", summary.Requests, summary.PricedRequests,
		summary.PromptTokens, summary.CachedInputTokens, summary.CacheWriteInputTokens,
		summary.OutputTokens, summary.ReasoningTokens, summary.TotalTokens,
		summary.BillableMicros, summary.UpstreamCostMicros, summary.UpstreamCostKnownRequests)}
	for _, section := range sections {
		for _, row := range section.Rows {
			rows = append(rows, billingReportRow(section.Dimension, row.Name, row.Secondary, row.Requests, row.PricedRequests,
				row.PromptTokens, row.CachedInputTokens, row.CacheWriteInputTokens,
				row.OutputTokens, row.ReasoningTokens, row.TotalTokens,
				row.BillableMicros, row.UpstreamCostMicros, row.UpstreamCostKnownRequests,
			))
		}
	}
	return header, rows, nil
}

func billingReportRow(
	dimension, name, secondary string,
	requests, pricedRequests int64,
	promptTokens, cachedInputTokens, cacheWriteInputTokens, outputTokens, reasoningTokens, totalTokens int64,
	billableMicros, upstreamCostMicros billing.Micros, upstreamCostKnownRequests int64,
) []string {
	upstreamCost, costDifference := "", ""
	if upstreamCostKnownRequests > 0 {
		upstreamCost = formatBillingMicros(upstreamCostMicros)
		if upstreamCostKnownRequests == requests {
			costDifference = formatBillingMicros(billableMicros - upstreamCostMicros)
		}
	}
	return []string{
		dimension, name, secondary,
		fmt.Sprintf("%d", requests), fmt.Sprintf("%d", pricedRequests),
		fmt.Sprintf("%d", promptTokens), fmt.Sprintf("%d", cachedInputTokens),
		fmt.Sprintf("%d", cacheWriteInputTokens), fmt.Sprintf("%d", outputTokens),
		fmt.Sprintf("%d", reasoningTokens), fmt.Sprintf("%d", totalTokens),
		formatBillingMicros(billableMicros), upstreamCost, costDifference,
		formatBillingCoverage(requests, upstreamCostKnownRequests),
	}
}

func formatBillingMicros(value billing.Micros) string {
	const scale int64 = 1_000_000
	negative := value < 0
	whole := int64(value) / scale
	fraction := int64(value) % scale
	if fraction < 0 {
		fraction = -fraction
	}
	if whole < 0 {
		whole = -whole
	}
	sign := ""
	if negative {
		sign = "-"
	}
	return fmt.Sprintf("%s%d.%06d", sign, whole, fraction)
}

// formatBillingCents uses integer arithmetic so large amounts and negative
// corrections round consistently, without losing precision through float64.
func formatBillingCents(value billing.Micros) string {
	cents := int64(value) / 10_000
	remainder := int64(value) % 10_000
	if remainder >= 5_000 {
		cents++
	} else if remainder <= -5_000 {
		cents--
	}
	sign := ""
	if cents < 0 {
		sign = "-"
		cents = -cents
	}
	return fmt.Sprintf("%s%d.%02d", sign, cents/100, cents%100)
}

func formatBillingCoverage(requests, known int64) string {
	if requests <= 0 || known <= 0 {
		return "0.00%"
	}
	if known > requests {
		known = requests
	}
	return fmt.Sprintf("%.2f%%", float64(known)*100/float64(requests))
}

func csvText(value string) string {
	if value == "" {
		return ""
	}
	switch value[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}
