package handler

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func TestBillingReportsShowCentsWithoutChangingExactMoney(t *testing.T) {
	cases := []struct {
		micros billing.Micros
		want   string
	}{
		{1, "0.00"}, {-1, "0.00"}, {4999, "0.00"}, {5000, "0.01"},
		{-5000, "-0.01"}, {999999, "1.00"}, {-999999, "-1.00"},
		{math.MaxInt64, "9223372036854.78"}, {math.MinInt64, "-9223372036854.78"},
	}
	for _, tc := range cases {
		summary := &billing.AnalyticsSummary{Currency: "USD", Requests: 1, BillableMicros: tc.micros}
		raw, err := renderBillingReportCSV(summary, nil)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(raw), "\ufeff"))).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if rows[1][11] != tc.want || rows[1][14] != "0.00%" {
			t.Fatalf("micros=%d CSV=%v, want amount %s", tc.micros, rows[1], tc.want)
		}
		workbook, err := renderBillingReportXLSX(summary, nil)
		if err != nil {
			t.Fatal(err)
		}
		sheet := readXLSXTestSheet(t, workbook)
		found := false
		for _, cell := range sheet.Rows[1].Cells {
			if cell.Ref == "L2" {
				found = true
				if cell.Value != formatBillingMicros(tc.micros) || cell.Style != "1" {
					t.Fatalf("exact numeric amount or style lost: %+v", cell)
				}
			}
		}
		if !found {
			t.Fatal("amount missing")
		}
		archive, err := zip.NewReader(bytes.NewReader(workbook), int64(len(workbook)))
		if err != nil {
			t.Fatal(err)
		}
		styleFound := false
		for _, file := range archive.File {
			if file.Name != "xl/styles.xml" {
				continue
			}
			stream, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			style, err := io.ReadAll(stream)
			stream.Close()
			if err != nil {
				t.Fatal(err)
			}
			styleFound = strings.Contains(string(style), `numFmtId="2"`) && strings.Contains(string(style), `applyNumberFormat="1"`)
		}
		if !styleFound {
			t.Fatal("two-decimal Excel number format missing")
		}
		if summary.BillableMicros != tc.micros {
			t.Fatal("export changed underlying amount")
		}
	}
}
