package handler

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

type xlsxTestCell struct {
	Ref    string `xml:"r,attr"`
	Type   string `xml:"t,attr"`
	Style  string `xml:"s,attr"`
	Value  string `xml:"v"`
	Inline string `xml:"is>t"`
}

type xlsxTestSheet struct {
	Rows []struct {
		Cells []xlsxTestCell `xml:"c"`
	} `xml:"sheetData>row"`
}

func readXLSXTestSheet(t *testing.T, content []byte) xlsxTestSheet {
	t.Helper()
	archive, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("xlsx is not a zip package: %v", err)
	}
	names := map[string]*zip.File{}
	for _, file := range archive.File {
		names[file.Name] = file
	}
	for _, required := range []string{"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/worksheets/sheet1.xml", "xl/styles.xml"} {
		if names[required] == nil {
			t.Fatalf("xlsx package is missing %s", required)
		}
	}
	reader, err := names["xl/worksheets/sheet1.xml"].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	raw, _ := io.ReadAll(reader)
	var sheet xlsxTestSheet
	if err := xml.Unmarshal(raw, &sheet); err != nil {
		t.Fatalf("sheet xml: %v", err)
	}
	return sheet
}

// XLSX export (W7 extension): the workbook must carry exactly the CSV figures,
// keep amounts as exact numeric cells and never turn user text into formulas.
func TestRenderBillingReportXLSXMatchesCSVAndNeverEmitsFormulas(t *testing.T) {
	summary := &billing.AnalyticsSummary{
		Requests: 3, PricedRequests: 3, PromptTokens: 10, TotalTokens: 14,
		BillableMicros: 1_250_001, UpstreamCostMicros: 1_000_000, UpstreamCostKnownRequests: 3,
	}
	sections := []billingReportSection{{
		Dimension: billingReportDimensions[1].Label,
		Rows: []billing.AnalyticsBreakdown{
			{Name: "=HYPERLINK(\"http://x\")", Secondary: "ops\x01team", Requests: 2, TotalTokens: 9, BillableMicros: -250_000},
			{Name: "alice & <bob>", Requests: 1, TotalTokens: 5, BillableMicros: 1_500_001, UpstreamCostKnownRequests: 0},
		},
	}}
	content, err := renderBillingReportXLSX(summary, sections)
	if err != nil {
		t.Fatal(err)
	}
	sheet := readXLSXTestSheet(t, content)
	header, rows, _ := billingReportTable(summary, sections)
	if len(sheet.Rows) != len(rows)+1 {
		t.Fatalf("xlsx rows=%d want %d", len(sheet.Rows), len(rows)+1)
	}
	for i, cell := range sheet.Rows[0].Cells {
		if cell.Type != "inlineStr" || cell.Inline != header[i] {
			t.Fatalf("header cell %d = %+v, want %q", i, cell, header[i])
		}
	}

	csvContent, err := renderBillingReportCSV(summary, sections)
	if err != nil {
		t.Fatal(err)
	}
	csvRows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(csvContent), "\ufeff"))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	byRef := func(row int) map[string]xlsxTestCell {
		out := map[string]xlsxTestCell{}
		for _, cell := range sheet.Rows[row].Cells {
			out[cell.Ref] = cell
		}
		return out
	}
	for r := 1; r < len(csvRows); r++ {
		cells := byRef(r)
		for c, csvValue := range csvRows[r] {
			ref := xlsxColumn(c) + strconv.Itoa(r+1)
			cell, ok := cells[ref]
			if csvValue == "" {
				if ok {
					t.Fatalf("%s should be blank, got %+v", ref, cell)
				}
				continue
			}
			got := cell.Value
			if cell.Type == "inlineStr" {
				got = cell.Inline
			}
			if c < billingReportTextColumns {
				// CSV prefixes an apostrophe to neutralise formulas; XLSX stores
				// the raw text as an inline string instead.
				if cell.Type != "inlineStr" || xlsxSafeText(strings.TrimPrefix(csvValue, "'")) != strings.TrimPrefix(got, "'") {
					t.Fatalf("%s text=%+v csv=%q", ref, cell, csvValue)
				}
				continue
			}
			if c >= 11 && c <= 13 {
				if cell.Style != "1" || got != rows[r-1][c] {
					t.Fatalf("%s must retain exact money with two-decimal display: %+v", ref, cell)
				}
				continue
			}
			if got != csvValue {
				t.Fatalf("%s value=%q csv=%q (cell %+v)", ref, got, csvValue, cell)
			}
		}
	}
	first := byRef(2)
	if cell := first["B3"]; cell.Type != "inlineStr" || cell.Inline != "=HYPERLINK(\"http://x\")" {
		t.Fatalf("formula-looking name must stay an inline string: %+v", cell)
	}
	if cell := first["C3"]; cell.Inline != "opsteam" {
		t.Fatalf("control characters must be stripped for valid XML: %+v", cell)
	}
	if cell := first["L3"]; cell.Type != "" || cell.Value != "-0.250000" {
		t.Fatalf("negative amount must be an exact numeric cell: %+v", cell)
	}
	if cell := byRef(1)["L2"]; cell.Value != "1.250001" {
		t.Fatalf("summary amount must keep all six micro digits: %+v", cell)
	}
	if strings.Contains(string(content), "<f>") {
		t.Fatal("xlsx must not contain formula cells")
	}
}

func TestGetBillingReportServesXLSXOnlyWhenRequested(t *testing.T) {
	recorder := httptest.NewRecorder()
	GetBillingReport(&Dependencies{})(recorder, httptest.NewRequest(http.MethodGet, "/admin/v1/billing/analytics/report?format=xlsx", nil))
	if recorder.Code == http.StatusOK {
		t.Fatalf("report without a billing store must not succeed: %d", recorder.Code)
	}
	if got := xlsxColumn(0) + xlsxColumn(25) + xlsxColumn(26) + xlsxColumn(701) + xlsxColumn(702); got != "AZAAZZAAA" {
		t.Fatalf("column letters=%q", got)
	}
}
