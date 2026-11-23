package handler

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestMonthlyStatementXLSXIncludesEstimatedCounts(t *testing.T) {
	st := sampleStatement()
	st.Departments[0].Employees[0].Models[0].EstimatedRequests = 2
	st.Departments[0].Employees[0].EstimatedRequests = 2
	st.Departments[0].EstimatedRequests = 2
	st.Total.EstimatedRequests = 2
	content, err := renderMonthlyStatementXLSX(st)
	if err != nil {
		t.Fatal(err)
	}
	parts := unzipParts(t, content)
	header := string([]rune{0x4F30, 0x7B97, 0x8BA1, 0x8D39, 0x8C03, 0x7528, 0x6B21, 0x6570})
	if header != billingEstimatedRequestsHeader {
		t.Fatalf("header codepoints=%U", []rune(billingEstimatedRequestsHeader))
	}
	for _, name := range []string{"xl/worksheets/sheet1.xml", "xl/worksheets/sheet2.xml"} {
		var sheet struct {
			Rows []struct {
				Cells []struct {
					Ref    string `xml:"r,attr"`
					Value  string `xml:"v"`
					Inline struct {
						Text string `xml:"t"`
					} `xml:"is"`
				} `xml:"c"`
			} `xml:"sheetData>row"`
		}
		if err = xml.Unmarshal([]byte(parts[name]), &sheet); err != nil {
			t.Fatal(err)
		}
		texts := map[string]string{}
		values := map[string]string{}
		for _, row := range sheet.Rows {
			for _, cell := range row.Cells {
				texts[cell.Ref] = cell.Inline.Text
				values[cell.Ref] = cell.Value
			}
		}
		if texts["H1"] != header || values["H2"] != "2" || values["H3"] != "0" {
			t.Fatalf("sheet=%s header=%q counts=%s/%s", name, texts["H1"], values["H2"], values["H3"])
		}
	}
	if !strings.Contains(parts["xl/worksheets/sheet3.xml"], header[:len(header)-len(string([]rune{0x8C03, 0x7528, 0x6B21, 0x6570}))]) {
		t.Fatal("estimate accounting note missing")
	}
}
