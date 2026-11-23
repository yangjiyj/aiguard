package handler

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"regexp"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

// renderBillingReportXLSX writes the same table as the CSV report as a
// minimal Office Open XML workbook using only the standard library, so no
// third-party spreadsheet dependency enters the billing path.
//
// Text is always written as inline strings: a cell such as "=HYPERLINK(...)"
// can never become a formula, so the CSV apostrophe escape is not needed.
// Integer and fixed-point amount columns are written as numeric cells with
// the exact decimal text produced by formatBillingMicros.
func renderBillingReportXLSX(summary *billing.AnalyticsSummary, sections []billingReportSection) ([]byte, error) {
	header, rows, err := billingReportTable(summary, sections)
	if err != nil {
		return nil, err
	}
	var sheet bytes.Buffer
	sheet.WriteString(xml.Header)
	sheet.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	writeXLSXRow(&sheet, 1, header, false)
	for i, row := range rows {
		writeXLSXRow(&sheet, i+2, row, true)
	}
	sheet.WriteString(`</sheetData></worksheet>`)

	parts := []struct{ name, body string }{
		{"[Content_Types].xml", xml.Header + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
			`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>` +
			`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
			`</Types>`},
		{"_rels/.rels", xml.Header + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
			`</Relationships>`},
		{"xl/workbook.xml", xml.Header + `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
			`<sheets><sheet name="计费明细" sheetId="1" r:id="rId1"/></sheets></workbook>`},
		{"xl/_rels/workbook.xml.rels", xml.Header + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
			`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
			`</Relationships>`},
		{"xl/styles.xml", xml.Header + `<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
			`<fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>` +
			`<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>` +
			`<borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
			`<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="2" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs>` +
			`<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`},
		{"xl/worksheets/sheet1.xml", sheet.String()},
	}
	var out bytes.Buffer
	archive := zip.NewWriter(&out)
	for _, part := range parts {
		writer, err := archive.Create(part.name)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write([]byte(part.body)); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// xlsxNumber matches the integer and fixed-point cells billingReportRow emits.
var xlsxNumber = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)

func writeXLSXRow(buffer *bytes.Buffer, rowNumber int, cells []string, typed bool) {
	row := strconv.Itoa(rowNumber)
	buffer.WriteString(`<row r="` + row + `">`)
	for col, value := range cells {
		if value == "" {
			continue
		}
		ref := xlsxColumn(col) + row
		if typed && col >= billingReportTextColumns && xlsxNumber.MatchString(value) {
			style := ""
			if col >= 11 && col <= 13 {
				style = ` s="1"` // Built-in format 2 displays two decimal places.
			}
			buffer.WriteString(`<c r="` + ref + `"` + style + `><v>` + value + `</v></c>`)
			continue
		}
		buffer.WriteString(`<c r="` + ref + `" t="inlineStr"><is><t xml:space="preserve">`)
		_ = xml.EscapeText(buffer, []byte(xlsxSafeText(value)))
		buffer.WriteString(`</t></is></c>`)
	}
	buffer.WriteString(`</row>`)
}

func xlsxColumn(index int) string {
	name := ""
	for index++; index > 0; index = (index - 1) / 26 {
		name = string(rune('A'+(index-1)%26)) + name
	}
	return name
}

// xlsxSafeText drops characters XML 1.0 cannot carry (C0 controls other than
// tab/newline/CR); a stray control byte in a user name must not corrupt the file.
func xlsxSafeText(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' || r >= 0x20 && r != 0xFFFE && r != 0xFFFF {
			return r
		}
		return -1
	}, value)
}
