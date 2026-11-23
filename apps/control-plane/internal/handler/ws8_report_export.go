package handler

// W8：审计类服务端全量导出（CSV / XLSX）。XLSX 用标准库 archive/zip 手写最小
// OOXML 包（一张工作表、inline string），不引第三方依赖，便于离线交付与供应链审计。

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// reportExportMaxRows 是单次导出的行数上限，超出返回 413 让用户缩小时间范围。
const reportExportMaxRows = 100000

type reportTable struct {
	Sheet   string
	Headers []string
	Rows    [][]string
}

func parseExportFormat(r *http.Request) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) {
	case "", "csv":
		return "csv", true
	case "xlsx":
		return "xlsx", true
	default:
		return "", false
	}
}

// encodeCSV 写 UTF-8 BOM，Excel 直接打开中文不乱码。
func encodeCSV(t reportTable) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\ufeff")
	w := csv.NewWriter(&buf)
	if err := w.Write(t.Headers); err != nil {
		return nil, err
	}
	for _, row := range t.Rows {
		if err := w.Write(sanitizeCSVRow(row)); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// sanitizeCSVRow 防公式注入：以 = + - @ 开头的单元格前加单引号。
func sanitizeCSVRow(row []string) []string {
	out := make([]string, len(row))
	for i, v := range row {
		if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
			v = "'" + v
		}
		out[i] = v
	}
	return out
}

func xlsxColumnName(i int) string {
	name := ""
	for i >= 0 {
		name = string(rune('A'+i%26)) + name
		i = i/26 - 1
	}
	return name
}

func xmlEscape(s string) string {
	var buf bytes.Buffer
	// 过滤 XML 1.0 不允许的控制字符，否则 Excel 拒绝打开。
	clean := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' || r >= 0x20 {
			return r
		}
		return -1
	}, s)
	_ = xml.EscapeText(&buf, []byte(clean))
	return buf.String()
}

func encodeXLSX(t reportTable) ([]byte, error) {
	var sheet strings.Builder
	sheet.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	writeRow := func(idx int, cells []string) {
		sheet.WriteString(`<row r="` + strconv.Itoa(idx) + `">`)
		for c, v := range cells {
			sheet.WriteString(`<c r="` + xlsxColumnName(c) + strconv.Itoa(idx) + `" t="inlineStr"><is><t xml:space="preserve">`)
			sheet.WriteString(xmlEscape(v))
			sheet.WriteString(`</t></is></c>`)
		}
		sheet.WriteString(`</row>`)
	}
	writeRow(1, t.Headers)
	for i, row := range t.Rows {
		writeRow(i+2, row)
	}
	sheet.WriteString(`</sheetData></worksheet>`)

	sheetName := t.Sheet
	if sheetName == "" {
		sheetName = "Sheet1"
	}
	files := []struct{ name, body string }{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
			`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
			`</Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
			`</Relationships>`},
		{"xl/workbook.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
			`<sheets><sheet name="` + xmlEscape(sheetName) + `" sheetId="1" r:id="rId1"/></sheets></workbook>`},
		{"xl/_rels/workbook.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
			`</Relationships>`},
		{"xl/worksheets/sheet1.xml", sheet.String()},
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeReportTable 编码并写响应。文件名走 RFC 5987，中文文件名不乱码。
func writeReportTable(w http.ResponseWriter, format, baseName string, t reportTable) error {
	var body []byte
	var err error
	contentType := "text/csv; charset=utf-8"
	if format == "xlsx" {
		body, err = encodeXLSX(t)
		contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	} else {
		body, err = encodeCSV(t)
	}
	if err != nil {
		return err
	}
	filename := baseName + "." + format
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, asciiFilename(filename), url.PathEscape(filename)))
	w.Header().Set("Cache-Control", "no-store")
	_, err = w.Write(body)
	return err
}

func asciiFilename(name string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
}

func formatReportTime(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return ""
	}
	return t.In(loc).Format("2006-01-02 15:04:05")
}

// parseReportRange 解析 from/to（RFC3339 或 YYYY-MM-DD，日期按租户时区；to 为日期时包含当天）。
func parseReportRange(r *http.Request, loc *time.Location) (time.Time, time.Time, error) {
	parse := func(key string, endOfDay bool) (time.Time, error) {
		raw := strings.TrimSpace(firstQuery(r, key, key+"_time"))
		if raw == "" {
			return time.Time{}, nil
		}
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t, nil
		}
		t, err := time.ParseInLocation("2006-01-02", raw, loc)
		if err != nil {
			return time.Time{}, fmt.Errorf("%s must be RFC3339 or YYYY-MM-DD", key)
		}
		if endOfDay {
			t = t.AddDate(0, 0, 1)
		}
		return t, nil
	}
	from, err := parse("from", false)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	to, err := parse("to", true)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !from.IsZero() && !to.IsZero() && !from.Before(to) {
		return time.Time{}, time.Time{}, fmt.Errorf("from must be earlier than to")
	}
	return from, to, nil
}
