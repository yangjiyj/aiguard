package handler

// W1 1.13：MCP 调用审计服务端全量导出（CSV / XLSX）+ 导出留痕。
//
// 口径：
//   - 与 GET /admin/v1/audit/tools/high-risk 共用 parseToolCallFilter，筛选条件逐项透传；
//     tool_type 强制为 mcp，未指定 risk_level 时导出全部风险等级（与 MCP 审计页一致）。
//   - 服务端按 100 条一页循环 ListAuditPage 取全量，时间窗上界在解析时固定，翻页期间新写入的行不会造成错位。
//   - 行数上限 mcpAuditExportMaxRows，超出即截断，响应头 X-Export-Truncated=true 并在留痕中记录。
//   - 单元格以 = + - @ 制表符/回车开头时加前导单引号，防止表格公式注入。
//   - 每次成功导出写一条 audit_operations（action_type=mcp_audit.export），记录格式、行数、是否截断、筛选条件。

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const (
	mcpAuditExportPageSize = 100
	mcpAuditExportXLSXType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)

// mcpAuditExportMaxRows 为单次导出行数上限；测试可临时调小。
var mcpAuditExportMaxRows = 50000

// ExportMCPAuditLogs 处理 GET /admin/v1/mcp-audit/export?format=csv|xlsx&<与列表相同的筛选参数>。
func ExportMCPAuditLogs(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.GetSession(r.Context())
		if session == nil {
			writeUnauthorized(w, "not authenticated")
			return
		}
		format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
		if format == "" {
			format = "csv"
		}
		if format != "csv" && format != "xlsx" {
			writeError(w, "invalid_request", "format must be csv or xlsx")
			return
		}
		if deps == nil || deps.ToolCallLogRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "tool call log repository unavailable")
			return
		}

		filter, err := parseToolCallFilter(r, session.TenantID)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		filter.ToolType = "mcp"
		if strings.TrimSpace(r.URL.Query().Get("risk_level")) == "" {
			filter.RiskLevel = ""
		}
		keyword, ok := validatedAuditKeyword(w, filter.Keyword)
		if !ok {
			return
		}
		filter.Keyword = keyword
		if !validateAuditKeywordWindow(w, keyword, filter.StartDate, filter.EndDate) {
			return
		}
		queryCtx, finishSearch, ok := beginAuditKeywordSearch(w, r, session.TenantID, keyword)
		if !ok {
			return
		}
		defer finishSearch()

		filter.SkipTotal = true
		filter.Limit = mcpAuditExportPageSize
		filter.Offset = 0
		maxRows := mcpAuditExportMaxRows
		items := make([]repository.ToolCallAuditListItem, 0, mcpAuditExportPageSize)
		truncated := false
	pages:
		for {
			page, err := deps.ToolCallLogRepo.ListAuditPage(queryCtx, filter)
			if err != nil {
				writeAuditKeywordQueryError(w, err, "failed to export mcp audit logs")
				return
			}
			for _, item := range page.Data {
				if len(items) >= maxRows {
					truncated = true
					break pages
				}
				items = append(items, item)
			}
			if !page.HasMore || len(page.Data) == 0 {
				break
			}
			filter.Offset += len(page.Data)
		}

		rows := make([][]string, 0, len(items)+1)
		rows = append(rows, append([]string(nil), mcpAuditExportColumns...))
		for _, item := range items {
			rows = append(rows, mcpAuditExportRow(item))
		}

		var body []byte
		contentType := "text/csv; charset=utf-8"
		if format == "csv" {
			body, err = mcpAuditExportCSV(rows)
		} else {
			contentType = mcpAuditExportXLSXType
			body, err = mcpAuditExportXLSX(rows)
		}
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to encode export file")
			return
		}

		logAudit(r, deps, "mcp_audit.export", map[string]interface{}{
			"format":    format,
			"rows":      len(items),
			"truncated": truncated,
			"max_rows":  maxRows,
			"from":      filter.StartDate.UTC().Format(time.RFC3339),
			"to":        filter.EndDate.UTC().Format(time.RFC3339),
			"filters":   mcpAuditExportFilterSnapshot(r),
		}, "mcp_audit", format)

		filename := fmt.Sprintf("mcp-audit-%s.%s", time.Now().UTC().Format("20060102150405"), format)
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Export-Row-Count", strconv.Itoa(len(items)))
		w.Header().Set("X-Export-Truncated", strconv.FormatBool(truncated))
		w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition, X-Export-Row-Count, X-Export-Truncated")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

// mcpAuditExportFilterSnapshot 记录调用方实际传入的筛选参数（format/limit/offset 除外）。
func mcpAuditExportFilterSnapshot(r *http.Request) map[string]interface{} {
	q := r.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		switch k {
		case "format", "limit", "offset":
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]interface{}, len(keys))
	for _, k := range keys {
		v := strings.TrimSpace(q.Get(k))
		if len(v) > 256 {
			v = v[:256]
		}
		out[k] = v
	}
	return out
}

func mcpAuditExportLabel(labels map[string]string, value string) string {
	if label, ok := labels[value]; ok {
		return label
	}
	return value
}

func mcpAuditExportRow(item repository.ToolCallAuditListItem) []string {
	server, tool := "", item.ToolName
	if idx := strings.Index(item.ToolName, "__"); idx > 0 {
		server, tool = item.ToolName[:idx], item.ToolName[idx+2:]
	}
	policy := item.MatchedPolicyName
	if policy == "" {
		policy = item.MatchedPolicyID
	}
	reason := item.EffectiveReason
	if reason == "" {
		reason = item.MatchReason
	}
	cells := []string{
		item.CreatedAt.UTC().Format(time.RFC3339),
		item.RequestID,
		server,
		tool,
		mcpAuditExportLabel(mcpAuditExportRiskLabels, item.RiskLevel),
		mcpAuditExportLabel(mcpAuditExportDecisionLabels, item.RawDecision),
		mcpAuditExportLabel(mcpAuditExportDecisionLabels, item.EffectiveDecision),
		mcpAuditExportLabel(mcpAuditExportModeLabels, item.Mode),
		item.UserID,
		item.SessionID,
		item.AgentType,
		policy,
		reason,
		mcpAuditExportLabel(mcpAuditExportDispositionLabels, item.DispositionStatus),
	}
	for i := range cells {
		cells[i] = mcpAuditExportSafeCell(cells[i])
	}
	return cells
}

// mcpAuditExportSafeCell 中和表格公式注入（CSV injection）。
func mcpAuditExportSafeCell(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	}
	return value
}

func mcpAuditExportCSV(rows [][]string) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write([]byte{0xEF, 0xBB, 0xBF})
	cw := csv.NewWriter(&buf)
	if err := cw.WriteAll(rows); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func mcpAuditExportColumnRef(idx int) string {
	name := ""
	for idx >= 0 {
		name = string(rune('A'+idx%26)) + name
		idx = idx/26 - 1
	}
	return name
}

func mcpAuditExportXMLText(value string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(value))
	return buf.String()
}

// mcpAuditExportXLSX 手写最小合法 OOXML 工作簿（单表、内联字符串），不引入第三方依赖。
func mcpAuditExportXLSX(rows [][]string) ([]byte, error) {
	var sheet strings.Builder
	sheet.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	sheet.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	for r, row := range rows {
		fmt.Fprintf(&sheet, `<row r="%d">`, r+1)
		for c, cell := range row {
			fmt.Fprintf(&sheet, `<c r="%s%d" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>`,
				mcpAuditExportColumnRef(c), r+1, mcpAuditExportXMLText(cell))
		}
		sheet.WriteString(`</row>`)
	}
	sheet.WriteString(`</sheetData></worksheet>`)

	parts := []struct{ name, body string }{
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
			`<sheets><sheet name="mcp-audit" sheetId="1" r:id="rId1"/></sheets></workbook>`},
		{"xl/_rels/workbook.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
			`</Relationships>`},
		{"xl/worksheets/sheet1.xml", sheet.String()},
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range parts {
		f, err := zw.Create(p.name)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write([]byte(p.body)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
