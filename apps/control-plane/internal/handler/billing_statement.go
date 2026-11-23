package handler

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

// GetBillingMonthlyStatement：GET /admin/v1/billing/statements/monthly?tenant_id=&month=YYYY-MM[&format=xlsx]
// 月度分账单（按部门汇总，展开到员工×模型）。仅平台管理员可读，与“账单与对账”页面权限一致。
func GetBillingMonthlyStatement(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		statement, err := store.MonthlyStatement(r.Context(), tenantID, strings.TrimSpace(r.URL.Query().Get("month")))
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("format")), "xlsx") {
			content, err := renderMonthlyStatementXLSX(statement)
			if err != nil {
				billingHTTPError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="statement-%s.xlsx"`, statement.Month))
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_, _ = w.Write(content)
			return
		}
		writeJSON(w, map[string]any{"data": statement})
	}
}

// statementGeneratedAt：账单没带生成时间时按当前时间，避免导出里出现 0001-01-01。
func statementGeneratedAt(st *billing.MonthlyStatement) time.Time {
	if st.GeneratedAt.IsZero() {
		return time.Now().UTC()
	}
	return st.GeneratedAt.UTC()
}

type xlsxCell struct {
	text   string
	number string // 非空时写数字单元格
	money  bool   // 数字按两位小数显示
}

func textCell(v string) xlsxCell { return xlsxCell{text: v} }
func intCell(v int64) xlsxCell   { return xlsxCell{number: strconv.FormatInt(v, 10)} }
func moneyCell(v int64) xlsxCell {
	return xlsxCell{number: formatBillingCents(billing.Micros(v)), money: true}
}
func billedCell(l billing.StatementLine) xlsxCell {
	// 一笔已计费都没有且存在未计费调用：显示“未计费”，不写 0.00，避免被当成免费。
	if l.BilledRequests == 0 && l.UnbilledRequests > 0 {
		return textCell("未计费")
	}
	return moneyCell(l.BilledMicros)
}

func writeStatementSheet(rows [][]xlsxCell, widths []int) string {
	var b bytes.Buffer
	b.WriteString(xml.Header)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	if len(widths) > 0 {
		b.WriteString(`<cols>`)
		for i, w := range widths {
			fmt.Fprintf(&b, `<col min="%d" max="%d" width="%d" customWidth="1"/>`, i+1, i+1, w)
		}
		b.WriteString(`</cols>`)
	}
	b.WriteString(`<sheetData>`)
	for i, row := range rows {
		ref := strconv.Itoa(i + 1)
		b.WriteString(`<row r="` + ref + `">`)
		for col, cell := range row {
			addr := xlsxColumn(col) + ref
			style := ""
			if i == 0 {
				style = ` s="2"`
			}
			if cell.number != "" {
				if cell.money {
					style = ` s="1"`
				}
				b.WriteString(`<c r="` + addr + `"` + style + `><v>` + cell.number + `</v></c>`)
				continue
			}
			if cell.text == "" {
				continue
			}
			b.WriteString(`<c r="` + addr + `"` + style + ` t="inlineStr"><is><t xml:space="preserve">`)
			_ = xml.EscapeText(&b, []byte(xlsxSafeText(cell.text)))
			b.WriteString(`</t></is></c>`)
		}
		b.WriteString(`</row>`)
	}
	b.WriteString(`</sheetData></worksheet>`)
	return b.String()
}

// renderMonthlyStatementXLSX 与计费报表一样只用标准库生成 xlsx，不引入第三方依赖。
const billingEstimatedRequestsHeader = "估算计费调用次数"

func renderMonthlyStatementXLSX(st *billing.MonthlyStatement) ([]byte, error) {
	if st == nil {
		return nil, billing.ErrInvalidUsage
	}
	// 金额列单位跟随账单币种：美元账单写「美元」，其余（含未带币种的历史数据）沿用「元」。
	unit := "元"
	if strings.EqualFold(strings.TrimSpace(st.Currency), "USD") {
		unit = "美元"
	}
	summary := [][]xlsxCell{{textCell("部门"), textCell("调用次数"), textCell("Token 数"), textCell("已计费金额（" + unit + "）"),
		textCell("未计费调用次数"), textCell("其中未定价"), textCell("其中用量未知"), textCell(billingEstimatedRequestsHeader)}}
	add := func(name string, l billing.StatementLine) {
		summary = append(summary, []xlsxCell{textCell(name), intCell(l.Requests), intCell(l.TotalTokens), moneyCell(l.BilledMicros),
			intCell(l.UnbilledRequests), intCell(l.UnpricedRequests), intCell(l.UsageUnknownRequests), intCell(l.EstimatedRequests)})
	}
	for _, d := range st.Departments {
		add(d.DepartmentName, d.StatementLine)
	}
	add("合计", st.Total)

	detail := [][]xlsxCell{{textCell("部门"), textCell("员工"), textCell("模型"), textCell("调用次数"), textCell("Token 数"),
		textCell("金额（" + unit + "）"), textCell("未计费调用次数"), textCell(billingEstimatedRequestsHeader)}}
	for _, d := range st.Departments {
		for _, e := range d.Employees {
			for _, m := range e.Models {
				detail = append(detail, []xlsxCell{textCell(d.DepartmentName), textCell(e.UserName), textCell(m.ModelName),
					intCell(m.Requests), intCell(m.TotalTokens), billedCell(m), intCell(m.UnbilledRequests), intCell(m.EstimatedRequests)})
			}
		}
	}

	notes := [][]xlsxCell{{textCell("计费口径说明")}}
	for _, line := range []string{
		"估算计费：流式调用未返回完整用量时，按已下发内容或预占上限保守结算，金额已计入账单。",
		"账期：" + st.Month + "，按 " + st.Timezone + " 时区的自然月统计（每月 1 日 00:00 起），与员工月额度的重置时间一致。",
		"币种：" + st.Currency + "。金额按内部结算价计算，表中四舍五入保留两位小数；系统内部以百万分之一元记账，合计可能与逐行相加相差不超过几分钱。",
		"已计费金额：只统计已完成结算的调用，按调用当时生效的价格计算，历史账单不会因之后调价而改变。",
		"未计费：模型当时没有生效价格（未定价），或正向代理看到了调用但拿不到 token 用量（用量未知），两类单独列出，没有计入金额，也不应视为免费。",
		"失败的调用只计次数，不计金额。",
		"Token 数为输入与输出 Token 之和；缓存命中与推理 Token 已包含在其中，不重复计算。",
		"部门、员工按调用发生时的归属记录，之后的部门调整不改变历史账单。",
		"导出时间：" + statementGeneratedAt(st).Format("2006-01-02 15:04:05") + "（UTC）。",
	} {
		notes = append(notes, []xlsxCell{textCell(line)})
	}

	sheets := []struct{ name, body string }{
		{"部门汇总", writeStatementSheet(summary, []int{24, 12, 14, 18, 16, 12, 14, 18})},
		{"员工明细", writeStatementSheet(detail, []int{20, 18, 24, 12, 14, 14, 16, 18})},
		{"计费口径说明", writeStatementSheet(notes, []int{120})},
	}
	var types, sheetXML, rels strings.Builder
	for i, s := range sheets {
		n := strconv.Itoa(i + 1)
		types.WriteString(`<Override PartName="/xl/worksheets/sheet` + n + `.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`)
		sheetXML.WriteString(`<sheet name="` + s.name + `" sheetId="` + n + `" r:id="rId` + n + `"/>`)
		rels.WriteString(`<Relationship Id="rId` + n + `" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet` + n + `.xml"/>`)
	}
	stylesID := strconv.Itoa(len(sheets) + 1)
	parts := []struct{ name, body string }{
		{"[Content_Types].xml", xml.Header + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
			`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>` +
			types.String() + `</Types>`},
		{"_rels/.rels", xml.Header + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`},
		{"xl/workbook.xml", xml.Header + `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>` +
			sheetXML.String() + `</sheets></workbook>`},
		{"xl/_rels/workbook.xml.rels", xml.Header + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + rels.String() +
			`<Relationship Id="rId` + stylesID + `" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`},
		{"xl/styles.xml", xml.Header + `<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
			`<fonts count="2"><font><sz val="11"/><name val="等线"/></font><font><b/><sz val="11"/><name val="等线"/></font></fonts>` +
			`<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>` +
			`<borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
			`<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>` +
			`<xf numFmtId="2" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>` +
			`<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>` +
			`<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`},
	}
	for i, s := range sheets {
		parts = append(parts, struct{ name, body string }{"xl/worksheets/sheet" + strconv.Itoa(i+1) + ".xml", s.body})
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
