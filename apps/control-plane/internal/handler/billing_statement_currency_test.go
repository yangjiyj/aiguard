package handler

import (
	"strings"
	"testing"
)

// 月度分账单 Excel 的金额列单位跟随账单币种：美元账单不能写「元」。
func TestMonthlyStatementXLSXHeadersFollowCurrency(t *testing.T) {
	cases := []struct {
		currency, unit, other string
	}{
		{"USD", "美元", "元）"},
		{"CNY", "元", "美元）"},
		{"", "元", "美元）"},
	}
	for _, c := range cases {
		st := sampleStatement()
		st.Currency = c.currency
		content, err := renderMonthlyStatementXLSX(st)
		if err != nil {
			t.Fatal(err)
		}
		parts := unzipParts(t, content)
		summary, detail := parts["xl/worksheets/sheet1.xml"], parts["xl/worksheets/sheet2.xml"]
		if !strings.Contains(summary, ">已计费金额（"+c.unit+"）<") || !strings.Contains(detail, ">金额（"+c.unit+"）<") {
			t.Fatalf("币种 %q 的表头单位应为 %s：%s | %s", c.currency, c.unit, summary, detail)
		}
		if c.currency == "USD" && (strings.Contains(summary, "已计费金额（元）") || strings.Contains(detail, "金额（元）")) {
			t.Fatalf("美元账单不应出现「元」表头")
		}
	}
}
