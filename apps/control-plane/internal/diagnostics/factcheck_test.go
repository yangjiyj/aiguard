package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"
)

const testReqID = "req_0a1b2c3d-1111-2222-3333-444455556666"

func reportWith(output string, f Finding) *Report {
	return &Report{
		Steps:    []Step{{Tool: "t", Output: json.RawMessage(output)}},
		Findings: []Finding{f},
	}
}

func TestFactCheck(t *testing.T) {
	out := `{"id":"` + testReqID + `","count":37,"rate":"12.5%","latency_ms":8200}`

	t.Run("数字与编号都出现在工具输出中", func(t *testing.T) {
		r := reportWith(out, Finding{
			Title:  "请求 " + testReqID + " 失败，共 37 次，失败率 12.5%",
			Impact: "延迟 8200 ms",
			Advice: []Advice{{Text: "37 次中的失败请参考上游"}},
		})
		if err := FactCheck(r); err != nil {
			t.Fatalf("期望通过，得到 %v", err)
		}
	})

	t.Run("编号不存在时报错并指出值", func(t *testing.T) {
		bad := "req_ffffffff-ffff-ffff-ffff-ffffffffffff"
		r := reportWith(out, Finding{Title: "请求 " + bad + " 失败"})
		err := FactCheck(r)
		if err == nil || !strings.Contains(err.Error(), bad) {
			t.Fatalf("期望错误含 %s，得到 %v", bad, err)
		}
	})

	t.Run("数字不存在时报错并指出值", func(t *testing.T) {
		r := reportWith(out, Finding{Title: "共 999 次失败"})
		err := FactCheck(r)
		if err == nil || !strings.Contains(err.Error(), "999") {
			t.Fatalf("期望错误含 999，得到 %v", err)
		}
	})

	t.Run("Impact 与 Advice 同样检查", func(t *testing.T) {
		if err := FactCheck(reportWith(out, Finding{Impact: "影响 4321 人"})); err == nil {
			t.Fatal("Impact 中的幻觉数字应被拒绝")
		}
		if err := FactCheck(reportWith(out, Finding{Advice: []Advice{{Text: "重试 4321 次"}}})); err == nil {
			t.Fatal("Advice 中的幻觉数字应被拒绝")
		}
	})

	t.Run("白名单数字免检", func(t *testing.T) {
		r := reportWith(`{}`, Finding{Title: "最近 1 小时、24 小时、2026 年，0 次，100% 完成，窗口 12 小时"})
		if err := FactCheck(r); err != nil {
			t.Fatalf("白名单应通过，得到 %v", err)
		}
	})

	t.Run("25 与 99% 不在白名单", func(t *testing.T) {
		if err := FactCheck(reportWith(`{}`, Finding{Title: "共 25 次"})); err == nil {
			t.Fatal("25 应被拒绝")
		}
		if err := FactCheck(reportWith(`{}`, Finding{Title: "成功率 99%"})); err == nil {
			t.Fatal("99% 应被拒绝")
		}
	})

	t.Run("数字边界不能子串误匹配", func(t *testing.T) {
		r := reportWith(`{"n":1500}`, Finding{Title: "共 500 次"})
		if err := FactCheck(r); err == nil {
			t.Fatal("500 不应匹配 1500")
		}
	})

	t.Run("百分号数字按数值匹配", func(t *testing.T) {
		r := reportWith(`{"ratio":35}`, Finding{Title: "占比 35%"})
		if err := FactCheck(r); err != nil {
			t.Fatalf("得到 %v", err)
		}
	})

	t.Run("请求编号内的数字不单独检查", func(t *testing.T) {
		r := reportWith(`{"id":"`+testReqID+`"}`, Finding{Title: "请求 " + testReqID})
		if err := FactCheck(r); err != nil {
			t.Fatalf("得到 %v", err)
		}
	})

	t.Run("无发现或空报告返回 nil", func(t *testing.T) {
		if err := FactCheck(&Report{}); err != nil {
			t.Fatal(err)
		}
		if err := FactCheck(nil); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("无工具输出时任何非白名单数字均拒绝", func(t *testing.T) {
		if err := FactCheck(&Report{Findings: []Finding{{Title: "共 77 次"}}}); err == nil {
			t.Fatal("应拒绝")
		}
	})
}

func TestFactCheckEvidenceAndUUIDDigits(t *testing.T) {
	id := "req_11111111-2222-3333-4444-555555555555"
	r := &Report{Steps: []Step{{Output: json.RawMessage(`{"id":"` + id + `","count":7}`)}},
		Findings: []Finding{{Title: "共 4444 条", Evidence: []Evidence{{Kind: "request", Ref: id}}}}}
	if err := FactCheck(r); err == nil {
		t.Fatal("uuid 片段 4444 不应让编造的数字通过")
	}
	r.Findings[0].Title = "共 7 条"
	r.Findings[0].Evidence[0].Ref = "req_99999999-2222-3333-4444-555555555555"
	if err := FactCheck(r); err == nil {
		t.Fatal("编造的证据编号必须被拒绝")
	}
	r.Findings[0].Evidence[0].Ref = id
	if err := FactCheck(r); err != nil {
		t.Fatal(err)
	}
}

// 正向代理（proxy-server）的请求编号是裸 UUID，同样要整体识别、整体校验。
func TestFactCheckBareUUIDRequestID(t *testing.T) {
	id := "11111111-2222-3333-4444-555555555555"
	if got := reqIDRe.FindString("编号 " + id + " 报错"); got != id {
		t.Fatalf("裸 UUID 应被识别为请求编号，got %q", got)
	}
	if got := reqIDRe.FindString("req_" + id); got != "req_"+id {
		t.Fatalf("req_ 前缀应保留，got %q", got)
	}
	r := &Report{Steps: []Step{{Output: json.RawMessage(`{"id":"` + id + `","count":7}`)}},
		Findings: []Finding{{Title: "共 4444 条", Evidence: []Evidence{{Kind: "request", Ref: id}}}}}
	if err := FactCheck(r); err == nil {
		t.Fatal("裸 UUID 片段 4444 不应让编造的数字通过")
	}
	r.Findings[0].Title = "共 7 条"
	r.Findings[0].Evidence[0].Ref = "99999999-2222-3333-4444-555555555555"
	if err := FactCheck(r); err == nil {
		t.Fatal("编造的裸 UUID 证据编号必须被拒绝")
	}
	r.Findings[0].Evidence[0].Ref = id
	if err := FactCheck(r); err != nil {
		t.Fatal(err)
	}
}
