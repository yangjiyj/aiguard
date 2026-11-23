package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------- 内存假 Querier ----------

type t6Fake struct {
	rules []t6Rule
	calls []string
}

type t6Rule struct {
	sub  string
	rows []map[string]any
	err  error
}

func (f *t6Fake) on(sub string, rows ...map[string]any) *t6Fake {
	f.rules = append(f.rules, t6Rule{sub: sub, rows: rows})
	return f
}

func (f *t6Fake) fail(sub string, err error) *t6Fake {
	f.rules = append(f.rules, t6Rule{sub: sub, err: err})
	return f
}

func (f *t6Fake) Query(_ context.Context, sql string, _ ...any) ([]map[string]any, error) {
	f.calls = append(f.calls, sql)
	for _, r := range f.rules {
		if strings.Contains(sql, r.sub) {
			return r.rows, r.err
		}
	}
	return nil, nil
}

func (f *t6Fake) count(sub string) int {
	n := 0
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

const (
	t6P1 = "prov_1"
	t6M1 = "mod_1"
)

func t6ReqID(n int) string { return fmt.Sprintf("req_00000000-0000-4000-8000-%012d", n) }

type t6R map[string]any

// t6Agg 构造聚合行。w=0 当前窗口，1 前一窗口。
func t6Row1(w int, cat string, code int, status string, count int, extra t6R) map[string]any {
	m := map[string]any{
		"w": int64(w), "failure_category": cat, "upstream_status_code": int64(code),
		"provider_id": t6P1, "provider_name": "主渠道", "model_id": t6M1, "model_name": "测试模型",
		"request_status": status, "billing_outcome": "unknown", "count": int64(count), "users": int64(2),
		"samples": []any{t6ReqID(count*10 + code%10), t6ReqID(count*10 + code%10 + 1)}, "hint": "", "err_code": "",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func t6OK(count int) map[string]any { return t6Row1(0, "", 200, "success", count, nil) }

func t6Admin() Scope { return Scope{TenantID: "ten", IsAdmin: true} }
func t6Staff() Scope { return Scope{TenantID: "ten", UserID: "u1"} }

func t6Setting(k, v string) map[string]any { return map[string]any{"key": k, "value": v} }

var (
	t6EnRe    = regexp.MustCompile(`[A-Za-z]{4,}`)
	t6QuoteRe = regexp.MustCompile(`「[^」]*」`)
)

func t6RunOne(t *testing.T, id string, q Querier, s Scope, host *HostView) []Finding {
	t.Helper()
	for _, c := range AllChecks() {
		if c.ID == id {
			fs, err := c.Run(context.Background(), q, s, Input{WindowH: 1}, host)
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			return fs
		}
	}
	t.Fatalf("没有检查项 %s", id)
	return nil
}

func t6AssertChinese(t *testing.T, f Finding) {
	t.Helper()
	for _, txt := range []string{f.Title, f.Impact} {
		if m := t6EnRe.FindString(t6QuoteRe.ReplaceAllString(txt, "")); m != "" {
			t.Errorf("%s: 文案含英文 %q：%s", f.CheckID, m, txt)
		}
	}
	for _, a := range f.Advice {
		if m := t6EnRe.FindString(t6QuoteRe.ReplaceAllString(a.Text, "")); m != "" {
			t.Errorf("%s: 建议含英文 %q：%s", f.CheckID, m, a.Text)
		}
	}
	if f.Title == "" || f.Impact == "" {
		t.Errorf("%s: 标题或影响为空", f.CheckID)
	}
}

func t6IDs(fs []Finding) string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.CheckID)
	}
	return strings.Join(ids, ",")
}

func t6Has(fs []Finding, id string) *Finding {
	for i := range fs {
		if fs[i].CheckID == id {
			return &fs[i]
		}
	}
	return nil
}

// ---------- 请求类：触发 / 不触发 ----------

func TestT6RequestChecks(t *testing.T) {
	hint := "Unsupported parameter: 'max_tokens' is not supported with this model. Use 'max_completion_tokens' instead."
	type tc struct {
		name      string
		check     string
		rows      []map[string]any
		wantIDs   []string // 期望出现的 CheckID（按 check 运行结果）
		wantNone  bool
		wantLevel Level
		titleHas  string
		advHas    string
	}
	cases := []tc{
		{name: "网关限流触发", check: "gw_rate_limited", rows: []map[string]any{t6OK(5), t6Row1(0, "rate_limited", 0, "rate_limited", 4, nil)},
			wantIDs: []string{"gw_rate_limited"}, wantLevel: LevelConfirmed, titleHas: "网关限流"},
		{name: "网关限流不触发", check: "gw_rate_limited", rows: []map[string]any{t6OK(5), t6Row1(0, "rate_limited", 429, "provider_error", 4, nil)}, wantNone: true},
		{name: "额度超限触发", check: "gw_quota", rows: []map[string]any{t6OK(5), t6Row1(0, "quota_exceeded", 0, "quota_exceeded", 2, nil)},
			wantIDs: []string{"gw_quota"}, wantLevel: LevelConfirmed},
		{name: "预算断流触发", check: "gw_quota", rows: []map[string]any{t6Row1(0, "unknown", 0, "provider_error", 3, t6R{"billing_outcome": "budget_exhausted"})},
			wantIDs: []string{"gw_quota"}, wantLevel: LevelConfirmed},
		{name: "额度不触发", check: "gw_quota", rows: []map[string]any{t6OK(5)}, wantNone: true},
		{name: "上游429触发", check: "up_429", rows: []map[string]any{t6OK(16), t6Row1(0, "rate_limited", 429, "provider_error", 4, nil)},
			wantIDs: []string{"up_429"}, wantLevel: LevelConfirmed, titleHas: "上游限流"},
		{name: "上游429占比过高另出疑似欠费", check: "up_429", rows: []map[string]any{t6OK(1), t6Row1(0, "rate_limited", 429, "provider_error", 9, nil)},
			wantIDs: []string{"up_429", "up_billing"}},
		{name: "insufficient_quota 疑似欠费", check: "up_429", rows: []map[string]any{t6OK(20), t6Row1(0, "rate_limited", 429, "provider_error", 2, t6R{"err_code": "insufficient_quota"})},
			wantIDs: []string{"up_429", "up_billing"}},
		{name: "402 疑似欠费", check: "up_429", rows: []map[string]any{t6OK(20), t6Row1(0, "unknown", 402, "provider_error", 2, nil)},
			wantIDs: []string{"up_billing"}},
		{name: "网关限流不算上游429", check: "up_429", rows: []map[string]any{t6Row1(0, "rate_limited", 429, "rate_limited", 9, nil)}, wantNone: true},
		{name: "上游5xx触发", check: "up_5xx", rows: []map[string]any{t6OK(14), t6Row1(0, "upstream_5xx", 502, "provider_error", 6, nil)},
			wantIDs: []string{"up_5xx"}, wantLevel: LevelConfirmed},
		{name: "上游5xx条数不足", check: "up_5xx", rows: []map[string]any{t6OK(2), t6Row1(0, "upstream_5xx", 502, "provider_error", 4, nil)}, wantNone: true},
		{name: "上游5xx占比不足", check: "up_5xx", rows: []map[string]any{t6OK(95), t6Row1(0, "upstream_5xx", 502, "provider_error", 5, nil)}, wantNone: true},
		{name: "参数错误触发", check: "up_param", rows: []map[string]any{t6Row1(0, "unknown", 400, "provider_error", 2, t6R{"hint": hint})},
			wantIDs: []string{"up_param"}, wantLevel: LevelConfirmed, titleHas: "max_tokens"},
		{name: "参数错误>=3条提示厂商", check: "up_param", rows: []map[string]any{t6Row1(0, "unknown", 400, "provider_error", 3, t6R{"hint": hint})},
			wantIDs: []string{"up_param"}, advHas: "导出诊断包联系厂商"},
		{name: "无hint的400不触发", check: "up_param", rows: []map[string]any{t6Row1(0, "unknown", 400, "provider_error", 5, nil)}, wantNone: true},
		{name: "超时触发", check: "timeout", rows: []map[string]any{t6OK(5), t6Row1(0, "timeout", 504, "provider_timeout", 3, nil)},
			wantIDs: []string{"timeout"}, wantLevel: LevelConfirmed},
		{name: "超时不触发", check: "timeout", rows: []map[string]any{t6OK(5)}, wantNone: true},
		{name: "鉴权失败触发", check: "auth_failed", rows: []map[string]any{t6Row1(0, "auth_failed", 401, "provider_error", 3, nil)},
			wantIDs: []string{"auth_failed"}, wantLevel: LevelConfirmed},
		{name: "鉴权不触发", check: "auth_failed", rows: []map[string]any{t6OK(5)}, wantNone: true},
		{name: "模型缺失触发", check: "model_missing", rows: []map[string]any{t6Row1(0, "unknown", 0, "model_not_configured", 2, nil)},
			wantIDs: []string{"model_missing"}, wantLevel: LevelConfirmed, titleHas: "测试模型"},
		{name: "模型缺失不触发", check: "model_missing", rows: []map[string]any{t6OK(5)}, wantNone: true},
		{name: "安全拦截突增触发", check: "security_block",
			rows:    []map[string]any{t6OK(5), t6Row1(0, "security_rejected", 0, "security_blocked", 9, nil), t6Row1(1, "security_rejected", 0, "security_blocked", 2, nil)},
			wantIDs: []string{"security_block"}, wantLevel: LevelSuspected},
		{name: "安全拦截未突增", check: "security_block",
			rows:     []map[string]any{t6Row1(0, "security_rejected", 0, "security_blocked", 9, nil), t6Row1(1, "security_rejected", 0, "security_blocked", 5, nil)},
			wantNone: true},
		{name: "安全拦截数量太少", check: "security_block", rows: []map[string]any{t6Row1(0, "security_rejected", 0, "security_blocked", 2, nil)}, wantNone: true},
		{name: "流式中断触发", check: "stream_abort", rows: []map[string]any{t6OK(17), t6Row1(0, "stream_aborted", 0, "stream_aborted", 3, nil)},
			wantIDs: []string{"stream_abort"}, wantLevel: LevelSuspected},
		{name: "流式中断占比不足", check: "stream_abort", rows: []map[string]any{t6OK(97), t6Row1(0, "stream_aborted", 0, "stream_aborted", 3, nil)}, wantNone: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := (&t6Fake{}).on("t6:agg", c.rows...)
			fs := t6RunOne(t, c.check, fake, t6Admin(), nil)
			if c.wantNone {
				if len(fs) != 0 {
					t.Fatalf("不应触发，得到 %s", t6IDs(fs))
				}
				return
			}
			for _, id := range c.wantIDs {
				f := t6Has(fs, id)
				if f == nil {
					t.Fatalf("缺少 %s，得到 %s", id, t6IDs(fs))
				}
				t6AssertChinese(t, *f)
				if len(f.Evidence) == 0 || f.Evidence[0].Kind != "request" || !strings.HasPrefix(f.Evidence[0].Ref, "req_") {
					t.Errorf("%s 缺示例请求证据: %+v", id, f.Evidence)
				}
			}
			f := t6Has(fs, c.wantIDs[0])
			if c.wantLevel != "" && f.Level != c.wantLevel {
				t.Errorf("级别 %s != %s", f.Level, c.wantLevel)
			}
			if c.titleHas != "" && !strings.Contains(f.Title, c.titleHas) {
				t.Errorf("标题 %q 不含 %q", f.Title, c.titleHas)
			}
			if c.advHas != "" {
				ok := false
				for _, a := range f.Advice {
					ok = ok || strings.Contains(a.Text, c.advHas)
				}
				if !ok {
					t.Errorf("建议里没有 %q: %+v", c.advHas, f.Advice)
				}
			}
			if c.check == "up_param" && c.advHas == "" {
				for _, a := range f.Advice {
					if strings.Contains(a.Text, "诊断包") {
						t.Errorf("条数 <3 不应提示联系厂商")
					}
				}
			}
		})
	}
}

func TestT6UpParamEvidenceRawAndLinks(t *testing.T) {
	long := "Unsupported parameter: 'max_tokens' " + strings.Repeat("x", 800) + " Bearer sk-abcdefghijklmnop1234"
	fake := (&t6Fake{}).on("t6:agg", t6Row1(0, "unknown", 400, "provider_error", 3, t6R{"hint": long}))
	fs := t6RunOne(t, "up_param", fake, t6Admin(), nil)
	if len(fs) != 1 {
		t.Fatalf("得到 %d", len(fs))
	}
	f := fs[0]
	var raw string
	for _, e := range f.Evidence {
		if e.Raw != "" {
			raw = e.Raw
		}
	}
	if raw == "" || len([]rune(raw)) > 501 || strings.Contains(raw, "sk-abcdefghijklmnop") {
		t.Errorf("Raw 应截断到 500 字并脱敏: %d %q", len([]rune(raw)), raw[:40])
	}
	if !strings.Contains(f.Title, "「主渠道」") || !strings.Contains(f.Title, "max_tokens") {
		t.Errorf("标题应带渠道名与参数名: %s", f.Title)
	}
	var link bool
	for _, a := range f.Advice {
		link = link || strings.HasPrefix(a.Link, "/cost/records?request_id=req_")
	}
	if !link {
		t.Errorf("建议缺调用明细链接: %+v", f.Advice)
	}
}

func TestT6StaffAdviceHasNoAdminLink(t *testing.T) {
	fake := (&t6Fake{}).on("t6:agg", t6OK(5), t6Row1(0, "quota_exceeded", 0, "quota_exceeded", 2, nil))
	fs := t6RunOne(t, "gw_quota", fake, t6Staff(), nil)
	if len(fs) != 1 {
		t.Fatal("应触发")
	}
	for _, a := range fs[0].Advice {
		if a.Link != "" {
			t.Errorf("员工建议不应带后台链接: %+v", a)
		}
	}
	if fake.count("t6:quota_policies") != 0 {
		t.Error("员工不应查额度策略明细")
	}
}

// ---------- 配置类 ----------

func TestT6ConfigChecks(t *testing.T) {
	now := time.Now().UTC()
	anchor := func(daysAgo int) string { return now.AddDate(0, 0, -daysAgo).Format(time.RFC3339) }
	t.Run("授权试用期已过", func(t *testing.T) {
		q := (&t6Fake{}).on("FROM system_settings", t6Setting("enterprise_license_install_anchor", anchor(120)))
		fs := t6RunOne(t, "license", q, t6Admin(), nil)
		if len(fs) != 1 || fs[0].Severity != SevError || fs[0].Level != LevelConfirmed {
			t.Fatalf("%+v", fs)
		}
		t6AssertChinese(t, fs[0])
	})
	t.Run("授权30天内到期", func(t *testing.T) {
		q := (&t6Fake{}).on("FROM system_settings", t6Setting("enterprise_license_install_anchor", anchor(70)))
		fs := t6RunOne(t, "license", q, t6Admin(), nil)
		if len(fs) != 1 || fs[0].Severity != SevWarn {
			t.Fatalf("%+v", fs)
		}
		t6AssertChinese(t, fs[0])
	})
	t.Run("授权正常", func(t *testing.T) {
		q := (&t6Fake{}).on("FROM system_settings", t6Setting("enterprise_license_install_anchor", anchor(5)))
		if fs := t6RunOne(t, "license", q, t6Admin(), nil); len(fs) != 0 {
			t.Fatalf("不应触发 %+v", fs)
		}
	})
	t.Run("渠道停用仍有路由", func(t *testing.T) {
		q := (&t6Fake{}).on("t6:provider_down", map[string]any{"id": "p9", "name": "备用渠道", "status": "disabled", "models": []any{"模型甲"}, "policies": int64(1)})
		fs := t6RunOne(t, "provider_down", q, t6Admin(), nil)
		if len(fs) != 1 || !strings.Contains(fs[0].Title, "「备用渠道」") || fs[0].Evidence[0].Kind != "config" {
			t.Fatalf("%+v", fs)
		}
		t6AssertChinese(t, fs[0])
	})
	t.Run("渠道全部正常", func(t *testing.T) {
		if fs := t6RunOne(t, "provider_down", &t6Fake{}, t6Admin(), nil); len(fs) != 0 {
			t.Fatal("不应触发")
		}
	})
	t.Run("模型无可用渠道", func(t *testing.T) {
		q := (&t6Fake{}).
			on("t6:no_route_used",
				map[string]any{"model_label": "模型甲", "model_name": "model-a", "requests": int64(7), "samples": []any{t6ReqID(1)}},
				map[string]any{"model_label": "模型乙", "model_name": "model-b", "requests": int64(3), "samples": []any{t6ReqID(2)}}).
			on("t6:no_route_ok", map[string]any{"model_name": "model-b"})
		fs := t6RunOne(t, "no_route", q, t6Admin(), nil)
		if len(fs) != 1 || !strings.Contains(fs[0].Title, "「模型甲」") {
			t.Fatalf("%+v", fs)
		}
		if fs[0].Evidence[0].Ref != t6ReqID(1) {
			t.Errorf("证据: %+v", fs[0].Evidence)
		}
		t6AssertChinese(t, fs[0])
	})
	t.Run("模型都有渠道", func(t *testing.T) {
		q := (&t6Fake{}).
			on("t6:no_route_used", map[string]any{"model_label": "模型乙", "model_name": "model-b", "requests": int64(3), "samples": []any{}}).
			on("t6:no_route_ok", map[string]any{"model_name": "model-b"})
		if fs := t6RunOne(t, "no_route", q, t6Admin(), nil); len(fs) != 0 {
			t.Fatal("不应触发")
		}
	})
}

// ---------- 宿主机类 ----------

func t6Host(mut func(s *HostSnapshot)) *HostView {
	s := &HostSnapshot{
		At: time.Now().UTC().Format(time.RFC3339), AgentVersion: "1", Fresh: true,
		Containers: []HostContainer{{Name: "x-gateway-core-1", Service: "gateway-core", State: "running", Health: "healthy", StartedAt: time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano)}},
		Disk:       []HostDisk{{Mount: "/", UsedPct: 40}},
		Certs:      []HostCert{{Path: "/etc/ssl/a.pem", DaysLeft: 200}},
	}
	if mut != nil {
		mut(s)
	}
	return &HostView{Snapshot: s}
}

func TestT6HostChecks(t *testing.T) {
	recent := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339Nano)
	type tc struct {
		name  string
		check string
		host  *HostView
		want  Severity // 空=不触发
		find  string
	}
	cases := []tc{
		{"容器正常", "host_container", t6Host(nil), "", ""},
		{"容器退出", "host_container", t6Host(func(s *HostSnapshot) { s.Containers[0].State = "exited" }), SevError, "gateway-core"},
		{"容器不健康", "host_container", t6Host(func(s *HostSnapshot) { s.Containers[0].Health = "unhealthy" }), SevError, ""},
		{"1小时内重启3次", "host_container", t6Host(func(s *HostSnapshot) {
			s.Containers[0].RestartCount = 3
			s.Containers[0].StartedAt = recent
		}), SevWarn, ""},
		{"重启多但很久以前", "host_container", t6Host(func(s *HostSnapshot) { s.Containers[0].RestartCount = 9 }), "", ""},
		{"漂移无", "host_drift", t6Host(func(s *HostSnapshot) { s.Drift = []HostDrift{{Service: "a", ImageMatch: true}} }), "", ""},
		{"镜像不一致", "host_drift", t6Host(func(s *HostSnapshot) { s.Drift = []HostDrift{{Service: "chat-portal-ui", ImageMatch: false}} }), SevError, ""},
		{"环境变量不一致", "host_drift", t6Host(func(s *HostSnapshot) {
			s.Drift = []HostDrift{{Service: "chat-portal-ui", ImageMatch: true, EnvDiff: []HostDriftEnv{{Key: "PORTAL_PUBLIC_URL", Chain: "https://a", Running: "https://b"}}}}
		}), SevError, ""},
		{"漂移比对失败", "host_drift", t6Host(func(s *HostSnapshot) { s.DriftError = "compose failed" }), SevWarn, ""},
		{"磁盘85%", "host_disk", t6Host(func(s *HostSnapshot) { s.Disk[0].UsedPct = 85 }), SevWarn, ""},
		{"磁盘90%", "host_disk", t6Host(func(s *HostSnapshot) { s.Disk[0].UsedPct = 90 }), SevError, ""},
		{"磁盘79%", "host_disk", t6Host(func(s *HostSnapshot) { s.Disk[0].UsedPct = 79 }), "", ""},
		{"证书15天", "host_cert", t6Host(func(s *HostSnapshot) { s.Certs[0].DaysLeft = 15 }), SevWarn, ""},
		{"证书已过期", "host_cert", t6Host(func(s *HostSnapshot) { s.Certs[0].DaysLeft = 0 }), SevError, ""},
		{"证书16天", "host_cert", t6Host(func(s *HostSnapshot) { s.Certs[0].DaysLeft = 16 }), "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := t6RunOne(t, c.check, &t6Fake{}, t6Admin(), c.host)
			if c.want == "" {
				if len(fs) != 0 {
					t.Fatalf("不应触发 %+v", fs)
				}
				return
			}
			if len(fs) != 1 || fs[0].Severity != c.want || fs[0].Level != LevelConfirmed && fs[0].Level != LevelUnknown {
				t.Fatalf("%+v", fs)
			}
			t6AssertChinese(t, fs[0])
			if c.find != "" && !strings.Contains(fs[0].Title, c.find) {
				t.Errorf("标题 %q 不含 %q", fs[0].Title, c.find)
			}
		})
	}
	t.Run("敏感漂移不泄露值", func(t *testing.T) {
		h := t6Host(func(s *HostSnapshot) {
			s.Drift = []HostDrift{{Service: "a", ImageMatch: true, EnvDiff: []HostDriftEnv{{Key: "DB_PASSWORD", Sensitive: true}}}}
		})
		fs := t6RunOne(t, "host_drift", &t6Fake{}, t6Admin(), h)
		if len(fs) != 1 || !strings.Contains(fs[0].Impact, "敏感") {
			t.Fatalf("%+v", fs)
		}
	})
}

func TestT6AgentMissing(t *testing.T) {
	stale := t6Host(func(s *HostSnapshot) { s.Fresh = false; s.Age = 10 * time.Minute })
	for name, h := range map[string]*HostView{
		"缺失": {Err: ErrAgentMissing}, "过期": stale, "nil": nil,
	} {
		t.Run(name, func(t *testing.T) {
			fs := t6RunOne(t, "agent_missing", &t6Fake{}, t6Admin(), h)
			if len(fs) != 1 || fs[0].Severity != SevWarn || fs[0].Level != LevelUnknown || fs[0].Title != "未安装或未运行宿主机采集器" {
				t.Fatalf("%+v", fs)
			}
			// 其余 host 检查应跳过：不产生 finding。
			for _, id := range []string{"host_container", "host_drift", "host_disk", "host_cert"} {
				if got := t6RunOne(t, id, &t6Fake{}, t6Admin(), h); len(got) != 0 {
					t.Errorf("%s 不应产生结论", id)
				}
			}
		})
	}
	if fs := t6RunOne(t, "agent_missing", &t6Fake{}, t6Admin(), t6Host(nil)); len(fs) != 0 {
		t.Error("快照新鲜时不应触发")
	}
}

// ---------- RunChecks ----------

func t6Dummy() *t6Fake {
	return (&t6Fake{}).
		on("t6:agg", t6OK(30),
			t6Row1(0, "rate_limited", 429, "provider_error", 5, nil),
			t6Row1(0, "quota_exceeded", 0, "quota_exceeded", 2, nil)).
		on("FROM system_settings", t6Setting("enterprise_license_install_anchor", time.Now().AddDate(0, 0, -5).UTC().Format(time.RFC3339)))
}

func TestT6RunChecks(t *testing.T) {
	q := t6Dummy()
	host := &HostView{Err: ErrAgentMissing}
	fs, ok, steps := RunChecks(context.Background(), q, t6Admin(), Input{Kind: "health", WindowH: 1}, host)
	if q.count("t6:agg") != 1 {
		t.Fatalf("聚合查询应只执行 1 次，实际 %d", q.count("t6:agg"))
	}
	if t6Has(fs, "gw_quota") == nil || t6Has(fs, "up_429") == nil || t6Has(fs, "agent_missing") == nil {
		t.Fatalf("缺少预期结论: %s", t6IDs(fs))
	}
	// 排序：error 在 warn 之前。
	seenWarn := false
	for _, f := range fs {
		if f.Severity == SevWarn {
			seenWarn = true
		} else if f.Severity == SevError && seenWarn {
			t.Fatalf("排序错误: %s", t6IDs(fs))
		}
	}
	// 每个检查一个 Step（另有一个聚合 Step）。
	names := map[string]bool{}
	for _, s := range steps {
		names[s.Tool] = true
		if s.Summary == "" || strings.ContainsAny(s.Summary, "abcdefghijklmnopqrstuvwxyz") {
			t.Errorf("Step 进度文案应为中文: %q", s.Summary)
		}
		if s.Err == "" && !json.Valid(s.Output) {
			t.Errorf("%s 输出不是合法 JSON", s.Tool)
		}
	}
	for _, c := range AllChecks() {
		if !names["check:"+c.ID] {
			t.Errorf("缺少 Step check:%s", c.ID)
		}
	}
	if !names["check:request_agg"] {
		t.Error("聚合应作为独立 Step 输出")
	}
	// okCount = 无问题且已执行（host 类全部跳过，不计入）。
	wantOK := 0
	for _, c := range AllChecks() {
		if c.Category == "host" {
			continue
		}
		if t6Has(fs, c.ID) == nil && !(c.ID == "up_429" && t6Has(fs, "up_billing") != nil) {
			wantOK++
		}
	}
	if ok != wantOK {
		t.Errorf("okCount=%d，期望 %d（结论 %s）", ok, wantOK, t6IDs(fs))
	}
	// FactCheck 通过。
	rep := &Report{Findings: fs, Steps: steps, OKCount: ok}
	if err := FactCheck(rep); err != nil {
		t.Fatalf("FactCheck: %v", err)
	}
}

func TestT6RunChecksStaffSkipsAdminOnly(t *testing.T) {
	q := t6Dummy()
	_, _, steps := RunChecks(context.Background(), q, t6Staff(), Input{WindowH: 1}, &HostView{Err: ErrAgentMissing})
	for _, s := range steps {
		for _, c := range AllChecks() {
			if c.AdminOnly && s.Tool == "check:"+c.ID {
				t.Errorf("员工不应执行 %s", c.ID)
			}
		}
	}
	for _, sub := range []string{"system_settings", "t6:provider_down", "t6:no_route"} {
		if q.count(sub) != 0 {
			t.Errorf("员工不应触发查询 %s", sub)
		}
	}
	if q.count("t6:agg") != 1 {
		t.Error("员工仍应执行请求聚合")
	}
}

func TestT6RunChecksContinuesAfterError(t *testing.T) {
	q := t6Dummy().fail("t6:provider_down", errors.New("boom"))
	// fail 规则追加在后，需放前面才能优先匹配：重建。
	q = &t6Fake{rules: append([]t6Rule{{sub: "t6:provider_down", err: errors.New("boom")}}, t6Dummy().rules...)}
	fs, ok, steps := RunChecks(context.Background(), q, t6Admin(), Input{WindowH: 1}, &HostView{Err: ErrAgentMissing})
	var failed int
	for _, s := range steps {
		if s.Tool == "check:provider_down" {
			if s.Err == "" {
				t.Error("应记录 Step.Err")
			}
			failed++
		}
	}
	if failed != 1 || t6Has(fs, "gw_quota") == nil || ok == 0 {
		t.Fatalf("其余检查应继续: failed=%d ok=%d fs=%s", failed, ok, t6IDs(fs))
	}
}

func TestT6RunChecksAggError(t *testing.T) {
	q := &t6Fake{rules: []t6Rule{{sub: "t6:agg", err: errors.New("boom")}}}
	_, _, steps := RunChecks(context.Background(), q, t6Staff(), Input{WindowH: 1}, nil)
	var errs int
	for _, s := range steps {
		if s.Err != "" {
			errs++
		}
	}
	if errs < 2 {
		t.Errorf("聚合失败应体现在聚合 Step 与各请求检查上: %d", errs)
	}
	if q.count("t6:agg") != 1 {
		t.Errorf("聚合失败也只应查询一次: %d", q.count("t6:agg"))
	}
}

func TestT6AggSQLParameterized(t *testing.T) {
	sql, args := t6AggSQL(Scope{TenantID: "ten'; DROP TABLE x;--", UserID: "u1"}, 3)
	if strings.Contains(sql, "DROP TABLE") || len(args) != 4 || !strings.Contains(sql, "rl.user_id = $4") {
		t.Fatalf("员工查询必须参数化并按 user 过滤: %v", args)
	}
	sql2, args2 := t6AggSQL(Scope{TenantID: "t", IsAdmin: true}, 1)
	if len(args2) != 3 || strings.Contains(sql2, "rl.user_id = $4") {
		t.Fatal("管理员不应带 user 过滤")
	}
	for _, must := range []string{"mode() WITHIN GROUP", "<> 'proxy'", "NOT IN ('received', 'in_progress')", "rl.tenant_id = $1"} {
		if !strings.Contains(sql, must) {
			t.Errorf("SQL 缺少 %q", must)
		}
	}
}

func TestT6ParamName(t *testing.T) {
	for in, want := range map[string]string{
		"Unsupported parameter: 'max_tokens' is not supported": "max_tokens",
		"Unknown parameter: 'input[0].content'.":               "input[0].content",
		"something about temperature":                          "temperature",
		"nothing relevant":                                     "",
	} {
		if got := t6ParamName(in); got != want {
			t.Errorf("%q -> %q，期望 %q", in, got, want)
		}
	}
}

// ---------- PG 集成测试 ----------

type t6Fix struct {
	conn         *pgx.Conn
	x            *Exec
	tenant       string
	staffA, adm  string
	provider, md string
	key          string
}

func t6NewFixture(t *testing.T) *t6Fix {
	t.Helper()
	dsn := os.Getenv("DIAG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("DIAG_TEST_DATABASE_URL 未设置")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	x, err := NewExec(dsn)
	if err != nil {
		t.Fatal(err)
	}
	sfx := fmt.Sprintf("%08x", rand.Uint32())
	f := &t6Fix{conn: conn, x: x, tenant: "t6ten_" + sfx, staffA: "t6ua_" + sfx, adm: "t6adm_" + sfx,
		provider: "t6prov_" + sfx, md: "t6mod_" + sfx, key: "t6k_" + sfx}
	t.Cleanup(func() {
		c := context.Background()
		for _, s := range []string{
			`DELETE FROM request_logs WHERE tenant_id = $1`,
			`DELETE FROM internal_keys WHERE tenant_id = $1`,
			`DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = $1)`,
			`DELETE FROM providers WHERE tenant_id = $1`,
			`DELETE FROM projects WHERE tenant_id = $1`,
			`DELETE FROM users WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			if _, err := conn.Exec(c, s, f.tenant); err != nil {
				t.Errorf("清理失败: %v (%s)", err, s)
			}
		}
		_ = conn.Close(c)
		x.Close()
	})
	ex := func(sql string, args ...any) {
		if _, err := conn.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("夹具失败: %v\n%s", err, sql)
		}
	}
	ex(`INSERT INTO tenants (id, name) VALUES ($1, $1)`, f.tenant)
	for _, u := range []string{f.adm, f.staffA} {
		ex(`INSERT INTO users (id, tenant_id, username, department_assignment_mode) VALUES ($1, $2, $1, 'emergency')`, u, f.tenant)
	}
	ex(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'p')`, "t6proj_"+f.tenant, f.tenant)
	ex(`INSERT INTO providers (id, tenant_id, name, provider_type) VALUES ($1, $2, $3, 'openai')`, f.provider, f.tenant, "渠道-"+f.provider)
	ex(`INSERT INTO models (id, provider_id, model_name) VALUES ($1, $2, $3)`, f.md, f.provider, "m-"+f.md)
	ex(`INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix) VALUES ($1,$2,$3,$4,$5,$6)`,
		f.key, f.tenant, "t6proj_"+f.tenant, f.staffA, "h_"+f.key, "t6p"+sfx[:5])
	return f
}

func (f *t6Fix) add(t *testing.T, n int, status string, code int, agoMin int, audit string) string {
	t.Helper()
	rid := fmt.Sprintf("req_%08d-0000-4000-8000-%012d", rand.Intn(99999999), n)
	var a, c any
	if audit != "" {
		a = audit
	}
	if code > 0 {
		c = code
	}
	if _, err := f.conn.Exec(context.Background(), `
INSERT INTO request_logs (id, request_id, tenant_id, user_id, client_id, provider_id, model_id, endpoint_type, request_status,
  upstream_status_code, latency_ms, created_at, output_audit_result)
VALUES ($1,$2,$3,$4,$5,$6,$7,'chat',$8,$9,100, now() - make_interval(mins => $10), $11::jsonb)`,
		"id_"+rid, rid, f.tenant, f.staffA, f.key, f.provider, f.md, status, c, agoMin, a); err != nil {
		t.Fatal(err)
	}
	return rid
}

func TestT6RunChecksPG(t *testing.T) {
	f := t6NewFixture(t)
	n := 0
	next := func() int { n++; return n }
	// 成功 4 条；上游 429 四条（50%，只触发 up_429 不触发疑似欠费）；网关额度 2 条；上游 400 带 hint 3 条。
	for i := 0; i < 4; i++ {
		f.add(t, next(), "success", 200, 5+i, "")
	}
	var id429 string
	for i := 0; i < 4; i++ {
		id429 = f.add(t, next(), "provider_error", 429, 10+i, "")
	}
	idQuota := f.add(t, next(), "quota_exceeded", 0, 4, "")
	f.add(t, next(), "quota_exceeded", 0, 5, "")
	hint := "Unsupported parameter: 'max_tokens' is not supported with this model."
	audit := fmt.Sprintf(`{"response_metadata":{"upstream_error_hint":%q,"upstream_error_code":"unsupported_parameter"}}`, hint)
	var id400 string
	for i := 0; i < 3; i++ {
		id400 = f.add(t, next(), "provider_error", 400, 2+i, audit)
	}
	// 排除项：不应被统计。
	f.add(t, next(), "received", 0, 1, "")
	f.add(t, next(), "in_progress", 0, 1, "")

	ctx := context.Background()
	scope := Scope{TenantID: f.tenant, IsAdmin: true}
	host := &HostView{Err: ErrAgentMissing}
	fs, ok, steps := RunChecks(ctx, f.x, scope, Input{Kind: "health", WindowH: 1}, host)
	for _, s := range steps {
		if s.Err != "" {
			t.Errorf("步骤 %s 出错: %s", s.Tool, s.Err)
		}
	}
	for _, want := range []string{"up_429", "gw_quota", "up_param", "agent_missing"} {
		if t6Has(fs, want) == nil {
			t.Fatalf("缺少 %s，得到 %s", want, t6IDs(fs))
		}
	}
	for _, not := range []string{"up_billing", "up_5xx", "auth_failed", "gw_rate_limited", "timeout"} {
		if t6Has(fs, not) != nil {
			t.Errorf("不应出现 %s", not)
		}
	}
	// 上游原文与请求编号作为证据。
	up := t6Has(fs, "up_param")
	var raw bool
	for _, e := range up.Evidence {
		raw = raw || strings.Contains(e.Raw, "max_tokens")
	}
	if !raw || !strings.Contains(up.Title, "max_tokens") {
		t.Errorf("up_param 应引用上游原文: %+v", up)
	}
	var advGw bool
	for _, a := range up.Advice {
		advGw = advGw || strings.Contains(a.Text, "导出诊断包联系厂商")
	}
	if !advGw {
		t.Error("同一渠道同一错误 3 条应提示联系厂商")
	}
	for _, e := range t6Has(fs, "up_429").Evidence {
		if e.Kind != "request" || !strings.HasPrefix(e.Ref, "req_") {
			t.Errorf("证据应为请求编号: %+v", e)
		}
	}
	_, _ = idQuota, id400
	_ = id429
	if ok == 0 {
		t.Error("应有正常项")
	}
	rep := &Report{Findings: fs, Steps: steps, OKCount: ok}
	if err := FactCheck(rep); err != nil {
		t.Fatalf("FactCheck: %v", err)
	}
	for _, fd := range fs {
		t6AssertChinese(t, fd)
	}

	// 员工只能看到自己的请求；其他租户没有数据时不应有结论。
	other := Scope{TenantID: f.tenant + "_x", IsAdmin: true}
	fs2, _, _ := RunChecks(ctx, f.x, other, Input{WindowH: 1}, host)
	for _, fd := range fs2 {
		if fd.CheckID == "up_429" || fd.CheckID == "gw_quota" {
			t.Errorf("跨租户泄露: %s", fd.CheckID)
		}
	}
	staff := Scope{TenantID: f.tenant, UserID: f.staffA}
	fs3, _, steps3 := RunChecks(ctx, f.x, staff, Input{WindowH: 1}, host)
	if t6Has(fs3, "up_429") == nil {
		t.Errorf("员工应看到自己的 429: %s", t6IDs(fs3))
	}
	for _, s := range steps3 {
		if s.Tool == "check:license" {
			t.Error("员工不应执行 license")
		}
	}
	staffOther := Scope{TenantID: f.tenant, UserID: f.adm}
	fs4, _, _ := RunChecks(ctx, f.x, staffOther, Input{WindowH: 1}, host)
	if t6Has(fs4, "up_429") != nil {
		t.Error("员工不应看到他人请求")
	}
	if err := FactCheck(&Report{Findings: fs3, Steps: steps3}); err != nil {
		t.Fatalf("员工 FactCheck: %v", err)
	}
}

// ---------- provider_down：按路由策略真实结构精确解析（PG） ----------

func TestT6ProviderDownPolicyStructurePG(t *testing.T) {
	f := t6NewFixture(t)
	ctx := context.Background()
	ex := func(sql string, args ...any) {
		t.Helper()
		if _, err := f.conn.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("夹具失败: %v\n%s", err, sql)
		}
	}
	t.Cleanup(func() {
		_, _ = f.conn.Exec(context.Background(), `DELETE FROM routing_policies WHERE tenant_id = $1`, f.tenant)
	})
	// 一个停用渠道，名下没有在用模型：是否被报出来只取决于有没有策略真正引用它。
	down := "t6down_" + f.tenant
	ex(`INSERT INTO providers (id, tenant_id, name, provider_type, status) VALUES ($1,$2,'停用渠道甲','openai','disabled')`, down, f.tenant)

	run := func() []Finding {
		return t6RunOne(t, "provider_down", f.x, Scope{TenantID: f.tenant, IsAdmin: true}, nil)
	}
	reset := func() { ex(`DELETE FROM routing_policies WHERE tenant_id = $1`, f.tenant) }
	n := 0
	add := func(scopeType, layer, strategy string, schema int, enabled bool, cfg string) {
		t.Helper()
		n++
		ref := "model-" + fmt.Sprint(n)
		if scopeType == "tenant" {
			ref = f.tenant
		}
		ex(`INSERT INTO routing_policies (id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, schema_version)
VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`, fmt.Sprintf("t6rp%d_%s", n, f.tenant), f.tenant, scopeType, ref, layer, strategy, cfg, enabled, schema)
	}
	q := func(s string) string { return strings.ReplaceAll(s, "DOWN", down) }

	cases := []struct {
		name string
		add  func()
		want bool
	}{
		{"v2 候选启用", func() {
			add("model", "provider", "priority", 2, true, q(`{"strategy":"priority","providers":[{"provider_id":"DOWN","enabled":true,"priority":1}]}`))
		}, true},
		{"v2 租户默认策略候选启用", func() {
			add("tenant", "provider", "weighted", 2, true, q(`{"strategy":"weighted","providers":[{"provider_id":"DOWN","enabled":true,"weight":3}]}`))
		}, true},
		{"v2 fixed 策略", func() {
			add("model", "provider", "fixed", 2, true, q(`{"strategy":"fixed","fixed_provider_id":"DOWN","providers":[]}`))
		}, true},
		{"v3 显式路由启用", func() {
			add("model", "provider", "failover", 3, true, q(`{"mode":"failover","routes":[{"provider_id":"DOWN","enabled":true,"priority":1}]}`))
		}, true},
		{"v1 fallback 链", func() {
			add("model", "provider", "fallback", 1, true, q(`{"provider_chain":["x","DOWN"]}`))
		}, true},
		{"v1 lb 权重候选", func() {
			add("model", "provider", "lb", 1, true, q(`{"weighted_providers":[{"id":"DOWN","weight":5}]}`))
		}, true},
		{"v1 canary 灰度渠道", func() {
			add("model", "provider", "canary", 1, true, q(`{"stable_provider":"x","canary_provider":"DOWN","canary_ratio":10}`))
		}, true},
		// ---- 以下都不应误报 ----
		{"v2 候选 enabled=false", func() {
			add("model", "provider", "priority", 2, true, q(`{"strategy":"priority","providers":[{"provider_id":"DOWN","enabled":false,"priority":1}]}`))
		}, false},
		{"非 fixed 策略遗留的 fixed_provider_id", func() {
			add("model", "provider", "priority", 2, true, q(`{"strategy":"priority","fixed_provider_id":"DOWN","providers":[]}`))
		}, false},
		{"策略本身被停用", func() {
			add("model", "provider", "priority", 2, false, q(`{"strategy":"priority","providers":[{"provider_id":"DOWN","enabled":true,"priority":1}]}`))
		}, false},
		{"模型层策略关键词里出现渠道 ID", func() {
			add("model", "model", "conditional", 1, true, q(`{"high_keywords":["DOWN"],"default_model":"DOWN"}`))
		}, false},
		{"渠道 ID 只是另一个 ID 的子串", func() {
			add("model", "provider", "priority", 2, true, q(`{"strategy":"priority","providers":[{"provider_id":"DOWN-backup","enabled":true,"priority":1}]}`))
		}, false},
		{"渠道 ID 出现在无关的自定义字段", func() {
			add("model", "provider", "priority", 2, true, q(`{"strategy":"priority","providers":[{"provider_id":"other","enabled":true,"priority":1}],"note":"DOWN","custom_order":["DOWN"]}`))
		}, false},
		{"v1 lb 权重为 0 的候选", func() {
			add("model", "provider", "lb", 1, true, q(`{"weighted_providers":[{"id":"DOWN","weight":0}]}`))
		}, false},
		{"v1 fallback 链不是数组（脏数据不能让查询报错）", func() {
			add("model", "provider", "fallback", 1, true, q(`{"provider_chain":"DOWN"}`))
		}, false},
		{"v2 providers 不是数组（脏数据）", func() {
			add("model", "provider", "priority", 2, true, q(`{"strategy":"priority","providers":{"provider_id":"DOWN","enabled":true}}`))
		}, false},
	}
	for _, c := range cases {
		reset()
		c.add()
		fs := run()
		got := len(fs) == 1 && strings.Contains(fs[0].Title, "停用渠道甲")
		if got != c.want {
			t.Errorf("%s：期望报出=%v，实际=%v（%+v）", c.name, c.want, got, fs)
		}
	}
}

func TestT6ProviderDownSQLHasNoStringMatch(t *testing.T) {
	if strings.Contains(t6PolicyRefsProvider, "position(") || strings.Contains(t6PolicyRefsProvider, "::text in") {
		t.Fatal("路由策略引用判断不应再用字符串近似匹配")
	}
}

// ---------- 密钥模型白名单（体检项）----------

func TestT6KeyModelDeniedCheck(t *testing.T) {
	t.Run("按密钥聚合并给确定结论", func(t *testing.T) {
		q := (&t6Fake{}).on("t6:key_model_denied", map[string]any{"key_id": "k1", "key_prefix": "sk-ab12", "key_name": "编程助手",
			"model_name": "gpt-6.1-sol", "count": int64(4), "samples": []any{t6ReqID(1)}})
		fs := t6RunOne(t, "key_model_allowlist", q, t6Admin(), nil)
		if len(fs) != 1 || fs[0].Level != LevelConfirmed || fs[0].Severity != SevError {
			t.Fatalf("%+v", fs)
		}
		for _, kw := range []string{"sk-ab12", "编程助手", "gpt-6.1-sol", "白名单"} {
			if !strings.Contains(fs[0].Title, kw) {
				t.Errorf("标题缺少 %q：%s", kw, fs[0].Title)
			}
		}
		if len(fs[0].Advice) == 0 || fs[0].Advice[0].Link != "/keys?key_id=k1" {
			t.Errorf("建议应链接到密钥管理页: %+v", fs[0].Advice)
		}
		t6AssertChinese(t, fs[0])
	})
	t.Run("员工看不到后台链接", func(t *testing.T) {
		q := (&t6Fake{}).on("t6:key_model_denied", map[string]any{"key_id": "k1", "key_prefix": "sk-ab12", "count": int64(1), "samples": []any{}})
		fs := t6RunOne(t, "key_model_allowlist", q, t6Staff(), nil)
		if len(fs) != 1 || fs[0].Advice[0].Link != "" || !strings.Contains(fs[0].Advice[0].Text, "联系管理员") {
			t.Fatalf("%+v", fs)
		}
	})
	t.Run("没有被拒绝的请求不报", func(t *testing.T) {
		if fs := t6RunOne(t, "key_model_allowlist", &t6Fake{}, t6Admin(), nil); len(fs) != 0 {
			t.Fatalf("不应触发 %+v", fs)
		}
	})
	t.Run("网关模型拒绝不算上游鉴权失败", func(t *testing.T) {
		if !t6IsGateway(t6Row{Status: "key_model_not_allowed", Code: 403}) || !t6IsGateway(t6Row{Status: "forbidden_model", Code: 403}) {
			t.Fatal("key_model_not_allowed / forbidden_model 应视为网关自身拒绝")
		}
	})
}
