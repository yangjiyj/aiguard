package modelops

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGatedHidesMetricsBelowMinimumSamples(t *testing.T) {
	v := 0.5
	if gated(&v, MinMetricSamples-1) != nil {
		t.Fatal("样本不足时必须返回 nil")
	}
	if got := gated(&v, MinMetricSamples); got == nil || *got != 0.5 {
		t.Fatalf("样本足够时必须保留原值: %v", got)
	}
	if gated(nil, 100) != nil {
		t.Fatal("nil 指标保持 nil")
	}
}

func TestPortalPerformanceWindow(t *testing.T) {
	for _, tc := range []struct{ hours, width, buckets int }{{0, 21600, 28}, {168, 21600, 28}, {24, 3600, 24}} {
		hours, width, buckets, err := portalPerformanceWindow(tc.hours)
		if err != nil || width != tc.width || buckets != tc.buckets || (tc.hours != 0 && hours != tc.hours) || (tc.hours == 0 && hours != 168) {
			t.Fatalf("%d → %d %d %d %v", tc.hours, hours, width, buckets, err)
		}
	}
	for _, bad := range []int{6, 72, -1, 1000} {
		if _, _, _, err := portalPerformanceWindow(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%d 必须拒绝", bad)
		}
	}
}

// perfFixture 在 modelops 现有真库 fixture 上补齐本功能用到的列。
func perfFixture(t *testing.T) (context.Context, *PostgresStore, *pgxpool.Pool) {
	t.Helper()
	ctx, store, pool := fixture(t)
	if _, err := pool.Exec(ctx, `ALTER TABLE request_logs ADD COLUMN routing_decision_json JSONB;
ALTER TABLE models ADD COLUMN capabilities_json JSONB DEFAULT '{}'::jsonb;`); err != nil {
		t.Fatal(err)
	}
	return ctx, store, pool
}

func attemptsJSON(parts ...string) string {
	return `{"model_route_v2":{"attempts":[` + strings.Join(parts, ",") + `]}}`
}

func TestPostgresProviderMonitorAttemptsFallbacksAndErrors(t *testing.T) {
	ctx, store, pool := perfFixture(t)
	ok := func(name string, ms int) string {
		return `{"route":{"provider_name":"` + name + `"},"result":"success","latency_ms":` + strconv.Itoa(ms) + `}`
	}
	fail := func(name, category, status string) string {
		return `{"route":{"provider_name":"` + name + `"},"result":"failed","failure_category":"` + category + `","status_code_category":"` + status + `","latency_ms":50}`
	}
	rows := []string{}
	// 5 次 Provider A 直接成功，带首字延迟，满足门槛。
	for i := 0; i < 5; i++ {
		rows = append(rows, `('ok-`+strconv.Itoa(i)+`','ok-`+strconv.Itoa(i)+`','tenant-a','ma','pa','success',200,1000,200,'`+attemptsJSON(ok("Provider A", 1000))+`',clock_timestamp()-interval '1 hour')`)
	}
	rows = append(rows,
		// A 5xx 后回退到 Claude 成功：A 回退出 1，Claude 回退入 1。
		`('fb-1','fb-1','tenant-a','ma','native','success',200,1500,300,'`+attemptsJSON(fail("Provider A", "upstream_5xx", "5xx"), ok("Claude", 1400))+`',clock_timestamp()-interval '1 hour')`,
		// A 限流、网络错误、取消（取消不进分母）。
		`('rl','rl','tenant-a','ma','pa','failed',429,100,NULL,'`+attemptsJSON(fail("Provider A", "rate_limited", "4xx"))+`',clock_timestamp()-interval '1 hour')`,
		`('net','net','tenant-a','ma','pa','failed',502,100,NULL,'`+attemptsJSON(fail("Provider A", "network_error", ""))+`',clock_timestamp()-interval '1 hour')`,
		`('cx','cx','tenant-a','ma','pa','cancelled',NULL,100,NULL,'`+attemptsJSON(fail("Provider A", "canceled", ""))+`',clock_timestamp()-interval '1 hour')`,
		// 没有 attempts 的旧行：按最终渠道记 1 次；被拦截的不计。
		`('legacy','legacy','tenant-a','ma','pa','failed',500,100,NULL,NULL,clock_timestamp()-interval '1 hour')`,
		`('blocked','blocked','tenant-a','ma','pa','blocked',NULL,10,NULL,NULL,clock_timestamp()-interval '1 hour')`,
		// 网关本地拒绝时 upstream_status_code 记的是本地返回码，没有到达渠道，不计。
		`('no-route','no-route','tenant-a','ma','pa','model_route_unavailable',503,10,NULL,NULL,clock_timestamp()-interval '1 hour')`,
		`('no-native','no-native','tenant-a','ma','pa','responses_native_unavailable',503,10,NULL,NULL,clock_timestamp()-interval '1 hour')`,
		`('governed','governed','tenant-a','ma','pa','governor_blocked',429,10,NULL,NULL,clock_timestamp()-interval '1 hour')`,
		`('client-cx','client-cx','tenant-a','ma','pa','client_canceled',499,10,NULL,NULL,clock_timestamp()-interval '1 hour')`,
		// 渠道名关联不上：单独成行。
		`('ghost','ghost','tenant-a','ma','pa','success',200,100,NULL,'`+attemptsJSON(ok("Ghost", 100))+`',clock_timestamp()-interval '1 hour')`,
		// 其他租户、窗口外的数据不计。
		`('foreign','foreign','tenant-b','mb','pb','success',200,100,NULL,'`+attemptsJSON(ok("Provider B", 100))+`',clock_timestamp()-interval '1 hour')`,
		`('old','old','tenant-a','ma','pa','success',200,100,NULL,'`+attemptsJSON(ok("Provider A", 100))+`',clock_timestamp()-interval '30 hours')`,
	)
	if _, err := pool.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,model_id,provider_id,request_status,upstream_status_code,latency_ms,upstream_ttft_ms,routing_decision_json,created_at) VALUES `+strings.Join(rows, ",")); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetProviderMonitor(ctx, "tenant-a", ReadFilter{WindowHours: 24})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]ProviderStat{}
	for _, item := range got.Items {
		byName[item.ProviderName] = item
	}
	a := byName["Provider A"]
	// A：5 成功 + 5xx + 限流 + 网络 + 旧行 5xx = 9 次尝试（取消不计）。
	if a.ProviderID != "pa" || a.Attempts != 9 || a.Successes != 5 {
		t.Fatalf("Provider A 计数错误: %+v", a)
	}
	if a.Errors != (ErrorBreakdown{HTTP5xx: 2, RateLimited: 1, Network: 1}) || a.FallbackOut != 1 || a.FallbackIn != 0 {
		t.Fatalf("Provider A 错误分布或回退错误: %+v", a)
	}
	if a.SuccessRate == nil || math.Abs(*a.SuccessRate-5.0/9) > 1e-9 || a.TTFTP50MS == nil || *a.TTFTP50MS != 200 || a.LatencyP50MS == nil || *a.LatencyP50MS != 1000 {
		t.Fatalf("Provider A 指标错误: %+v", a)
	}
	c := byName["Claude"]
	if c.ProviderID != "native" || c.Attempts != 1 || c.FallbackIn != 1 || c.SuccessRate != nil || c.TTFTP50MS != nil {
		t.Fatalf("Claude 回退入或门槛错误: %+v", c)
	}
	if g, ok := byName["Ghost"]; !ok || g.ProviderID != "" || g.Attempts != 1 {
		t.Fatalf("未关联渠道必须单独成行: %+v", byName)
	}
	if _, ok := byName["Provider B"]; ok {
		t.Fatal("其他租户数据泄漏")
	}
	if got.Totals.Attempts != 11 || got.Totals.Fallbacks != 1 || got.WindowHours != 24 {
		t.Fatalf("汇总错误: %+v", got.Totals)
	}
	if len(a.Hourly) != 24 || len(a.Models) != 1 || a.Models[0].ModelName != "public-a" || a.Models[0].Attempts != 9 || a.ModelCount != 1 {
		t.Fatalf("趋势或按模型拆分错误: hourly=%d models=%+v", len(a.Hourly), a.Models)
	}
	var trendAttempts int64
	for _, p := range a.Hourly {
		trendAttempts += p.Attempts
	}
	if trendAttempts != 9 {
		t.Fatalf("趋势总数应等于尝试数: %d", trendAttempts)
	}
	filtered, err := store.GetProviderMonitor(ctx, "tenant-a", ReadFilter{WindowHours: 24, ProviderID: "native"})
	if err != nil || len(filtered.Items) != 1 || filtered.Items[0].ProviderID != "native" {
		t.Fatalf("渠道筛选失败: %+v %v", filtered, err)
	}
	if _, err = store.GetProviderMonitor(ctx, "tenant-a", ReadFilter{WindowHours: 5}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("非法窗口必须拒绝: %v", err)
	}
}

func TestPostgresModelPerformanceAggregatesAcrossProvidersWithoutLeakingThem(t *testing.T) {
	ctx, store, pool := perfFixture(t)
	if _, err := pool.Exec(ctx, `UPDATE models SET capabilities_json='{"protocols":{"chat_completions":true,"responses_native":true}}' WHERE id='ma';
INSERT INTO models VALUES('ma2','native','public-a','deployment-a2','active');
UPDATE models SET capabilities_json='{"protocols":{"anthropic_messages":true}}' WHERE id='ma2';`); err != nil {
		t.Fatal(err)
	}
	rows := []string{}
	for i := 0; i < 6; i++ {
		model := "ma"
		if i%2 == 1 {
			model = "ma2"
		}
		id := "s-" + strconv.Itoa(i)
		rows = append(rows, `('`+id+`','`+id+`','tenant-a','`+model+`','pa','success',200,2000,500,'{"response_metadata":{"timing":{"generation_ms":1000}}}',10,50,clock_timestamp()-interval '2 hours')`)
	}
	rows = append(rows,
		`('f-1','f-1','tenant-a','ma','pa','failed',502,100,NULL,'{}',1,0,clock_timestamp()-interval '2 hours')`,
		`('b-1','b-1','tenant-a','ma','pa','blocked',NULL,10,NULL,'{}',1,0,clock_timestamp()-interval '2 hours')`,
		`('c-1','c-1','tenant-a','ma','pa','cancelled',NULL,10,NULL,'{}',1,0,clock_timestamp()-interval '2 hours')`,
		`('x-1','x-1','tenant-b','mb','pb','success',200,10,5,'{}',1,1,clock_timestamp()-interval '2 hours')`,
	)
	if _, err := pool.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,model_id,provider_id,request_status,upstream_status_code,latency_ms,upstream_ttft_ms,output_audit_result,input_tokens,output_tokens,created_at) VALUES `+strings.Join(rows, ",")); err != nil {
		t.Fatal(err)
	}
	report, err := store.GetModelPerformance(ctx, "tenant-a", 24)
	if err != nil {
		t.Fatal(err)
	}
	var a *ModelPerformance
	for i := range report.Data {
		if report.Data[i].ModelName == "public-a" {
			a = &report.Data[i]
		}
		if report.Data[i].ModelName == "public-b" {
			t.Fatal("其他租户模型泄漏")
		}
	}
	if a == nil {
		t.Fatalf("缺少 public-a: %+v", report.Data)
	}
	// 6 成功 + 1 失败进分母；拦截与取消不进。
	if a.Samples != 7 || a.SuccessRate == nil || math.Abs(*a.SuccessRate-6.0/7) > 1e-9 {
		t.Fatalf("成功率口径错误: %+v", a)
	}
	if a.TTFTP50MS == nil || *a.TTFTP50MS != 500 || a.TPSP50 == nil || *a.TPSP50 != 50 || a.LatencyP50MS == nil || *a.LatencyP50MS != 2000 {
		t.Fatalf("性能指标错误: %+v", a)
	}
	if strings.Join(a.Protocols, ",") != "chat,responses,messages" {
		t.Fatalf("协议并集错误: %v", a.Protocols)
	}
	if len(a.Hourly) != 24 || report.WindowHours != 24 {
		t.Fatalf("24 小时窗口应有 24 桶: %d", len(a.Hourly))
	}
	var bucketSamples int64
	for _, p := range a.Hourly {
		bucketSamples += p.Samples
	}
	if bucketSamples != 7 {
		t.Fatalf("趋势样本合计错误: %d", bucketSamples)
	}
	encoded, _ := json.Marshal(report)
	if strings.Contains(string(encoded), "provider") || strings.Contains(string(encoded), "Provider A") {
		t.Fatalf("门户响应不得包含渠道信息: %s", encoded)
	}
	week, err := store.GetModelPerformance(ctx, "tenant-a", 168)
	if err != nil || len(week.Data) == 0 || len(week.Data[0].Hourly) != 28 {
		t.Fatalf("7 天窗口应有 28 桶: %+v %v", week, err)
	}
	if _, err = store.GetModelPerformance(ctx, "tenant-a", 6); !errors.Is(err, ErrInvalid) {
		t.Fatalf("门户只允许 24/168: %v", err)
	}
}

func TestPostgresModelPerformanceIgnoresBufferedBurstsForTPS(t *testing.T) {
	ctx, store, pool := perfFixture(t)
	if _, err := pool.Exec(ctx, `INSERT INTO models VALUES('mburst','pa','public-burst','deployment-burst','active'),('msteady','pa','public-steady','deployment-steady','active')`); err != nil {
		t.Fatal(err)
	}
	rows := []string{}
	// 安全缓冲后整段转发：生成窗口不到 1 秒，几百 token 一次到达，不能算成速度。
	for i, gen := range []int{900, 900, 900, 900, 1200} {
		id := "burst-" + strconv.Itoa(i)
		rows = append(rows, `('`+id+`','`+id+`','tenant-a','mburst','pa','success',200,20000,9000,'{"response_metadata":{"timing":{"generation_ms":`+strconv.Itoa(gen)+`}}}',10,400,clock_timestamp()-interval '1 hour')`)
	}
	for i := 0; i < 5; i++ {
		id := "steady-" + strconv.Itoa(i)
		rows = append(rows, `('`+id+`','`+id+`','tenant-a','msteady','pa','success',200,3000,1000,'{"response_metadata":{"timing":{"generation_ms":2000}}}',10,100,clock_timestamp()-interval '1 hour')`)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,model_id,provider_id,request_status,upstream_status_code,latency_ms,upstream_ttft_ms,output_audit_result,input_tokens,output_tokens,created_at) VALUES `+strings.Join(rows, ",")); err != nil {
		t.Fatal(err)
	}
	report, err := store.GetModelPerformance(ctx, "tenant-a", 24)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]ModelPerformance{}
	for _, m := range report.Data {
		by[m.ModelName] = m
	}
	if b := by["public-burst"]; b.TPSP50 != nil {
		t.Fatalf("生成窗口不足 1 秒的样本不应计入 TPS: %v", *b.TPSP50)
	}
	if s := by["public-steady"]; s.TPSP50 == nil || *s.TPSP50 != 50 {
		t.Fatalf("正常样本 TPS 应为 50: %+v", s.TPSP50)
	}
}
