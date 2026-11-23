package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type auditQueryBenchmarkCase struct {
	name       string
	path       string
	handler    http.HandlerFunc
	routeParam map[string]string
	budgetMS   float64
	minItems   int
}

type auditQueryBenchmarkSample struct {
	DurationMS float64 `json:"duration_ms"`
	BodyBytes  int     `json:"response_body_bytes"`
	Status     int     `json:"status"`
	Items      int     `json:"items"`
	ErrorCode  string  `json:"error_code,omitempty"`
}

type auditQueryBenchmarkResult struct {
	Case            string                      `json:"case"`
	Phase           string                      `json:"phase"`
	Rows            int                         `json:"rows"`
	Iterations      int                         `json:"iterations"`
	Concurrency     int                         `json:"concurrency"`
	P50MS           float64                     `json:"p50_ms"`
	P95MS           float64                     `json:"p95_ms"`
	MaxMS           float64                     `json:"max_ms"`
	BodyBytes       int                         `json:"response_body_bytes"`
	BudgetMS        float64                     `json:"budget_ms"`
	GoalMet         bool                        `json:"goal_met"`
	CompletenessMet bool                        `json:"completeness_met"`
	Successes       int                         `json:"successes"`
	StatusCounts    map[int]int                 `json:"status_counts"`
	Samples         []auditQueryBenchmarkSample `json:"samples"`
	GoOS            string                      `json:"go_os"`
	GoArch          string                      `json:"go_arch"`
	GoCPUs          int                         `json:"go_cpus"`
	PGVersion       string                      `json:"postgres_version"`
	PGSettings      map[string]string           `json:"postgres_settings"`
}

func TestAuditQueryBudgetBenchmark(t *testing.T) {
	dsn := os.Getenv("JJD_QUERY_BENCHMARK_DSN")
	if dsn == "" {
		t.Skip("JJD_QUERY_BENCHMARK_DSN is not set")
	}
	phase := os.Getenv("JJD_QUERY_BENCHMARK_PHASE")
	if phase == "" {
		phase = "hot"
	}
	selected := os.Getenv("JJD_QUERY_BENCHMARK_CASE")
	rowCount, _ := strconv.Atoi(os.Getenv("JJD_QUERY_BENCHMARK_ROWS"))
	if rowCount <= 0 {
		rowCount = 100000
	}

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse benchmark DSN: %v", err)
	}
	config.MaxConns = 12
	config.MinConns = 0
	config.ConnConfig.RuntimeParams["application_name"] = "jjdguard-audit-query-budget"
	config.ConnConfig.RuntimeParams["statement_timeout"] = "15s"
	if os.Getenv("JJD_QUERY_BENCHMARK_EXPLAIN") == "1" {
		config.MaxConns = 1
		config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			_, err := conn.Exec(ctx, `
				LOAD 'auto_explain';
				SET auto_explain.log_min_duration = 0;
				SET auto_explain.log_analyze = on;
				SET auto_explain.log_buffers = on;
				SET auto_explain.log_timing = on;
				SET auto_explain.log_nested_statements = on;
				SET auto_explain.log_format = json
			`)
			return err
		}
	}
	db, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("connect benchmark database: %v", err)
	}
	defer db.Close()
	if err := db.Ping(context.Background()); err != nil {
		t.Fatalf("ping benchmark database: %v", err)
	}

	requests := repository.NewRequestLogRepository(db)
	contents := repository.NewContentLogRepository(db, "customer")
	users := repository.NewUserRepository(db)
	alerts := repository.NewAlertGroupRepository(db)
	tools := repository.NewToolCallLogRepository(db)
	deps := &Dependencies{
		UserRepo:               users,
		RequestLogRepo:         requests,
		SecurityEventRepo:      repository.NewSecurityEventRepository(db),
		ForwardProxyAccessRepo: requests,
		EvidenceRunRepo:        requests,
		ContentLogRepo:         contents,
		ContentAuditSelector:   ContentAuditSelectorDependencies{Users: users},
		ToolCallLogRepo:        tools,
		AlertGroupRepo:         alerts,
		SystemRepo:             repository.NewSystemRepository(db),
	}

	window := url.Values{
		"from": {"2026-08-01T00:00:00Z"},
		"to":   {"2026-10-01T00:00:00Z"},
	}
	path := func(base string, extra url.Values) string {
		values := url.Values{}
		for key, items := range window {
			values[key] = append([]string{}, items...)
		}
		for key, items := range extra {
			values[key] = append([]string{}, items...)
		}
		return base + "?" + values.Encode()
	}
	cases := []auditQueryBenchmarkCase{
		{name: "content_main", path: path("/admin/v1/audit/content", url.Values{"alert_only": {"true"}, "limit": {"20"}, "offset": {"0"}}), handler: ListContentAudit(deps), budgetMS: 500},
		{name: "content_user", path: path("/admin/v1/audit/content", url.Values{"alert_only": {"true"}, "user_id": {"bench-user-7"}, "limit": {"20"}, "offset": {"0"}}), handler: ListContentAudit(deps), budgetMS: 500},
		{name: "content_keyword_zh2", path: path("/admin/v1/audit/content", url.Values{"alert_only": {"true"}, "keyword": {"异常"}, "limit": {"20"}, "offset": {"0"}}), handler: ListContentAudit(deps), budgetMS: 1000},
		{name: "content_keyword_acl_only", path: path("/admin/v1/audit/content", url.Values{"alert_only": {"true"}, "keyword": {"仅 access_content_logs"}, "limit": {"20"}, "offset": {"0"}}), handler: ListContentAudit(deps), budgetMS: 1000, minItems: 1},
		{name: "content_keyword_content_only", path: path("/admin/v1/audit/content", url.Values{"alert_only": {"true"}, "keyword": {"仅 content_logs"}, "limit": {"20"}, "offset": {"0"}}), handler: ListContentAudit(deps), budgetMS: 1000, minItems: 1},
		{name: "content_keyword_old_tail", path: path("/admin/v1/audit/content", url.Values{"alert_only": {"true"}, "keyword": {"旧会话尾部命中"}, "limit": {"20"}, "offset": {"0"}}), handler: ListContentAudit(deps), budgetMS: 1000, minItems: 1},
		{name: "content_deep_1001", path: path("/admin/v1/audit/content", url.Values{"alert_only": {"true"}, "limit": {"20"}, "offset": {"1000"}}), handler: ListContentAudit(deps), budgetMS: 750},
		{name: "content_users", path: "/admin/v1/audit/content/users?q=用户&limit=50", handler: ListContentAuditUsers(deps), budgetMS: 250},
		{name: "access_records", path: path("/admin/v1/audit/access-retention", url.Values{"content_only": {"true"}, "skip_summary": {"true"}, "skip_total": {"true"}, "limit": {"20"}, "offset": {"0"}}), handler: ListForwardProxyAccess(deps), budgetMS: 500},
		{name: "access_records_exact_count", path: path("/admin/v1/audit/access-retention", url.Values{"content_only": {"true"}, "skip_summary": {"true"}, "skip_total": {"false"}, "limit": {"20"}, "offset": {"0"}}), handler: ListForwardProxyAccess(deps), budgetMS: 500},
		{name: "access_deep_1001", path: path("/admin/v1/audit/access-retention", url.Values{"content_only": {"true"}, "skip_summary": {"true"}, "skip_total": {"true"}, "limit": {"20"}, "offset": {"1000"}}), handler: ListForwardProxyAccess(deps), budgetMS: 750},
		{name: "access_deep_1001_exact_count", path: path("/admin/v1/audit/access-retention", url.Values{"content_only": {"true"}, "skip_summary": {"true"}, "skip_total": {"false"}, "limit": {"20"}, "offset": {"1000"}}), handler: ListForwardProxyAccess(deps), budgetMS: 750},
		{name: "access_keyword_zh2", path: path("/admin/v1/audit/access-retention", url.Values{"content_only": {"true"}, "skip_summary": {"true"}, "keyword": {"异常"}, "limit": {"20"}, "offset": {"0"}}), handler: ListForwardProxyAccess(deps), budgetMS: 1000},
		{name: "access_keyword_acl_only", path: path("/admin/v1/audit/access-retention", url.Values{"content_only": {"true"}, "skip_summary": {"true"}, "keyword": {"仅 access_content_logs"}, "limit": {"20"}, "offset": {"0"}}), handler: ListForwardProxyAccess(deps), budgetMS: 1000, minItems: 1},
		{name: "access_keyword_content_only", path: path("/admin/v1/audit/access-retention", url.Values{"content_only": {"true"}, "skip_summary": {"true"}, "keyword": {"仅 content_logs"}, "limit": {"20"}, "offset": {"0"}}), handler: ListForwardProxyAccess(deps), budgetMS: 1000, minItems: 1},
		{name: "access_keyword_old_tail", path: path("/admin/v1/audit/access-retention", url.Values{"content_only": {"true"}, "skip_summary": {"true"}, "keyword": {"旧会话尾部命中"}, "limit": {"20"}, "offset": {"0"}}), handler: ListForwardProxyAccess(deps), budgetMS: 1000, minItems: 1},
		{name: "access_runs", path: path("/admin/v1/audit/access-retention/runs", url.Values{"view": {"agent_tasks"}, "skip_total": {"true"}, "limit": {"20"}, "offset": {"0"}}), handler: ListEvidenceRuns(deps), budgetMS: 750},
		{name: "access_runs_exact_count", path: path("/admin/v1/audit/access-retention/runs", url.Values{"view": {"agent_tasks"}, "skip_total": {"false"}, "limit": {"20"}, "offset": {"0"}}), handler: ListEvidenceRuns(deps), budgetMS: 750},
		{name: "access_counts", path: path("/admin/v1/audit/access-retention", url.Values{"summary_only": {"true"}, "summary_detail": {"counts"}, "content_only": {"true"}}), handler: ListForwardProxyAccess(deps), budgetMS: 750},
		{name: "access_summary", path: path("/admin/v1/audit/access-retention", url.Values{"summary_only": {"true"}, "content_only": {"true"}}), handler: ListForwardProxyAccess(deps), budgetMS: 2000},
		{name: "alert_detail", path: "/admin/v1/alert-groups/ag-bench-0", handler: GetAlertGroup(deps), routeParam: map[string]string{"id": "ag-bench-0"}, budgetMS: 250},
		{name: "alert_events", path: "/admin/v1/alert-groups/ag-bench-0/events?view=events&limit=20&offset=0", handler: ListAlertGroupEvents(deps), routeParam: map[string]string{"id": "ag-bench-0"}, budgetMS: 500},
		{name: "alert_events_deep_1001", path: "/admin/v1/alert-groups/ag-bench-0/events?view=events&limit=20&offset=1000", handler: ListAlertGroupEvents(deps), routeParam: map[string]string{"id": "ag-bench-0"}, budgetMS: 750},
		{name: "tool_audit_exact_count", path: path("/admin/v1/audit/tools/high-risk", url.Values{"risk_level": {"all"}, "limit": {"20"}, "offset": {"0"}, "skip_total": {"false"}}), handler: ListHighRiskToolCalls(deps), budgetMS: 500},
		{name: "tool_audit_101", path: path("/admin/v1/audit/tools/high-risk", url.Values{"risk_level": {"all"}, "limit": {"20"}, "offset": {"100"}, "skip_total": {"false"}}), handler: ListHighRiskToolCalls(deps), budgetMS: 500},
		{name: "tool_audit_1001", path: path("/admin/v1/audit/tools/high-risk", url.Values{"risk_level": {"all"}, "limit": {"20"}, "offset": {"1000"}, "skip_total": {"false"}}), handler: ListHighRiskToolCalls(deps), budgetMS: 750},
		{name: "tool_audit_keyword_zh2", path: path("/admin/v1/audit/tools/high-risk", url.Values{"risk_level": {"all"}, "keyword": {"基准"}, "limit": {"20"}, "offset": {"0"}}), handler: ListHighRiskToolCalls(deps), budgetMS: 1000, minItems: 1},
	}

	pgVersion, pgSettings := auditQueryBenchmarkPGInfo(t, db)
	for _, benchCase := range cases {
		if selected != "" && selected != benchCase.name {
			continue
		}
		result := runAuditQueryBenchmarkCase(t, benchCase, phase, rowCount)
		result.PGVersion = pgVersion
		result.PGSettings = pgSettings
		writeAuditQueryBenchmarkResult(t, result)
	}
	if selected != "" && !auditQueryBenchmarkCaseExists(cases, selected) {
		t.Fatalf("unknown benchmark case %q", selected)
	}
	if phase == "hot" && (selected == "" || selected == "access_keyword_zh2") {
		cancelResult := runAuditQueryCancellationProbe(t, auditQueryBenchmarkCaseByName(t, cases, "access_keyword_zh2"), rowCount)
		cancelResult.PGVersion = pgVersion
		cancelResult.PGSettings = pgSettings
		writeAuditQueryBenchmarkResult(t, cancelResult)
	}
}

func auditQueryBenchmarkCaseByName(t *testing.T, cases []auditQueryBenchmarkCase, name string) auditQueryBenchmarkCase {
	t.Helper()
	for _, item := range cases {
		if item.name == name {
			return item
		}
	}
	t.Fatalf("benchmark case %q not found", name)
	return auditQueryBenchmarkCase{}
}

func auditQueryBenchmarkCaseExists(cases []auditQueryBenchmarkCase, name string) bool {
	for _, item := range cases {
		if item.name == name {
			return true
		}
	}
	return false
}

func runAuditQueryBenchmarkCase(t *testing.T, benchCase auditQueryBenchmarkCase, phase string, rows int) auditQueryBenchmarkResult {
	t.Helper()
	iterations, concurrency := 1, 1
	switch phase {
	case "pg_restart_cold", "explain":
	case "hot":
		iterations = 5
		if _, err := invokeAuditQueryBenchmarkHandler(context.Background(), benchCase); err != nil {
			t.Fatalf("warm %s: %v", benchCase.name, err)
		}
	case "concurrent":
		iterations, concurrency = 10, 10
		if _, err := invokeAuditQueryBenchmarkHandler(context.Background(), benchCase); err != nil {
			t.Fatalf("warm %s: %v", benchCase.name, err)
		}
	default:
		t.Fatalf("unsupported benchmark phase %q", phase)
	}

	samples := make([]auditQueryBenchmarkSample, iterations)
	if concurrency == 1 {
		for i := range samples {
			sample, err := invokeAuditQueryBenchmarkHandler(context.Background(), benchCase)
			if err != nil && phase != "explain" {
				t.Fatalf("%s: %v", benchCase.name, err)
			}
			samples[i] = sample
		}
	} else {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range samples {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				<-start
				samples[index], _ = invokeAuditQueryBenchmarkHandler(context.Background(), benchCase)
			}(i)
		}
		close(start)
		wg.Wait()
	}

	durations := make([]float64, len(samples))
	bodyBytes := 0
	successes := 0
	statusCounts := map[int]int{}
	completenessMet := true
	for i, sample := range samples {
		durations[i] = sample.DurationMS
		statusCounts[sample.Status]++
		if sample.Status == http.StatusOK && sample.ErrorCode == "" {
			successes++
		}
		if sample.ErrorCode != "" {
			completenessMet = false
		}
		if sample.Status == http.StatusOK && sample.Items < benchCase.minItems {
			completenessMet = false
		}
		if sample.BodyBytes > bodyBytes {
			bodyBytes = sample.BodyBytes
		}
	}
	sort.Float64s(durations)
	p50 := auditQueryPercentile(durations, 0.50)
	p95 := auditQueryPercentile(durations, 0.95)
	return auditQueryBenchmarkResult{
		Case: benchCase.name, Phase: phase, Rows: rows, Iterations: iterations, Concurrency: concurrency,
		P50MS: p50, P95MS: p95, MaxMS: durations[len(durations)-1], BodyBytes: bodyBytes,
		BudgetMS: benchCase.budgetMS, GoalMet: p95 <= benchCase.budgetMS && successes == iterations && completenessMet,
		CompletenessMet: completenessMet,
		Successes:       successes, StatusCounts: statusCounts, Samples: samples,
		GoOS: runtime.GOOS, GoArch: runtime.GOARCH, GoCPUs: runtime.NumCPU(),
	}
}

func invokeAuditQueryBenchmarkHandler(ctx context.Context, benchCase auditQueryBenchmarkCase) (auditQueryBenchmarkSample, error) {
	request := httptest.NewRequest(http.MethodGet, benchCase.path, nil)
	user := &repository.User{ID: "bench-user-7", Username: "bench-user-7", TenantID: "tenant_default", Role: "platform_admin"}
	session := &repository.Session{UserID: user.ID, Username: user.Username, TenantID: user.TenantID, Role: user.Role}
	requestCtx := context.WithValue(request.Context(), auth.UserKey, user)
	requestCtx = context.WithValue(requestCtx, auth.SessionKey, session)
	if ctx != nil {
		select {
		case <-ctx.Done():
			cancelled, cancel := context.WithCancel(requestCtx)
			cancel()
			requestCtx = cancelled
		default:
		}
	}
	if len(benchCase.routeParam) > 0 {
		routeContext := chi.NewRouteContext()
		for key, value := range benchCase.routeParam {
			routeContext.URLParams.Add(key, value)
		}
		requestCtx = context.WithValue(requestCtx, chi.RouteCtxKey, routeContext)
	}
	request = request.WithContext(requestCtx)
	recorder := httptest.NewRecorder()
	started := time.Now()
	benchCase.handler(recorder, request)
	duration := time.Since(started)
	sample := auditQueryBenchmarkSample{
		DurationMS: float64(duration.Microseconds()) / 1000,
		BodyBytes:  recorder.Body.Len(),
		Status:     recorder.Code,
		Items:      auditQueryBenchmarkResponseItems(recorder.Body.Bytes()),
		ErrorCode:  auditQueryBenchmarkResponseError(recorder.Body.Bytes()),
	}
	if recorder.Code != http.StatusOK {
		return sample, fmt.Errorf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	return sample, nil
}

func auditQueryBenchmarkResponseError(body []byte) string {
	var payload struct {
		SummaryError string `json:"summary_error"`
		Error        struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return "invalid_json"
	}
	if payload.Error.Code != "" {
		return payload.Error.Code
	}
	return payload.SummaryError
}

func TestAuditQueryBenchmarkResponseError(t *testing.T) {
	for _, test := range []struct {
		body string
		want string
	}{
		{body: `{"data":[],"summary_error":"summary_unavailable"}`, want: "summary_unavailable"},
		{body: `{"error":{"code":"search_timeout"}}`, want: "search_timeout"},
		{body: `{"data":[]}`},
		{body: `not-json`, want: "invalid_json"},
	} {
		if got := auditQueryBenchmarkResponseError([]byte(test.body)); got != test.want {
			t.Fatalf("body=%q error=%q want=%q", test.body, got, test.want)
		}
	}
}

func auditQueryBenchmarkResponseItems(body []byte) int {
	var payload map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil {
		return 0
	}
	for _, key := range []string{"data", "items"} {
		raw := payload[key]
		var items []json.RawMessage
		if len(raw) > 0 && json.Unmarshal(raw, &items) == nil {
			return len(items)
		}
	}
	if len(payload["item"]) > 0 && string(payload["item"]) != "null" {
		return 1
	}
	return 0
}

func runAuditQueryCancellationProbe(t *testing.T, benchCase auditQueryBenchmarkCase, rows int) auditQueryBenchmarkResult {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	sample, err := invokeAuditQueryBenchmarkHandler(ctx, benchCase)
	duration := time.Since(started)
	if err == nil {
		t.Fatal("cancelled query unexpectedly returned HTTP 200")
	}
	sample.DurationMS = float64(duration.Microseconds()) / 1000
	budget := 250.0
	return auditQueryBenchmarkResult{
		Case: "cancellation_access_keyword", Phase: "cancelled", Rows: rows, Iterations: 1, Concurrency: 1,
		P50MS: sample.DurationMS, P95MS: sample.DurationMS, MaxMS: sample.DurationMS,
		BodyBytes: sample.BodyBytes, BudgetMS: budget, GoalMet: sample.DurationMS <= budget,
		CompletenessMet: true,
		Successes:       0, StatusCounts: map[int]int{sample.Status: 1},
		Samples: []auditQueryBenchmarkSample{sample}, GoOS: runtime.GOOS, GoArch: runtime.GOARCH, GoCPUs: runtime.NumCPU(),
	}
}

func auditQueryPercentile(sorted []float64, percentile float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(math.Ceil(percentile*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	return sorted[index]
}

func auditQueryBenchmarkPGInfo(t *testing.T, db *pgxpool.Pool) (string, map[string]string) {
	t.Helper()
	var version string
	if err := db.QueryRow(context.Background(), "SHOW server_version").Scan(&version); err != nil {
		t.Fatalf("read PostgreSQL version: %v", err)
	}
	settings := map[string]string{}
	for _, name := range []string{"shared_buffers", "work_mem", "effective_cache_size", "random_page_cost", "max_connections", "jit"} {
		var value string
		if err := db.QueryRow(context.Background(), "SELECT current_setting($1)", name).Scan(&value); err != nil {
			t.Fatalf("read PostgreSQL setting %s: %v", name, err)
		}
		settings[name] = value
	}
	return version, settings
}

func writeAuditQueryBenchmarkResult(t *testing.T, result auditQueryBenchmarkResult) {
	t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal benchmark result: %v", err)
	}
	output := os.Getenv("JJD_QUERY_BENCHMARK_OUTPUT")
	if output == "" {
		t.Log(string(raw))
		return
	}
	file, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open benchmark output: %v", err)
	}
	defer file.Close()
	if _, err := file.Write(append(raw, '\n')); err != nil {
		t.Fatalf("write benchmark output: %v", err)
	}
}
