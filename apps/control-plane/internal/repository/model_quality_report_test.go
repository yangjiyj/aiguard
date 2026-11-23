package repository

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestModelQualityCalendarWindowUsesVisibleTimezone(t *testing.T) {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	window, err := ParseModelQualityWindow("2026-03", "America/New_York", now)
	if err != nil {
		t.Fatal(err)
	}
	if window.End.Sub(window.Start) != 31*24*time.Hour-time.Hour {
		t.Fatalf("DST calendar month = %v", window.End.Sub(window.Start))
	}
	cn, err := ParseModelQualityWindow("2026-10", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if cn.Start != time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC) || cn.End != time.Date(2026, 10, 31, 16, 0, 0, 0, time.UTC) {
		t.Fatalf("incorrect Shanghai month: %+v", cn)
	}
	for _, input := range [][2]string{{"2026-13", "UTC"}, {"2026-1", "UTC"}, {"2019-12", "UTC"}, {"2026-10", "invalid/location"}, {"2026-10", "UTC\n"}} {
		if _, err = ParseModelQualityWindow(input[0], input[1], now); err == nil {
			t.Fatalf("invalid calendar accepted: %v", input)
		}
	}
}

func modelQualityTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("MODEL_QUALITY_TEST_DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL / MODEL_QUALITY_TEST_DATABASE_URL 未设置")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "model_quality_" + uuid.NewString()[:8]
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	if _, err = db.Exec(ctx, `CREATE TABLE providers(id text PRIMARY KEY,tenant_id text,name text);
 CREATE TABLE models(id text PRIMARY KEY,provider_id text,model_name text,model_label text);
 CREATE TABLE request_logs(id text PRIMARY KEY,tenant_id text,provider_id text,model_id text,request_status text,upstream_status_code integer,latency_ms integer,upstream_ttft_ms bigint,created_at timestamptz, agent_instance_id varchar(128),output_audit_result jsonb,input_tokens integer,output_tokens integer);
 CREATE INDEX ON request_logs(tenant_id,created_at);
 INSERT INTO providers VALUES('provider-a','tenant-a','Provider A'),('provider-b','tenant-b','private-foreign-provider');
 INSERT INTO models VALUES('model-a','provider-a','model-a','Model A'),('model-b','provider-b','private-foreign-model','private-foreign-model');`); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestModelQualityMonthlyEvidencePreservesUnknownAndIsolation(t *testing.T) {
	db := modelQualityTestDB(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO request_logs(id,tenant_id,provider_id,model_id,request_status,upstream_status_code,latency_ms,upstream_ttft_ms,created_at) VALUES
 ('ok-a','tenant-a','provider-a','model-a','success',200,100,10,'2026-10-01T15:59:00Z'),
 ('fail-a','tenant-a','provider-a','model-a','failed',500,200,NULL,'2026-10-01T15:59:30Z'),
 ('ok-b','tenant-a','provider-a','model-a','success',200,300,30,'2026-10-01T16:00:00Z'),
 ('client','tenant-a','provider-a','model-a','failed',400,400,NULL,'2026-10-01T16:01:00Z'),
 ('auth','tenant-a','provider-a','model-a','failed',401,400,NULL,'2026-10-01T16:01:30Z'),
 ('cancel','tenant-a','provider-a','model-a','cancelled',499,999,999,'2026-10-01T16:02:00Z'),
 ('blocked','tenant-a','provider-a','model-a','blocked',403,999,999,'2026-10-01T16:03:00Z'),
 ('unknown','tenant-a','provider-a','model-a','pending',NULL,999,999,'2026-10-01T16:04:00Z'),
 ('outside','tenant-a','provider-a','model-a','failed',500,999,NULL,'2026-09-30T15:59:00Z'),
 ('foreign','tenant-b','provider-b','model-b','failed',500,999,NULL,'2026-10-01T16:00:00Z');`); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	window, _ := ParseModelQualityWindow("2026-10", "Asia/Shanghai", now)
	repo := NewModelQualityReportRepository(db)
	report, err := repo.Report(ctx, "tenant-a", "", "", window, now)
	if err != nil {
		t.Fatal(err)
	}
	m := report.Totals
	if !report.Available || !report.InProgress || m.Requests != 8 || m.EligibleRequests != 5 || m.PlatformFailures != 2 || m.AuthFailures != 1 || m.ClientErrors != 1 || m.Blocked != 1 || m.Cancelled != 1 || m.Unknown != 1 || m.HTTPSuccesses != 2 {
		t.Fatalf("evidence counts = %+v", m)
	}
	if m.Availability == nil || *m.Availability != 0.6 || m.P50MS == nil || *m.P50MS != 200 || m.FirstEventSamples != 2 || m.ActiveMinutes != 3 || m.DownMinutes != 2 {
		t.Fatalf("incorrect denominator/latency/minutes = %+v", m)
	}
	if len(report.Days) != 2 || report.Days[0].Day != "2026-10-01" || report.Days[1].Day != "2026-10-02" {
		t.Fatalf("calendar days = %+v", report.Days)
	}
	if len(report.Models) != 1 || report.Models[0].ActiveMinutes != 3 {
		t.Fatalf("target active minutes = %+v", report.Models)
	}
	encoded, _ := json.Marshal(report)
	if string(encoded) == "" {
		t.Fatal("report empty")
	}
	for _, filter := range [][2]string{{"provider-b", ""}, {"", "model-b"}} {
		if _, err = repo.Report(ctx, "tenant-a", filter[0], filter[1], window, now); err != ErrModelQualityScopeNotFound {
			t.Fatalf("foreign scope = %v", err)
		}
	}
}

func TestModelQualityEmptyMonthIsNotPerfectAvailability(t *testing.T) {
	db := modelQualityTestDB(t)
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	window, _ := ParseModelQualityWindow("2026-09", "UTC", now)
	report, err := NewModelQualityReportRepository(db).Report(context.Background(), "tenant-a", "", "", window, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Available || report.InProgress || report.Totals.Availability != nil || report.Totals.MinuteAvailability != nil || report.Totals.P50MS != nil || report.Totals.FirstEventP50MS != nil || len(report.Models) != 0 || len(report.Days) != 0 {
		t.Fatalf("no evidence promoted to healthy: %+v", report)
	}
}

// 真库测试使用独立 schema，观察聚合结果和窗口扫描计划，不接触业务表。
func TestModelQualityTimingMetrics(t *testing.T) {
	db := modelQualityTestDB(t)
	ctx := context.Background()
	_, err := db.Exec(ctx, `INSERT INTO request_logs(id,tenant_id,provider_id,model_id,request_status,upstream_status_code,latency_ms,upstream_ttft_ms,created_at,output_audit_result,input_tokens,output_tokens) VALUES
 ('timing-a','tenant-a','provider-a','model-a','success',200,1000,100,'2026-10-01T00:00:00Z','{"response_metadata":{"timing":{"input_security_ms":10,"output_security_ms":20,"pre_upstream_ms":40,"generation_ms":500}}}',20,50),
 ('timing-b','tenant-a','provider-a','model-a','success',200,1100,100,'2026-10-01T00:00:30Z','{}',30,100)`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 1, 0, 1, 0, 0, time.UTC)
	window, _ := ParseModelQualityWindow("2026-10", "UTC", now)
	report, err := NewModelQualityReportRepository(db).Report(ctx, "tenant-a", "", "", window, now)
	if err != nil {
		t.Fatal(err)
	}
	m := report.Totals
	if m.OutputTokensPerSecP50 == nil || *m.OutputTokensPerSecP50 != 100 || m.SecurityP50MS == nil || *m.SecurityP50MS != 30 || m.SecurityP95MS == nil || *m.SecurityP95MS != 30 || m.PreUpstreamP50MS == nil || *m.PreUpstreamP50MS != 40 || m.PreUpstreamP95MS == nil || *m.PreUpstreamP95MS != 40 || m.RPM == nil || *m.RPM != 2 || m.TPM == nil || *m.TPM != 200 {
		t.Fatalf("性能聚合口径错误: %+v", m)
	}
	if len(report.Models) != 1 || report.Models[0].OutputTokensPerSecP50 == nil {
		t.Fatalf("模型供应商分组缺少新指标: %+v", report.Models)
	}
	rows, err := db.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) "+modelQualitySourceSQL+" SELECT "+modelQualityAggregateSQL+" FROM observations", "tenant-a", window.Start, now, "", "", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var line string
		if err = rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		t.Log(line)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Log("观察点：生产数据量下租户+created_at 索引扫描、窗口内实际行数、聚合排序内存/磁盘及共享缓冲区；小 fixture 顺序扫描正常。")
}
