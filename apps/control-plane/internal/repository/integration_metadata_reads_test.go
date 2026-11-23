package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func metadataReadTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	db := enforcementTestDB(t)
	_, err := db.Exec(context.Background(), `
	CREATE TABLE request_logs(id text PRIMARY KEY,request_id text UNIQUE,tenant_id text,client_id text,created_at timestamptz,policy_note text,model_id text,routing_decision_json jsonb);
	CREATE TABLE security_events(id text PRIMARY KEY,request_id text,tenant_id text,created_at timestamptz,action_taken text,matched_summary jsonb,rule_id text);
	CREATE TABLE content_logs(id text,request_id text,tenant_id text,created_at timestamp,content text);
	CREATE TABLE access_content_logs(id text,request_id text,tenant_id text,created_at timestamptz,request_content_redacted text);
	CREATE TABLE system_settings(key text PRIMARY KEY,value text);
	INSERT INTO internal_keys(id,tenant_id,agent_instance_id) VALUES('key-a','tenant-a','agent-a'),('key-other','tenant-a','agent-other'),('key-b','tenant-b','agent-b'),('empty-agent','tenant-a',''),('blank-agent','tenant-a','  ');
	INSERT INTO system_settings VALUES('log_retention_days','180');`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func insertMetadataRequest(t *testing.T, db *pgxpool.Pool, id, tenant, key string, at time.Time) {
	t.Helper()
	_, err := db.Exec(context.Background(), `INSERT INTO request_logs(id,request_id,tenant_id,client_id,created_at,routing_decision_json,policy_note) VALUES($1,$2,$3,$4,$5,'{"model_route_v2":{"requested_model":"请求的模型"}}','key_model_outside_allowlist')`, "log-"+id, "req-"+id, tenant, key, at)
	if err != nil {
		t.Fatal(err)
	}
}

func insertMetadataEvent(t *testing.T, db *pgxpool.Pool, id, req, tenant, action, summary string, at time.Time) {
	t.Helper()
	_, err := db.Exec(context.Background(), `INSERT INTO security_events(id,request_id,tenant_id,created_at,action_taken,matched_summary) VALUES($1,$2,$3,$4,$5,$6::jsonb)`, id, "req-"+req, tenant, at, action, summary)
	if err != nil {
		t.Fatal(err)
	}
}

const metadataDLPFinding = `{"type":"secret","category":"openai_key","rule_id":"policy-a","policy_code":"策略代码","policy_scene":"data_leak","action":"block","matched_capabilities":["openai_key"],"matched_text":"正文测试标记","raw_evidence":"正文测试标记"}`

func TestCredentialHitsTenantScopeProjectionAndActualAction(t *testing.T) {
	db := metadataReadTestDB(t)
	repo := NewIntegrationRepository(db)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Second)
	for _, f := range []struct{ id, tenant, key string }{{"a", "tenant-a", "key-a"}, {"other", "tenant-a", "key-other"}, {"b", "tenant-b", "key-b"}, {"forged", "tenant-b", "key-a"}} {
		insertMetadataRequest(t, db, f.id, f.tenant, f.key, at)
		insertMetadataEvent(t, db, "evt-"+f.id, f.id, f.tenant, "security_audit_only", `{"summary":"正文测试标记","findings":[`+metadataDLPFinding+`,`+metadataDLPFinding+`]}`, at)
	}
	// 相同请求上的另一个租户事件不能被关联进来。
	insertMetadataEvent(t, db, "evt-wrong-tenant", "a", "tenant-b", "security_blocked", `{"findings":[`+metadataDLPFinding+`]}`, at)
	insertMetadataEvent(t, db, "evt-model", "a", "tenant-a", "security_audit", `{"findings":[{"category":"key_model_outside_allowlist","matched_text":"正文测试标记"}]}`, at)
	insertMetadataEvent(t, db, "evt-mask", "a", "tenant-a", "security_masked", `{"findings":[`+metadataDLPFinding+`]}`, at)
	insertMetadataEvent(t, db, "evt-block", "a", "tenant-a", "security_blocked", `{"findings":[`+metadataDLPFinding+`]}`, at)
	insertMetadataEvent(t, db, "evt-builtin", "a", "tenant-a", "audit", `{"findings":[{"category":"openai_key","type":"secret"}]}`, at)
	insertMetadataEvent(t, db, "evt-nonfinding", "a", "tenant-a", "audit", `{"findings":[{"category":"openai_key","rule_id":"policy-a","policy_code":"代码","matched_capabilities":["openai_key"],"counts_as_security_finding":false}]}`, at)
	insertMetadataEvent(t, db, "evt-unknown-action", "a", "tenant-a", "security_check_failed", `{"findings":[`+metadataDLPFinding+`]}`, at)
	insertMetadataEvent(t, db, "evt-not-dlp", "a", "tenant-a", "audit", `{"findings":[{"type":"semantic_attack","category":"prompt_injection","policy_scene":"prompt_injection","rule_id":"attack-policy","policy_code":"提示词保护","matched_capabilities":["prompt_injection"]}]}`, at)
	q := CredentialHitsQuery{KeyID: "key-a", Since: at.Add(-time.Hour), Until: at.Add(time.Hour), Limit: 100}
	page, err := repo.CredentialHits(ctx, "tenant-a", q)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Data) != 4 {
		t.Fatalf("混入其它租户、凭据或非命中，或同一事件重复：%+v", page)
	}
	seen := map[string]bool{}
	for _, item := range page.Data {
		if seen[item.ID] {
			t.Fatal("同一事件重复", item.ID)
		}
		seen[item.ID] = true
		if item.KeyID != "key-a" || !item.CreatedAt.Equal(at) {
			t.Fatalf("归属或发生时间错误：%+v", item)
		}
		wantAction := map[string]string{"evt-a": "audit", "evt-mask": "mask", "evt-block": "block", "evt-model": "audit"}[item.ID]
		if item.Action != wantAction {
			t.Fatalf("将配置动作冒充实际动作：%+v", item)
		}
		if item.ID == "evt-model" {
			if item.Category != "key_model_outside_allowlist" || item.Model != "请求的模型" || item.PolicyID != "" {
				t.Fatalf("模型事件失真：%+v", item)
			}
		} else if item.Category != "dlp:openai_key" || item.PolicyID != "policy-a" || item.Model != "" {
			t.Fatalf("防泄漏事件失真：%+v", item)
		}
	}
	raw, _ := json.Marshal(page)
	if strings.Contains(string(raw), "正文测试标记") {
		t.Fatal("命中片段或正文出现在响应中")
	}
	var obj map[string]any
	json.Unmarshal(raw, &obj)
	for _, value := range obj["data"].([]any) {
		for key := range value.(map[string]any) {
			switch key {
			case "id", "key_id", "created_at", "category", "policy_id", "action", "model":
			default:
				t.Errorf("多余响应字段：%s", key)
			}
		}
	}
	for _, key := range []string{"legacy", "empty-agent", "blank-agent", "key-b", "missing"} {
		q.KeyID = key
		if _, err = repo.CredentialHits(ctx, "tenant-a", q); !errors.Is(err, ai.ErrNotFound) {
			t.Errorf("应拒绝非集成或异租户凭据 %s：%v", key, err)
		}
	}
}

func TestCredentialHitsKeysetPaginationDedupAndTimeBoundaries(t *testing.T) {
	db := metadataReadTestDB(t)
	repo := NewIntegrationRepository(db)
	ctx := context.Background()
	since := time.Now().UTC().Truncate(time.Second).Add(-7 * 24 * time.Hour)
	until := since.Add(7 * 24 * time.Hour)
	insertMetadataRequest(t, db, "page", "tenant-a", "key-a", until)
	for i := 0; i < 5; i++ {
		insertMetadataEvent(t, db, fmt.Sprintf("evt-%d", i), "page", "tenant-a", "audit", `{"findings":[`+metadataDLPFinding+`,`+metadataDLPFinding+`]}`, since.Add(time.Duration(i/2)*time.Second))
	}
	insertMetadataEvent(t, db, "evt-before", "page", "tenant-a", "audit", `{"findings":[`+metadataDLPFinding+`]}`, since.Add(-time.Microsecond))
	insertMetadataEvent(t, db, "evt-until", "page", "tenant-a", "audit", `{"findings":[`+metadataDLPFinding+`]}`, until)
	q := CredentialHitsQuery{KeyID: "key-a", Since: since, Until: until, Limit: 2}
	seen := map[string]bool{}
	for pageNo := 0; pageNo < 4; pageNo++ {
		page, err := repo.CredentialHits(ctx, "tenant-a", q)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Data {
			if seen[item.ID] || item.ID == "evt-before" || item.ID == "evt-until" {
				t.Fatalf("分页重复或时间边界错误：%s", item.ID)
			}
			seen[item.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		q.Cursor = page.NextCursor
		if pageNo == 0 {
			resume := q
			resume.Since, resume.Until = time.Time{}, time.Time{}
			resumed, err := repo.CredentialHits(ctx, "tenant-a", resume)
			if err != nil || !resumed.Since.Equal(since) || !resumed.Until.Equal(until) || len(resumed.Data) != 2 {
				t.Fatalf("仅传游标时未固定首次时间窗：%+v %v", resumed, err)
			}
			// 页前插入新事件不能让后续页重复已有编号。
			insertMetadataEvent(t, db, "evt-new", "page", "tenant-a", "audit", `{"findings":[`+metadataDLPFinding+`]}`, until.Add(-time.Second))
			foreign := q
			foreign.KeyID = "key-other"
			if _, err = repo.CredentialHits(ctx, "tenant-a", foreign); !errors.Is(err, ai.ErrInvalid) {
				t.Fatal("游标可被挪到另一凭据", err)
			}
			if _, err = repo.CredentialHits(ctx, "tenant-b", q); !errors.Is(err, ai.ErrInvalid) {
				t.Fatal("游标可被挪到另一租户", err)
			}
			changed := q
			changed.Until = until.Add(-time.Second)
			if _, err = repo.CredentialHits(ctx, "tenant-a", changed); !errors.Is(err, ai.ErrInvalid) {
				t.Fatal("游标可被挪到另一时间窗", err)
			}
		}
	}
	if len(seen) != 5 {
		t.Fatalf("分页漏事件或重复：%v", seen)
	}
	for _, invalid := range []CredentialHitsQuery{
		{KeyID: "key-a", Since: since, Until: until.Add(time.Microsecond), Limit: 2},
		{KeyID: "key-a", Since: until, Until: since, Limit: 2},
		{KeyID: "key-a", Since: since, Until: since, Limit: 2},
		{KeyID: "key-a", Since: since, Until: until, Limit: 2, Cursor: "乱码"},
	} {
		if _, err := repo.CredentialHits(ctx, "tenant-a", invalid); !errors.Is(err, ai.ErrInvalid) {
			t.Errorf("非法时间或游标未拒绝：%+v %v", invalid, err)
		}
	}
}

func TestCredentialRetentionActualDaysAndContentMetadataOnly(t *testing.T) {
	db := metadataReadTestDB(t)
	repo := NewIntegrationRepository(db)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for _, f := range []struct{ id, tenant, key string }{{"a", "tenant-a", "key-a"}, {"other", "tenant-a", "key-other"}, {"b", "tenant-b", "key-b"}} {
		insertMetadataRequest(t, db, f.id, f.tenant, f.key, now)
	}
	for _, f := range []struct {
		id, req, tenant string
		at              time.Time
	}{{"old", "a", "tenant-a", now.Add(-24*time.Hour - time.Microsecond)}, {"other", "other", "tenant-a", now}, {"foreign", "a", "tenant-b", now}, {"future", "a", "tenant-a", now.Add(time.Second)}} {
		if _, err := db.Exec(ctx, `INSERT INTO content_logs VALUES($1,$2,$3,$4,'正文测试标记')`, f.id, "log-"+f.req, f.tenant, f.at); err != nil {
			t.Fatal(err)
		}
	}
	got, err := repo.CredentialRetentionStatus(ctx, "tenant-a", "key-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if got.LogRetentionDays != 180 || got.HasContentLogs24h || got.LastContentLogAt != nil {
		t.Fatalf("把其它来源误当本凭据内容日志：%+v", got)
	}
	boundary := now.Add(-24 * time.Hour)
	if _, err = db.Exec(ctx, `INSERT INTO content_logs VALUES('boundary','log-a','tenant-a',$1,'正文测试标记')`, boundary); err != nil {
		t.Fatal(err)
	}
	got, err = repo.CredentialRetentionStatus(ctx, "tenant-a", "key-a", now)
	if err != nil || !got.HasContentLogs24h || got.LastContentLogAt == nil || !got.LastContentLogAt.Equal(boundary) {
		t.Fatalf("恰好二十四小时前的日志应纳入：%+v %v", got, err)
	}
	last := now.Add(-time.Minute)
	if _, err = db.Exec(ctx, `INSERT INTO content_logs VALUES('local','log-a','tenant-a',$1,'正文测试标记')`, last); err != nil {
		t.Fatal(err)
	}
	got, err = repo.CredentialRetentionStatus(ctx, "tenant-a", "key-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasContentLogs24h || got.LastContentLogAt == nil || !got.LastContentLogAt.Equal(last) {
		t.Fatalf("未读取实际内容日志存在性：%+v", got)
	}
	// 正反向代理内容留存使用 request_id 关联；聊天内容日志使用 request_logs.id。
	if _, err = db.Exec(ctx, `INSERT INTO access_content_logs VALUES('access','req-a','tenant-a',$1,'正文测试标记')`, now); err != nil {
		t.Fatal(err)
	}
	got, err = repo.CredentialRetentionStatus(ctx, "tenant-a", "key-a", now)
	if err != nil || got.LastContentLogAt == nil || !got.LastContentLogAt.Equal(now) {
		t.Fatalf("访问留存未覆盖：%+v %v", got, err)
	}
	for raw, want := range map[string]int{"1": 30, "bad": 90, "9999": 3650, "0": 90} {
		if _, err = db.Exec(ctx, `UPDATE system_settings SET value=$1 WHERE key='log_retention_days'`, raw); err != nil {
			t.Fatal(err)
		}
		got, err = repo.CredentialRetentionStatus(ctx, "tenant-a", "key-a", now)
		if err != nil || got.LogRetentionDays != want {
			t.Errorf("实际留存口径错误 %s：%+v %v", raw, got, err)
		}
	}
	if _, err = db.Exec(ctx, `DELETE FROM system_settings`); err != nil {
		t.Fatal(err)
	}
	got, err = repo.CredentialRetentionStatus(ctx, "tenant-a", "key-a", now)
	if err != nil || got.LogRetentionDays != 90 {
		t.Fatalf("缺省实际留存错误：%+v %v", got, err)
	}
	for _, key := range []string{"legacy", "empty-agent", "blank-agent", "key-b", "missing"} {
		if _, err = repo.CredentialRetentionStatus(ctx, "tenant-a", key, now); !errors.Is(err, ai.ErrNotFound) {
			t.Errorf("应拒绝非集成或异租户凭据 %s：%v", key, err)
		}
	}
}

func TestIntegrationMetadataNeedsNoContentOrCredentialMaterialPermissions(t *testing.T) {
	db := metadataReadTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	insertMetadataRequest(t, db, "restricted", "tenant-a", "key-a", now)
	insertMetadataEvent(t, db, "evt-restricted", "restricted", "tenant-a", "audit", `{"findings":[`+metadataDLPFinding+`]}`, now)
	if _, err := db.Exec(ctx, `INSERT INTO content_logs VALUES('restricted','log-restricted','tenant-a',$1,'正文测试标记')`, now); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := db.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	role := fmt.Sprintf("j2_metadata_reader_%d", time.Now().UnixNano())
	roleSQL := pgx.Identifier{role}.Sanitize()
	schemaSQL := pgx.Identifier{schema}.Sanitize()
	for _, statement := range []string{
		`CREATE ROLE ` + roleSQL + ` NOLOGIN`,
		`GRANT USAGE ON SCHEMA ` + schemaSQL + ` TO ` + roleSQL,
		`GRANT SELECT(id,tenant_id,agent_instance_id) ON internal_keys TO ` + roleSQL,
		`GRANT SELECT(id,request_id,tenant_id,client_id,routing_decision_json) ON request_logs TO ` + roleSQL,
		`GRANT SELECT(id,request_id,tenant_id,created_at,action_taken,matched_summary) ON security_events TO ` + roleSQL,
		`GRANT SELECT(request_id,tenant_id,created_at) ON content_logs,access_content_logs TO ` + roleSQL,
		`GRANT SELECT(key,value) ON system_settings TO ` + roleSQL,
	} {
		if _, err := db.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { db.Exec(ctx, `DROP OWNED BY `+roleSQL); db.Exec(ctx, `DROP ROLE `+roleSQL) })
	cfg := db.Config().Copy()
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET ROLE `+roleSQL+`; SET default_transaction_read_only=on; SET TIME ZONE 'Asia/Shanghai'`)
		return err
	}
	readerDB, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer readerDB.Close()
	repo := NewIntegrationRepository(readerDB)
	page, err := repo.CredentialHits(ctx, "tenant-a", CredentialHitsQuery{KeyID: "key-a", Since: now.Add(-time.Hour), Until: now.Add(time.Hour)})
	if err != nil || len(page.Data) != 1 {
		t.Fatalf("读取元数据不应需要写入或正文权限：%+v %v", page, err)
	}
	status, err := repo.CredentialRetentionStatus(ctx, "tenant-a", "key-a", now)
	if err != nil || !status.HasContentLogs24h || status.LastContentLogAt == nil || !status.LastContentLogAt.Equal(now) {
		t.Fatalf("仅时间列权限的留存读取失败：%+v %v", status, err)
	}
	for _, statement := range []string{`SELECT content FROM content_logs`, `SELECT key_hash FROM internal_keys`, `UPDATE internal_keys SET agent_instance_id='other'`} {
		if _, err := readerDB.Exec(ctx, statement); err == nil {
			t.Fatalf("夹具意外获得正文、凭据或写权限：%s", statement)
		}
	}
}
