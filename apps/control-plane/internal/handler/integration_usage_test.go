package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIntegrationUsageHTTPPG(t *testing.T) {
	dsn := os.Getenv("INTEGRATION_USAGE_HTTP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("INTEGRATION_USAGE_HTTP_TEST_DATABASE_URL absent; real HTTP/PG check not executed")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || !strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "asp_preview_aidr_usable_gateway_") {
		t.Fatal("refuse non-owned test database")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("test pool creation failed")
	}
	defer db.Close()
	_, err = db.Exec(ctx, `
 CREATE TABLE users(id varchar(64) PRIMARY KEY,tenant_id varchar(64),department_version bigint NOT NULL DEFAULT 1);
 CREATE TABLE permission_grants(id varchar(64) PRIMARY KEY,user_id varchar(64),tenant_id varchar(64),scope_type varchar(16),scope_id varchar(64),role varchar(64),granted_by varchar(64));
 CREATE TABLE system_permissions(role_name varchar(64),resource varchar(64),action varchar(32));
 CREATE TABLE audit_operations(id varchar(64) PRIMARY KEY,user_id varchar(64),action_type varchar(64),action_detail jsonb,target_type varchar(32),target_id varchar(64),ip_address varchar(64));
 INSERT INTO users VALUES ('actor','tenant-a',1);
 INSERT INTO permission_grants VALUES ('employee-grant','actor','tenant-a','tenant','tenant-a','employee','fixture-admin');
 CREATE TABLE models(id varchar(64) PRIMARY KEY,model_name varchar(255));
 CREATE TABLE internal_keys(id varchar(64) PRIMARY KEY,tenant_id varchar(64),project_id varchar(64),agent_instance_id varchar(128));
 CREATE TABLE request_logs(id varchar(64) PRIMARY KEY,request_id varchar(128),tenant_id varchar(64),agent_instance_id varchar(128),created_at timestamptz,project_id varchar(64),client_id varchar(64),agent_type varchar(64),model_id varchar(64),request_status varchar(64),upstream_status_code integer,input_tokens integer,output_tokens integer,output_audit_result jsonb);
 CREATE TABLE security_events(id varchar(64) PRIMARY KEY,tenant_id varchar(64),request_id varchar(128),action_taken varchar(64));
 CREATE TABLE billing_usage_facts(id varchar(64) PRIMARY KEY,tenant_id varchar(64),request_id varchar(128),project_id varchar(64),client_id varchar(64),model_id varchar(64),raw_usage_json jsonb,estimated boolean NOT NULL DEFAULT false,UNIQUE(tenant_id,request_id));
 INSERT INTO models VALUES ('model-a','model display');
 INSERT INTO internal_keys VALUES ('key-a','tenant-a','project-a','agent_fixture');
 INSERT INTO request_logs VALUES ('actual','actual','tenant-a','agent_fixture','2026-10-16T10:00:02Z','project-a','key-a','hermes','model-a','success',200,10,5,'{"response_metadata":{"usage_source":"upstream"}}'),('missing','missing','tenant-a','agent_fixture','2026-10-16T10:00:01Z','project-a','key-a','hermes','model-a','success',200,NULL,NULL,NULL),('foreign','foreign','tenant-b','agent_fixture','2026-10-16T10:00:03Z','project-a','key-a','hermes','model-a','success',200,100,100,NULL);
 INSERT INTO billing_usage_facts VALUES ('fact','tenant-a','actual','project-a','key-a','model-a','{"usage_source":"upstream","upstream_usage":{"prompt_tokens":10,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":0}},"body":"sensitive-fixture","wallet":"private-fixture"}',false);
 `)
	if err != nil {
		t.Fatal(err)
	}
	deps := &Dependencies{IntegrationRepo: repository.NewIntegrationRepository(db)}
	checker := permission.NewChecker(db, permission.NewGrantsCache())
	allowed, checkErr := checker.HasPermission(ctx, "actor", "tenant-a", "tenant", "tenant-a", "integration_events", "read")
	if checkErr != nil || allowed {
		t.Fatalf("real permission fixture must deny without a checker error: allowed=%v err=%v", allowed, checkErr)
	}
	handler := permission.Middleware(checker, db, false)(ListIntegrationAuditEvents(deps))
	get := func(role, tenant, cursor string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/admin/v1/integration/audit-events?agent_instance_id=agent_fixture&limit=1&start_time=2026-10-16T10:00:00Z&end_time=2026-10-16T10:00:04Z&cursor="+cursor, nil)
		if role != "" {
			req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "actor", TenantID: tenant, Role: role}))
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	w := get("platform_connector", "tenant-a", "")
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var envelope struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
		Next  string           `json:"next_cursor"`
		More  bool             `json:"has_more"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Total != 2 || len(envelope.Data) != 1 || envelope.Next != "1" || !envelope.More {
		t.Fatalf("legacy envelope changed: %s", w.Body.String())
	}
	row := envelope.Data[0]
	usage := row["usage"].(map[string]any)
	if row["model_id"] != "model-a" || row["request_id"] != "actual" || usage["measurement_state"] != "actual" || usage["input_tokens"] != float64(10) || usage["output_tokens"] != float64(5) || usage["cache_read_input_tokens"] != float64(0) || usage["cache_write_input_tokens"] != nil {
		t.Fatalf("bad DTO: %s", w.Body.String())
	}
	for _, bad := range []string{"sensitive-fixture", "private-fixture", "raw_usage", "upstream_usage", "key_ciphertext", "wallet"} {
		if strings.Contains(w.Body.String(), bad) {
			t.Fatalf("unexpected %s", bad)
		}
	}
	for _, tc := range []struct {
		name, raw, state string
		read             any
	}{
		{"miss exceeds input", `{"prompt_tokens":10,"completion_tokens":5,"prompt_cache_miss_tokens":11}`, "uncollected", nil},
		{"partial miss valid", `{"prompt_tokens":10,"completion_tokens":5,"prompt_cache_miss_tokens":7}`, "actual", nil},
		{"hit and miss jointly valid", `{"prompt_tokens":10,"completion_tokens":5,"prompt_cache_hit_tokens":3,"prompt_cache_miss_tokens":7}`, "actual", float64(3)},
		{"hit and miss jointly invalid", `{"prompt_tokens":10,"completion_tokens":5,"prompt_cache_hit_tokens":3,"prompt_cache_miss_tokens":8}`, "uncollected", nil},
		{"cache read alias and miss valid", `{"prompt_tokens":10,"completion_tokens":5,"cached_tokens":3,"prompt_cache_miss_tokens":7}`, "actual", float64(3)},
		{"cache read alias and miss invalid", `{"prompt_tokens":10,"completion_tokens":5,"cached_tokens":3,"prompt_cache_miss_tokens":8}`, "uncollected", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := db.Exec(ctx, `UPDATE billing_usage_facts SET raw_usage_json=jsonb_build_object('usage_source','upstream','upstream_usage',$1::jsonb) WHERE id='fact'`, tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			response := get("platform_connector", "tenant-a", "")
			if response.Code != 200 {
				t.Fatalf("status=%d", response.Code)
			}
			var got struct {
				Data []map[string]any `json:"data"`
			}
			if err = json.Unmarshal(response.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if len(got.Data) != 1 {
				t.Fatalf("unexpected row count %d", len(got.Data))
			}
			u := got.Data[0]["usage"].(map[string]any)
			if u["measurement_state"] != tc.state {
				t.Fatalf("state=%v want=%s", u["measurement_state"], tc.state)
			}
			if tc.state == "uncollected" {
				for _, field := range []string{"input_tokens", "output_tokens", "cache_read_input_tokens", "cache_write_input_tokens"} {
					value, ok := u[field]
					if !ok || value != nil {
						t.Fatalf("invalid native miss exposed %s=%v", field, value)
					}
				}
			} else {
				if u["input_tokens"] != float64(10) || u["output_tokens"] != float64(5) || u["cache_write_input_tokens"] != nil {
					t.Fatalf("valid native components changed: %v", u)
				}
				if u["cache_read_input_tokens"] != tc.read {
					t.Fatalf("native hit presence/value changed: %v", u)
				}
			}
		})
	}
	w = get("platform_connector", "tenant-a", "1")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if err = json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Next != "" || envelope.More || envelope.Data[0]["request_id"] != "missing" {
		t.Fatalf("legacy continuation changed: %s", w.Body.String())
	}
	usage = envelope.Data[0]["usage"].(map[string]any)
	for _, field := range []string{"input_tokens", "output_tokens", "cache_read_input_tokens", "cache_write_input_tokens"} {
		value, ok := usage[field]
		if !ok || value != nil {
			t.Fatalf("unknown %s invented: %s", field, w.Body.String())
		}
	}
	// Keep the ordinary identity negative case through the real DB checker.
	for _, role := range []string{"", "employee"} {
		denied := get(role, "tenant-a", "")
		if denied.Code != 403 || !strings.Contains(denied.Body.String(), `"code":"permission_denied"`) {
			t.Fatalf("middleware role %q status=%d body=%s", role, denied.Code, denied.Body.String())
		}
	}
	// The handler also rejects an absent identity on its own.
	anonymous := httptest.NewRecorder()
	ListIntegrationAuditEvents(deps).ServeHTTP(anonymous, httptest.NewRequest("GET", "/admin/v1/integration/audit-events", nil))
	if anonymous.Code != 401 {
		t.Fatalf("absent identity handler status=%d", anonymous.Code)
	}
	// The real actor is retained by the existing asynchronous denial audit.
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var count int
		err = db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE user_id='actor' AND action_type='permission.denied' AND action_detail->>'path'='/admin/v1/integration/audit-events'`).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("employee denial audit missing")
		}
	}
	// Connector remains unable to obtain audit content or money/aggregate APIs.
	for _, path := range []string{"/admin/v1/audit/requests", "/admin/v1/audit/content", "/admin/v1/audit/export", "/admin/v1/usage/records", "/admin/v1/billing/analytics/summary"} {
		req := httptest.NewRequest("GET", path, nil)
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "actor", TenantID: "tenant-a", Role: "platform_connector"}))
		w = httptest.NewRecorder()
		permission.Middleware(nil, nil, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatalf("connector scope expanded %s: %d", path, w.Code)
		}
	}
}
