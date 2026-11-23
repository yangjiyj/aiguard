package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Only the runner-owned empty test database is eligible. No production DSN or
// migration runner is used; these are the exact queried native column types.
func TestIntegrationUsagePG(t *testing.T) {
	dsn := os.Getenv("INTEGRATION_USAGE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("INTEGRATION_USAGE_TEST_DATABASE_URL absent; real PG check not executed")
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
	var dbname string
	if err = db.QueryRow(ctx, `SELECT current_database()`).Scan(&dbname); err != nil || !strings.HasPrefix(dbname, "asp_preview_aidr_usable_gateway_") {
		t.Fatal("test database guard failed")
	}
	_, err = db.Exec(ctx, `
 CREATE TABLE models (id varchar(64) PRIMARY KEY, model_name varchar(255));
 CREATE TABLE internal_keys (id varchar(64) PRIMARY KEY, tenant_id varchar(64) NOT NULL, project_id varchar(64) NOT NULL, agent_instance_id varchar(128),status varchar(32));
 CREATE TABLE request_logs (id varchar(64) PRIMARY KEY, request_id varchar(128) NOT NULL, tenant_id varchar(64) NOT NULL, agent_instance_id varchar(128), created_at timestamptz NOT NULL DEFAULT now(), project_id varchar(64), client_id varchar(64), agent_type varchar(64), model_id varchar(64), request_status varchar(64), upstream_status_code integer, input_tokens integer, output_tokens integer, output_audit_result jsonb);
 CREATE TABLE security_events (id varchar(64) PRIMARY KEY, tenant_id varchar(64) NOT NULL, request_id varchar(128), action_taken varchar(64));
 CREATE TABLE billing_usage_facts (id varchar(64) PRIMARY KEY, tenant_id varchar(64) NOT NULL, request_id varchar(128) NOT NULL, project_id varchar(64), client_id varchar(64), model_id varchar(64), raw_usage_json jsonb, estimated boolean NOT NULL DEFAULT false, UNIQUE(tenant_id,request_id));
 INSERT INTO models VALUES ('model-a','display only');
 INSERT INTO internal_keys VALUES ('key-a','tenant-a','project-a','agent-a','revoked');
 `)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewIntegrationRepository(db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for i, tc := range integrationUsageCases() {
		t.Run(tc.name, func(t *testing.T) {
			id := fmt.Sprintf("row-%d", i)
			_, err := db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,agent_instance_id,created_at,project_id,client_id,model_id,input_tokens,output_tokens,output_audit_result) VALUES ($1,$1,'tenant-a','agent-a',$2,'project-a','key-a','model-a',$3,$4,jsonb_build_object('response_metadata',jsonb_build_object('usage_source',$5::text)))`, id, now, tc.input, tc.output, tc.source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec(ctx, `INSERT INTO billing_usage_facts VALUES ($1,'tenant-a',$1,'project-a','key-a','model-a',$2::jsonb,$3)`, id, tc.raw, tc.estimated)
			if err != nil {
				t.Fatal(err)
			}
			rows, total, err := repo.ListEvents(ctx, "tenant-a", "agent-a", now.Add(-time.Second), now.Add(time.Second), 200, 0)
			if err != nil {
				t.Fatal(err)
			}
			if total != i+1 {
				t.Fatalf("total=%d", total)
			}
			var got *IntegrationEvent
			for j := range rows {
				if rows[j].ID == id {
					got = &rows[j]
				}
			}
			if got == nil || got.ModelID != "model-a" || !reflect.DeepEqual(got.Usage, tc.want) {
				t.Fatalf("projection=%+v want=%+v", got, tc.want)
			}
		})
	}
	t.Run("cross domain and historical revoked key", func(t *testing.T) {
		// Facts never carry agent_instance_id: the immutable native key binding is
		// checked in the same tenant/project/client domain, without filtering status.
		_, err := db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,agent_instance_id,created_at,project_id,client_id,model_id,input_tokens,output_tokens,output_audit_result) VALUES ('domain','domain','tenant-a','agent-a',$1,'project-a','key-a','model-a',10,5,'{"response_metadata":{"usage_source":"upstream"}}')`, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(ctx, `INSERT INTO security_events VALUES ('foreign-event','tenant-b','domain','block')`); err != nil {
			t.Fatal(err)
		}
		raw := `{"usage_source":"upstream","upstream_usage":{"prompt_tokens":10,"completion_tokens":5},"private_body":"never-return","wallet":"never-return"}`
		checks := []struct {
			name, tenant, request, project, client, model string
			actual                                        bool
		}{
			{"cross tenant", "tenant-b", "domain", "project-a", "key-a", "model-a", false},
			{"cross request", "tenant-a", "another-request", "project-a", "key-a", "model-a", false},
			{"cross client", "tenant-a", "domain", "project-a", "key-b", "model-a", false},
			{"cross project", "tenant-a", "domain", "project-b", "key-a", "model-a", false},
			{"cross model", "tenant-a", "domain", "project-a", "key-a", "model-b", false},
			{"exact binding", "tenant-a", "domain", "project-a", "key-a", "model-a", true},
		}
		for _, c := range checks {
			t.Run(c.name, func(t *testing.T) {
				_, err = db.Exec(ctx, `INSERT INTO billing_usage_facts VALUES ('domain-fact',$1,$2,$3,$4,$5,$6::jsonb,false)`, c.tenant, c.request, c.project, c.client, c.model, raw)
				if err != nil {
					t.Fatal(err)
				}
				rows, _, err := repo.ListEvents(ctx, "tenant-a", "agent-a", now.Add(-time.Second), now.Add(time.Second), 200, 0)
				if err != nil {
					t.Fatal(err)
				}
				var got IntegrationEvent
				for _, row := range rows {
					if row.ID == "domain" {
						got = row
					}
				}
				if (got.Usage.MeasurementState == "actual") != c.actual {
					t.Fatalf("state=%s", got.Usage.MeasurementState)
				}
				if got.Action != "allow" || len(got.EventIDs) != 0 {
					t.Fatal("cross-tenant security event leaked")
				}
				encoded, _ := json.Marshal(got)
				if strings.Contains(string(encoded), "never-return") || strings.Contains(string(encoded), "raw_usage") {
					t.Fatal("evidence escaped counts projection")
				}
				_, err = db.Exec(ctx, `DELETE FROM billing_usage_facts WHERE id='domain-fact'`)
				if err != nil {
					t.Fatal(err)
				}
			})
		}
		_, err = db.Exec(ctx, `INSERT INTO billing_usage_facts VALUES ('domain-fact','tenant-a','domain','project-a','key-a','model-a',$1::jsonb,false)`, raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(ctx, `UPDATE internal_keys SET agent_instance_id='agent-b' WHERE id='key-a'`); err != nil {
			t.Fatal(err)
		}
		rows, _, err := repo.ListEvents(ctx, "tenant-a", "agent-a", now.Add(-time.Second), now.Add(time.Second), 200, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.ID == "domain" && row.Usage.MeasurementState == "actual" {
				t.Fatal("cross-instance binding accepted")
			}
		}
		_, err = db.Exec(ctx, `UPDATE internal_keys SET agent_instance_id='agent-a' WHERE id='key-a'`)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("legacy offset and tenant window", func(t *testing.T) {
		all, total, err := repo.ListEvents(ctx, "tenant-a", "agent-a", now.Add(-time.Second), now.Add(time.Second), 200, 0)
		if err != nil {
			t.Fatal(err)
		}
		one, n, err := repo.ListEvents(ctx, "tenant-a", "agent-a", now.Add(-time.Second), now.Add(time.Second), 1, 1)
		if err != nil || n != total || len(one) != 1 || one[0].ID != all[1].ID {
			t.Fatalf("offset changed: %v", err)
		}
		for _, q := range [][2]string{{"tenant-b", "agent-a"}, {"tenant-a", "agent-b"}} {
			rows, n, err := repo.ListEvents(ctx, q[0], q[1], now.Add(-time.Second), now.Add(time.Second), 200, 0)
			if err != nil || n != 0 || len(rows) != 0 {
				t.Fatalf("scope expanded: %v", err)
			}
		}
		rows, n, err := repo.ListEvents(ctx, "tenant-a", "agent-a", now.Add(time.Second), now.Add(2*time.Second), 200, 0)
		if err != nil || n != 0 || len(rows) != 0 {
			t.Fatalf("window expanded: %v", err)
		}
	})
}
