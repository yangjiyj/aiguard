package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/testcontainer"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func retryTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	docker := testcontainer.DockerRunner(30 * time.Second)
	// 先回收被杀掉的测试进程留下的容器（规则见 testcontainer.ReapOrphans），失败只记日志。
	if removed, err := testcontainer.ReapOrphans(ctx, docker); err != nil {
		t.Logf("reap orphan test containers: %v", err)
	} else if len(removed) > 0 {
		t.Logf("reaped orphan test containers: %v", removed)
	}
	runArgs := append([]string{"run", "--rm", "-d"}, testcontainer.LabelArgs("gateway-retry")...)
	runArgs = append(runArgs, "-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_DB=test", "postgres:16-alpine")
	out, e := docker(ctx, runArgs...)
	if e != nil {
		t.Fatalf("PostgreSQL required: %v %s", e, out)
	}
	id := strings.TrimSpace(out)
	// rm -f -v：连同 postgres 镜像的匿名数据卷一起删掉。
	t.Cleanup(func() { _ = testcontainer.Remove(context.Background(), docker, id) })
	var b []byte
	b, e = exec.Command("docker", "port", id, "5432/tcp").Output()
	if e != nil {
		t.Fatal(e)
	}
	addr := strings.TrimSpace(string(b))
	db, e := pgxpool.New(ctx, "postgres://postgres:test@"+addr+"/test?sslmode=disable")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(db.Close)
	deadline := time.Now().Add(20 * time.Second)
	for db.Ping(ctx) != nil {
		if time.Now().After(deadline) {
			t.Fatal("PostgreSQL unavailable")
		}
		time.Sleep(100 * time.Millisecond)
	}
	sql, e := os.ReadFile("../../../../deploy/migrations/852_gateway_inspection_retries.sql")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(ctx, string(sql)); e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(ctx, `CREATE TABLE request_logs(request_id text PRIMARY KEY,tenant_id text, agent_instance_id varchar(128)); INSERT INTO request_logs VALUES('req','t1'),('another','t1'),('expired','t1'); CREATE TABLE security_events(id text PRIMARY KEY,request_id text,tenant_id text,project_id text,event_type text,severity text,rule_id text,action_taken text,matched_summary jsonb,evidence_ref text,created_at timestamptz DEFAULT now(), agent_instance_id varchar(128))`)
	if e != nil {
		t.Fatal(e)
	}
	return db
}
func TestReverseInspectionRetryDurableLeaseAndCoverage(t *testing.T) {
	db := retryTestDB(t)
	ctx := context.Background()
	var failed atomic.Bool
	failed.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failed.Load() {
			fmt.Fprint(w, `{"action":"audit","engine_build":"test-build","semantic_status":"incomplete","semantic_reason":"judge_unavailable"}`)
			return
		}
		fmt.Fprint(w, `{"action":"block","engine_build":"test-build","inspection_status":"completed","semantic_status":"completed","findings":[{"type":"secret","category":"test_secret","severity":"critical","raw_evidence":"TestSecretOnly49!","matched_text_preview":"Te***49","matched_location":"content[0:17]"}]}`)
	}))
	defer server.Close()
	h := &ReverseProxyHandler{db: db, tenantID: "t1", internalSecret: "isolated-test-secret-1234", securityURL: server.URL, client: server.Client()}
	q, e := newReverseInspectionQueue(h)
	if e != nil {
		t.Fatal(e)
	}
	h.retryQueue = q
	d, e := h.checkSecurityWithExtras(ctx, "req", "/check-input/", []byte("original-private-payload"), "original-private-payload", "text/plain", "example.invalid", "/v1/responses", "user", nil)
	if e != nil || len(d.RetryTaskIDs) != 1 || d.RetryUnavailable {
		t.Fatalf("not queued %+v %v", d, e)
	}
	id := d.RetryTaskIDs[0]
	var enc string
	db.QueryRow(ctx, "SELECT payload_encrypted FROM gateway_inspection_retries WHERE id=$1", id).Scan(&enc)
	if strings.Contains(enc, "original-private-payload") {
		t.Fatal("plaintext payload persisted")
	}
	originalPayload, _ := q.open(id, enc)
	var originalTask reverseRetryPayload
	json.Unmarshal(originalPayload, &originalTask)
	if _, e = q.open("different-tenant-task", enc); e == nil {
		t.Fatal("ciphertext is not scope bound")
	}
	summary, _ := json.Marshal(map[string]any{"source": "gateway_reverse_proxy", "stage": "input", "semantic_status": "incomplete", "retry_task_ids": d.RetryTaskIDs, "retry_unavailable": false})
	db.Exec(ctx, "INSERT INTO security_events(id,request_id,tenant_id,matched_summary) VALUES('original','req','t1',$1)", summary)
	db.Exec(ctx, "UPDATE gateway_inspection_retries SET next_attempt_at=now()")
	first, e := q.claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// A new queue instance resumes after a process dies holding a lease.
	db.Exec(ctx, "UPDATE gateway_inspection_retries SET lease_until=now()-interval '1 second'")
	restarted, e := newReverseInspectionQueue(h)
	if e != nil {
		t.Fatal(e)
	}
	second, e := restarted.claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	failed.Store(false)
	if e = q.runJob(ctx, first); e == nil {
		t.Fatal("stale worker published result")
	}
	if e = restarted.runJob(ctx, second); e != nil {
		t.Fatal(e)
	}
	if e = restarted.reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	var status, remediation string
	db.QueryRow(ctx, "SELECT status FROM gateway_inspection_retries WHERE id=$1", id).Scan(&status)
	db.QueryRow(ctx, "SELECT matched_summary#>>'{remediation,status}' FROM security_events WHERE id='original'").Scan(&remediation)
	if status != "completed" || remediation != "rechecked_complete" {
		t.Fatalf("%s %s", status, remediation)
	}
	var count int
	db.QueryRow(ctx, "SELECT count(*) FROM security_events WHERE id LIKE 'retry_%' AND matched_summary->>'retry_task_id'=$1", id).Scan(&count)
	if count != 1 {
		t.Fatalf("lost or duplicate findings: %d", count)
	}
	db.QueryRow(ctx, "SELECT payload_encrypted FROM gateway_inspection_retries WHERE id=$1", id).Scan(&enc)
	if enc != "" {
		t.Fatal("successful raw payload retained")
	}
	t.Run("missing-part-never-completes", func(t *testing.T) {
		db.Exec(ctx, `UPDATE security_events SET matched_summary=jsonb_set(matched_summary,'{retry_task_ids}',jsonb_build_array($1::text,'missing'))-'remediation' WHERE id='original'`, id)
		if e = q.reconcile(ctx); e != nil {
			t.Fatal(e)
		}
		db.QueryRow(ctx, "SELECT matched_summary#>>'{remediation,status}' FROM security_events WHERE id='original'").Scan(&status)
		if status == "rechecked_complete" {
			t.Fatal("missing work marked complete")
		}
	})
	t.Run("exhaustion-and-tenant-isolation", func(t *testing.T) {
		failed.Store(true)
		jID, e := q.enqueue("another", "/check-input/", []byte(`{"content":"retry"}`))
		if e != nil {
			t.Fatal(e)
		}
		db.Exec(ctx, "UPDATE gateway_inspection_retries SET attempts=7,next_attempt_at=now() WHERE id=$1", jID)
		other := ReverseProxyHandler{db: h.db, internalSecret: h.internalSecret, tenantID: "t2"}
		oq, _ := newReverseInspectionQueue(&other)
		if _, e = oq.claim(ctx); e != pgx.ErrNoRows {
			t.Fatalf("tenant isolation: %v", e)
		}
		j, e := q.claim(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if e = q.runJob(ctx, j); e != nil {
			t.Fatal(e)
		}
		db.QueryRow(ctx, "SELECT status FROM gateway_inspection_retries WHERE id=$1", jID).Scan(&status)
		if status != "failed" {
			t.Fatalf("unbounded retry %s", status)
		}
	})
	t.Run("expiry-and-terminal-verdict-are-not-reused", func(t *testing.T) {
		if _, err := q.enqueue("req", originalTask.Path, originalTask.Body, originalTask.RequireSemantic); err == nil {
			t.Fatal("old completion reused for a new failed attempt")
		}
		if _, err := q.enqueue("req", "/check-input/", []byte("changed")); err != nil {
			t.Fatal(err)
		}
		_, err := q.enqueue("expired", "/check-output/", []byte(`{"content":"original"}`))
		if err != nil {
			t.Fatal(err)
		}
		db.Exec(ctx, "UPDATE gateway_inspection_retries SET expires_at=now()-interval '1 second' WHERE request_id='expired'")
		if err = q.reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		var size int
		db.QueryRow(ctx, "SELECT status,payload_bytes FROM gateway_inspection_retries WHERE request_id='expired'").Scan(&status, &size)
		if status != "expired" || size != 0 {
			t.Fatalf("expired sensitive payload retained: %s %d", status, size)
		}
	})

}

func TestInspectionCompletionRequiresActualDecision(t *testing.T) {
	for _, r := range []reverseProxySecurityResponse{{}, {Action: "unknown"}, {Action: "allow", SemanticStatus: "incomplete"}, {Action: "allow", InspectionStatus: "failed"}} {
		if reverseInspectionComplete(r, nil) {
			t.Fatalf("false completion: %+v", r)
		}
	}
	if !reverseInspectionComplete(reverseProxySecurityResponse{Action: "audit", InspectionStatus: "completed", SemanticStatus: "completed"}, nil) {
		t.Fatal("completed scan rejected")
	}
}

func TestReverseInspectionRetryCannotTreatDisabledScopeAsRecovery(t *testing.T) {
	r := reverseProxySecurityResponse{Action: "allow", EngineBuild: "test", InspectionStatus: "completed", SemanticStatus: "not_requested"}
	if reverseRetryComplete(reverseRetryPayload{RequireSemantic: true}, r, nil) {
		t.Fatal("disabled semantic scan reported recovered")
	}
	r.SemanticStatus = "skipped"
	r.SemanticReason = "inspection_scope_excluded"
	if reverseRetryComplete(reverseRetryPayload{}, r, nil) {
		t.Fatal("scope exclusion reported recovered")
	}
	r.SemanticStatus = "completed"
	r.SemanticReason = ""
	if !reverseRetryComplete(reverseRetryPayload{RequireSemantic: true}, r, nil) {
		t.Fatal("completed original scope rejected")
	}
}
