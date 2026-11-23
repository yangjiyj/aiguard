package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testInspectionKey = "synthetic-inspection-test-key-not-production"

func inspectionDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("PROXY_INSPECTION_TEST_DSN")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL: PROXY_INSPECTION_TEST_DSN")
	}
	root, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "inspection_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = root.Exec(context.Background(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = root.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		root.Close()
	})
	migration, err := os.ReadFile("../../../../deploy/migrations/846_proxy_inspection_jobs.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), string(migration)); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(context.Background(), `CREATE TABLE request_logs(tenant_id text,request_id text,environment_scope text); CREATE TABLE security_events(id varchar(64) PRIMARY KEY,request_id text,tenant_id text,project_id text,event_type text,severity text,rule_id text,action_taken text,matched_summary jsonb,evidence_ref text,created_at timestamptz,principal_key text,effective_severity text,class_key text);`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}
func completedInspection(w http.ResponseWriter, content string) {
	findings := []interface{}{}
	action := "allow"
	if strings.Contains(content, "TAIL-RISK") || strings.Contains(content, "SYNTHETIC-BOUNDARY-SECRET") {
		action = "block"
		findings = append(findings, map[string]interface{}{"category": "synthetic_risk", "type": "secret", "action": "block", "severity": "high"})
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"action": action, "findings": findings, "raw_findings": findings, "semantic_status": "completed", "inspection_status": "completed", "engine_build": "test-v1", "rule_pack_version": "rules-v1", "semantic_config_revision": "semantic-v1"})
}
func queueForTest(t *testing.T, db *pgxpool.Pool, url string) *InspectionQueue {
	t.Helper()
	s := NewSecurityClientWithSecret(url, testInspectionKey).WithFingerprintStore(scanfp.NewStore(nil, 4096))
	q, err := NewInspectionQueue(db, s, testInspectionKey, "customer")
	if err != nil {
		t.Fatal(err)
	}
	return q
}
func simplePlan(content string) []map[string]interface{} {
	return []map[string]interface{}{{"request_id": "synthetic", "content": content, "content_source": "user", "context": map[string]interface{}{"tenant_id": "tenant", "host": "api.example.test"}}}
}
func drainInspection(t *testing.T, q *InspectionQueue) {
	t.Helper()
	for i := 0; i < 20; i++ {
		_, err := q.db.Exec(context.Background(), "UPDATE proxy_inspection_parts SET next_attempt_at=now() WHERE status='pending'")
		if err != nil {
			t.Fatal(err)
		}
		p, err := q.claim(context.Background(), "", "")
		if err != nil {
			t.Fatal(err)
		}
		if p == nil {
			return
		}
		if err = q.execute(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("queue did not drain")
}
func TestInspectionDurableRetryRestartAndIdempotentEvidence(t *testing.T) {
	db := inspectionDB(t)
	var available atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available.Load() {
			w.WriteHeader(503)
			return
		}
		var p map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&p)
		completedInspection(w, fmt.Sprint(p["content"]))
	}))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	action, _, meta := q.inspect(context.Background(), "tenant", "restart", "api.example.test", simplePlan("TAIL-RISK private test marker"), true)
	if action != "audit" || meta.SemanticReason != "inspection_queued" {
		t.Fatalf("not durably queued: %s %+v", action, meta)
	}
	var stored string
	if err := db.QueryRow(context.Background(), "SELECT payload_encrypted FROM proxy_inspection_parts").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "private test marker") {
		t.Fatal("plaintext persisted")
	}
	if _, err := q.open(inspectionPart{Tenant: "other", Request: "restart", Index: 0}, "payload", stored); err == nil {
		t.Fatal("cross-tenant ciphertext accepted")
	}
	available.Store(true)
	restarted := queueForTest(t, db, server.URL)
	drainInspection(t, restarted)
	_, err := db.Exec(context.Background(), "INSERT INTO request_logs VALUES('tenant','restart','customer')")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = restarted.reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	var status string
	var count, complete int
	_ = db.QueryRow(context.Background(), "SELECT status,completed_parts FROM proxy_inspection_jobs").Scan(&status, &complete)
	_ = db.QueryRow(context.Background(), "SELECT count(*) FROM security_events").Scan(&count)
	if status != "completed" || complete != 1 || count != 1 {
		t.Fatalf("state=%s parts=%d events=%d", status, complete, count)
	}
	_ = db.QueryRow(context.Background(), "SELECT payload_encrypted FROM proxy_inspection_parts").Scan(&stored)
	if stored != "" {
		t.Fatal("completed payload not erased")
	}
}

// An inspection that has not finished is an inspection gap: the request is
// forwarded and recorded (audit + incomplete), never withheld.
func TestInspectionIncompleteIsRecordedAndForwarded(t *testing.T) {
	db := inspectionDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	action, _, meta := q.inspect(context.Background(), "tenant", "strict", "api.example.test", simplePlan("hello"), false)
	if action != "audit" || meta.SemanticStatus != "incomplete" || meta.SemanticReason != "inspection_queued" {
		t.Fatalf("incomplete inspection must be recorded and forwarded: %s %+v", action, meta)
	}
}
func TestInspectionLarge64MiBRequestActuallyScansTailAndAttachment(t *testing.T) {
	db := inspectionDB(t)
	var texts, attachments atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = io.WriteString(w, `{"object_id":"synthetic-object","sha256":"synthetic","size":1048584}`)
			return
		}
		if r.Method == "DELETE" {
			w.WriteHeader(200)
			return
		}
		var p map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
		}
		c, _ := p["context"].(map[string]interface{})
		if a, ok := c["attachments"].([]interface{}); ok && len(a) > 0 {
			attachments.Add(1)
		}
		text := fmt.Sprint(p["content"])
		if strings.Contains(text, "TAIL-RISK") {
			texts.Add(1)
		}
		completedInspection(w, text)
	}))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	raw := append([]byte{137, 80, 78, 71, 13, 10, 26, 10}, bytes.Repeat([]byte{0}, 1024*1024)...)
	image := "data:image/png;base64," + base64.StdEncoding.EncodeToString(raw)
	parts := []map[string]interface{}{}
	for i := 0; i < 49; i++ {
		parts = append(parts, map[string]interface{}{"type": "input_image", "image_url": image})
	}
	parts = append(parts, map[string]interface{}{"type": "input_text", "text": "TAIL-RISK"})
	body, err := json.Marshal(map[string]interface{}{"model": "synthetic", "input": []interface{}{map[string]interface{}{"role": "user", "content": parts}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 64*1024*1024 {
		t.Fatal("fixture must exceed 64 MiB")
	}
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	action, findings, meta := q.client.CheckInput(context.Background(), "tenant", "large-64m", req)
	if action != "block" || len(findings) == 0 || meta.SemanticStatus != "completed" || texts.Load() != 1 || attachments.Load() != 1 {
		rows, _ := db.Query(context.Background(), "SELECT part_index,status,attempts,last_error,length(payload_encrypted) FROM proxy_inspection_parts ORDER BY part_index LIMIT 10")
		for rows.Next() {
			var index, attempts, size int
			var state, reason string
			_ = rows.Scan(&index, &state, &attempts, &reason, &size)
			t.Log(index, state, attempts, reason, size)
		}
		rows.Close()
		t.Fatalf("large request not fully inspected: %s findings=%d meta=%+v text=%d attachments=%d", action, len(findings), meta, texts.Load(), attachments.Load())
	}
	forwarded, _ := io.ReadAll(req.Body)
	if !bytes.Equal(body, forwarded) {
		t.Fatal("request mutated")
	}
}
func TestInspectionConcurrentClaimsLeaseRecoveryAndTerminalFailure(t *testing.T) {
	db := inspectionDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	if err := q.enqueue(context.Background(), "tenant", "lease", "host", "audit", simplePlan("hello")); err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec(context.Background(), "UPDATE proxy_inspection_jobs SET admission='forwarded'")
	var wg sync.WaitGroup
	var claims atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, e := q.claim(context.Background(), "", "")
			if e != nil {
				t.Error(e)
			}
			if p != nil {
				claims.Add(1)
			}
		}()
	}
	wg.Wait()
	if claims.Load() != 1 {
		t.Fatal("same work claimed twice")
	}
	_, _ = db.Exec(context.Background(), "UPDATE proxy_inspection_parts SET lease_until=now()-interval '1 second',attempts=7")
	p, err := q.claim(context.Background(), "", "")
	if err != nil || p == nil {
		t.Fatalf("lease not recovered: %v", err)
	}
	if err = q.execute(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err = q.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	var status string
	_ = db.QueryRow(context.Background(), "SELECT status FROM proxy_inspection_jobs").Scan(&status)
	if status != "failed" {
		t.Fatal("retry exhaustion not visible")
	}
}
func TestInspectionBurstIsBoundedAndCompletes(t *testing.T) {
	db := inspectionDB(t)
	var active, peak atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		time.Sleep(10 * time.Millisecond)
		completedInspection(w, "hello")
	}))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hello"}]}`))
			req.Header.Set("Content-Type", "application/json")
			a, _, m := q.client.CheckInput(context.Background(), "tenant", fmt.Sprint("burst-", i), req)
			if a != "allow" || m.SemanticStatus != "completed" {
				t.Errorf("burst incomplete: %s %+v", a, m)
			}
		}(i)
	}
	wg.Wait()
	if peak.Load() > 2 {
		t.Fatalf("unbounded engine concurrency %d", peak.Load())
	}
}

func TestInspectionCapacityIsRecordedGapInEnforceMode(t *testing.T) {
	t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", "false")
	db := inspectionDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { completedInspection(w, "hello") }))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	if err := q.enqueue(context.Background(), "tenant", "full", "host", "audit", simplePlan("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(context.Background(), `UPDATE proxy_inspection_jobs SET payload_bytes=512*1024*1024`); err != nil {
		t.Fatal(err)
	}
	action, _, meta := q.inspect(context.Background(), "tenant", "next", "host", simplePlan("hello"), false)
	if action == "block" || meta.SemanticReason != "inspection_queue_capacity" {
		t.Fatalf("防护模式下队列溢出记为覆盖缺口并放行（CHANGELOG 2.6.14）: %s %+v", action, meta)
	}
	if _, err := db.Exec(context.Background(), `UPDATE proxy_inspection_jobs SET total_parts=2`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := q.snapshot(context.Background(), "tenant", "full"); err == nil {
		t.Fatal("missing inspection work accepted")
	}
}

// 生产事故回归（2026-09-19）：全局留痕（security_audit_only=true）期间，补检队列
// 因积压撞上单租户 512MB 容量闸门，enqueue 失败分支不看审计位直接 block，
// 用户请求被 403 且告警显示"拦截"（723 条/24h）。审计模式是绝对的：队列不可用
// 记为覆盖缺口（security_check_failed/audit）并放行，绝不拦截。
func TestInspectionCapacityNeverBlocksInAuditOnlyMode(t *testing.T) {
	t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", "true")
	db := inspectionDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { completedInspection(w, "hello") }))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	if err := q.enqueue(context.Background(), "tenant", "full", "host", "audit", simplePlan("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(context.Background(), `UPDATE proxy_inspection_jobs SET payload_bytes=512*1024*1024`); err != nil {
		t.Fatal(err)
	}
	action, findings, meta := q.inspect(context.Background(), "tenant", "next", "host", simplePlan("hello"), true)
	if action != "audit" {
		t.Fatalf("审计模式下队列溢出不得拦截，got action=%q want audit", action)
	}
	if meta.SemanticStatus != "incomplete" || meta.SemanticReason != "inspection_queue_capacity" {
		t.Fatalf("覆盖缺口证据必须保留，got %+v", meta)
	}
	if len(findings) != 0 {
		t.Fatalf("未执行检测不得伪造 findings，got %v", findings)
	}
	if _, err := db.Exec(context.Background(), `UPDATE proxy_inspection_jobs SET payload_bytes=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(context.Background(), `UPDATE proxy_inspection_jobs SET total_parts=2`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := q.snapshot(context.Background(), "tenant", "full"); err == nil {
		t.Fatal("missing inspection work accepted")
	}
}

// 同一入队身份（tenant+request）重放触发 enqueue 确定性失败，验证审计模式同样放行。
func TestInspectionDuplicateAdmissionNeverBlocksInAuditOnlyMode(t *testing.T) {
	db := inspectionDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { completedInspection(w, "hello") }))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	action, _, _ := q.inspect(context.Background(), "tenant", "req-dup", "host", simplePlan("hello"), false)
	if action != "allow" && action != "audit" {
		t.Fatalf("首个请求应正常完成, got %q", action)
	}
	action, _, meta := q.inspect(context.Background(), "tenant", "req-dup", "host", simplePlan("hello again"), false)
	if action == "block" || meta.SemanticReason != "inspection_queue_unavailable" {
		t.Fatalf("防护模式下重复入队记为覆盖缺口并放行: %s %+v", action, meta)
	}
	action, _, meta = q.inspect(context.Background(), "tenant", "req-dup", "host", simplePlan("hello again"), true)
	if action != "audit" {
		t.Fatalf("审计模式下重复入队不得拦截，got %q want audit", action)
	}
	if meta.SemanticReason != "inspection_queue_unavailable" {
		t.Fatalf("缺口证据必须保留，got %+v", meta)
	}
}

func TestInspectionFilePendingIsNotRiskOrCompleted(t *testing.T) {
	for _, status := range []string{"pending", "not_found", "allow", "block"} {
		t.Run(status, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": status})
			}))
			defer server.Close()
			client := NewSecurityClientWithSecret(server.URL, testInspectionKey)
			p := simplePlan("")[0]
			p["inspection_attachment"] = ExtractedAttachment{ReferenceID: "file-synthetic"}
			result, err := client.executeInspectionPart(context.Background(), p, true)
			if status == "pending" || status == "not_found" {
				// 2.9.22：没有检测记录、检测未完成按文件策略“未核验的文件引用”立即处置（缺省告警放行），
				// 不再当成检测未完成反复重试；缺省处置不是风险结论，不拦。
				if err != nil || !inspectionComplete(result) || result["action"] != "audit" {
					t.Fatalf("unknown file verdict must follow the file policy at once: %v %+v", err, result)
				}
				return
			}
			if err != nil || !inspectionComplete(result) {
				t.Fatalf("known verdict lost: %v %+v", err, result)
			}
			if status == "block" && result["action"] != "block" {
				t.Fatal("known blocked file admitted")
			}
		})
	}
}

func TestInspectionStaleLeaseCannotOverwriteCompletedRisk(t *testing.T) {
	db := inspectionDB(t)
	var risk atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if risk.Load() {
			completedInspection(w, "TAIL-RISK")
		} else {
			completedInspection(w, "hello")
		}
	}))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	if err := q.enqueue(context.Background(), "tenant", "stale", "host", "audit", simplePlan("hello")); err != nil {
		t.Fatal(err)
	}
	old, err := q.claim(context.Background(), "tenant", "stale")
	if err != nil || old == nil {
		t.Fatal(err)
	}
	_, err = db.Exec(context.Background(), `UPDATE proxy_inspection_parts SET lease_until=now()-interval '1 second'`)
	if err != nil {
		t.Fatal(err)
	}
	current, err := q.claim(context.Background(), "tenant", "stale")
	if err != nil || current == nil {
		t.Fatal(err)
	}
	risk.Store(true)
	if err = q.execute(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	risk.Store(false)
	if err = q.execute(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	state, findings, action, err := q.snapshot(context.Background(), "tenant", "stale")
	if err != nil || state != "completed" || action != "block" || len(findings) != 1 {
		t.Fatalf("stale worker replaced risk: %s %s %+v %v", state, action, findings, err)
	}
}

func TestInspectionCacheScopeEpochAndIncomplete(t *testing.T) {
	var calls atomic.Int32
	var incomplete atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if incomplete.Load() {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"action": "allow", "findings": []interface{}{}, "raw_findings": []interface{}{}, "semantic_status": "incomplete", "engine_build": "test-v1", "rule_pack_version": "rules-v1"})
			return
		}
		completedInspection(w, "hello")
	}))
	defer server.Close()
	client := NewSecurityClientWithSecret(server.URL, testInspectionKey).WithFingerprintStore(scanfp.NewStore(nil, 4096))
	p := simplePlan("repeat this content")[0]
	if _, err := client.executeInspectionPart(context.Background(), p, true); err != nil {
		t.Fatal(err)
	}
	p["inspection_cache_epoch"] = "test-v1|rules-v1|semantic-v1"
	if _, err := client.executeInspectionPart(context.Background(), p, false); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("completed identical scope cache missed: %d", calls.Load())
	}
	p["context"].(map[string]interface{})["tenant_id"] = "other"
	_, _ = client.executeInspectionPart(context.Background(), p, false)
	if calls.Load() != 2 {
		t.Fatal("cross-tenant cache reused")
	}
	p["inspection_cache_epoch"] = "test-v2|rules-v1|semantic-v1"
	_, _ = client.executeInspectionPart(context.Background(), p, false)
	if calls.Load() != 3 {
		t.Fatal("stale engine epoch cache reused")
	}
	p["context"].(map[string]interface{})["host"] = "other.example.test"
	_, _ = client.executeInspectionPart(context.Background(), p, false)
	if calls.Load() != 4 {
		t.Fatal("cross-policy host cache reused")
	}
	incomplete.Store(true)
	p["content"] = "never cache incomplete"
	p["inspection_cache_epoch"] = "test-v1|rules-v1|semantic-v1"
	_, _ = client.executeInspectionPart(context.Background(), p, false)
	_, _ = client.executeInspectionPart(context.Background(), p, false)
	if calls.Load() != 6 {
		t.Fatal("incomplete result cached as clean")
	}
}

func TestInspectionIncompleteOrMalformedNeverBecomesClean(t *testing.T) {
	for _, r := range []map[string]interface{}{
		{"semantic_status": "completed"},
		{"semantic_status": "completed", "action": "unknown", "findings": []interface{}{}},
		{"semantic_status": "completed", "action": "allow", "findings": nil},
		{"semantic_status": "completed", "inspection_status": "incomplete", "action": "allow", "findings": []interface{}{}},
		{"semantic_status": "skipped", "semantic_reason": "deferred", "action": "allow", "findings": []interface{}{}},
	} {
		if inspectionComplete(r) {
			t.Fatalf("invalid complete result: %+v", r)
		}
	}
}

func TestInspectionFinalizationDoesNotReadOtherEnvironment(t *testing.T) {
	db := inspectionDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { completedInspection(w, "hello") }))
	defer server.Close()
	customer := queueForTest(t, db, server.URL)
	homeClient := NewSecurityClientWithSecret(server.URL, testInspectionKey)
	home, err := NewInspectionQueue(db, homeClient, "different-synthetic-encryption-secret", "home")
	if err != nil {
		t.Fatal(err)
	}
	_, _, meta := home.inspect(context.Background(), "tenant", "home-only", "host", simplePlan("hello"), true)
	if meta.SemanticStatus != "completed" {
		t.Fatal(meta)
	}
	_, err = db.Exec(context.Background(), `INSERT INTO request_logs VALUES('tenant','home-only','home')`)
	if err != nil {
		t.Fatal(err)
	}
	if err = customer.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM security_events`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("other environment finalized: %d %v", count, err)
	}
	if err = home.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(context.Background(), `SELECT count(*) FROM security_events`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("owner environment did not finalize: %d %v", count, err)
	}
}

func TestInspectionLongTenantFinalEventFitsSchema(t *testing.T) {
	db := inspectionDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { completedInspection(w, "hello") }))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	tenant := strings.Repeat("t", 64)
	request := uuid.NewString()
	_, _, meta := q.inspect(context.Background(), tenant, request, "host", simplePlan("hello"), true)
	if meta.SemanticStatus != "completed" {
		t.Fatal(meta)
	}
	_, err := db.Exec(context.Background(), `INSERT INTO request_logs VALUES($1,$2,'customer')`, tenant, request)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = q.reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	var id string
	if err = db.QueryRow(context.Background(), `SELECT id FROM security_events`).Scan(&id); err != nil || id != inspectionEventID(tenant, request) || len(id) > 64 {
		t.Fatalf("invalid event identity: %s %v", id, err)
	}
	var count int
	_ = db.QueryRow(context.Background(), `SELECT count(*) FROM security_events`).Scan(&count)
	if count != 1 {
		t.Fatal("final event duplicated")
	}
}

func TestInspectionWorkerCountFromEnv(t *testing.T) {
	t.Setenv("PROXY_INSPECTION_WORKERS", "")
	if got := inspectionWorkerCount(); got != 2 {
		t.Fatalf("默认应为 2，got %d", got)
	}
	t.Setenv("PROXY_INSPECTION_WORKERS", "8")
	if got := inspectionWorkerCount(); got != 8 {
		t.Fatalf("环境变量未生效，got %d", got)
	}
	t.Setenv("PROXY_INSPECTION_WORKERS", "999")
	if got := inspectionWorkerCount(); got != 2 {
		t.Fatalf("越界必须回落默认 2，got %d", got)
	}
	t.Setenv("PROXY_INSPECTION_WORKERS", "abc")
	if got := inspectionWorkerCount(); got != 2 {
		t.Fatalf("非数字必须回落默认 2，got %d", got)
	}
	t.Setenv("PROXY_INSPECTION_WORKERS", "0")
	if got := inspectionWorkerCount(); got != 2 {
		t.Fatalf("0 必须回落默认 2，got %d", got)
	}
}

func TestInspectionQueuePreservesCriticalEvidenceSeverity(t *testing.T) {
	db := inspectionDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := []any{map[string]any{"type": "secret", "category": "synthetic_credential", "severity": "critical", "action": "audit", "counts_as_security_finding": true}}
		_ = json.NewEncoder(w).Encode(map[string]any{"action": "audit", "findings": f, "raw_findings": f, "semantic_status": "completed", "inspection_status": "completed"})
	}))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	if err := q.enqueue(context.Background(), "tenant", "severity-critical", "api.example.test", "audit", simplePlan("synthetic credential")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(context.Background(), "UPDATE proxy_inspection_jobs SET admission='forwarded'; INSERT INTO request_logs VALUES('tenant','severity-critical','customer')"); err != nil {
		t.Fatal(err)
	}
	drainInspection(t, q)
	if err := q.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	var severity, effective string
	if err := db.QueryRow(context.Background(), "SELECT severity,matched_summary->>'effective_severity' FROM security_events").Scan(&severity, &effective); err != nil {
		t.Fatal(err)
	}
	if severity != "critical" || effective != "critical" {
		t.Fatalf("severity lost: %s / %s", severity, effective)
	}
}
