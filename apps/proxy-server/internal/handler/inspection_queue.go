package handler

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// InspectionQueue persists encrypted work before audit-mode admission. Leases and
// token-checked acknowledgements make process restarts and competing replicas safe.
type InspectionQueue struct {
	db          *pgxpool.Pool
	aead        cipher.AEAD
	client      *SecurityClient
	environment string
	slots       chan struct{}
}
type inspectionPart struct {
	Tenant, Request, Token, Payload, Previous string
	Index, Attempts                           int
	Mode, Epoch                               string
}

func NewInspectionQueue(db *pgxpool.Pool, client *SecurityClient, secret, environment string) (*InspectionQueue, error) {
	if db == nil || len(secret) < 16 {
		return nil, errors.New("inspection durable storage or encryption key unavailable")
	}
	key := sha256.Sum256([]byte("jjdguard:inspection-queue:v1:" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	q := &InspectionQueue{db: db, aead: aead, client: client, environment: environment, slots: make(chan struct{}, 2)}
	var ready bool
	if err = db.QueryRow(context.Background(), "SELECT to_regclass('proxy_inspection_parts') IS NOT NULL").Scan(&ready); err != nil || !ready {
		return nil, errors.New("inspection migration 846 is required")
	}
	client.inspectionQueue = q
	return q, nil
}
func (q *InspectionQueue) seal(tenant, request string, index int, kind string, data []byte) (string, error) {
	nonce := make([]byte, q.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	aad := fmt.Sprintf("%s/%s/%d/%s", tenant, request, index, kind)
	return base64.RawStdEncoding.EncodeToString(q.aead.Seal(nonce, nonce, data, []byte(aad))), nil
}
func (q *InspectionQueue) open(p inspectionPart, kind, value string) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(b) < q.aead.NonceSize() {
		return nil, errors.New("invalid encrypted inspection payload")
	}
	n := q.aead.NonceSize()
	aad := fmt.Sprintf("%s/%s/%d/%s", p.Tenant, p.Request, p.Index, kind)
	return q.aead.Open(nil, b[:n], b[n:], []byte(aad))
}
func (q *InspectionQueue) enqueue(ctx context.Context, tenant, request, host, mode string, tasks []map[string]interface{}) error {
	encrypted := make([]string, len(tasks))
	var size int64
	for i, task := range tasks {
		b, err := json.Marshal(task)
		if err != nil {
			return err
		}
		enc, err := q.seal(tenant, request, i, "payload", b)
		if err != nil {
			return err
		}
		encrypted[i] = enc
		size += int64(len(enc))
	}
	tx, err := q.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize admission only (never execution), so aggregate limits cannot race.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(84620260916)"); err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM proxy_inspection_jobs WHERE tenant_id=$1 AND request_id=$2)", tenant, request).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return errors.New("inspection request identity already exists")
	}
	var global, own, jobs int64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(sum(payload_bytes),0),COALESCE(sum(payload_bytes) FILTER(WHERE tenant_id=$1),0),count(*) FROM proxy_inspection_jobs WHERE status IN ('pending','running')`, tenant).Scan(&global, &own, &jobs); err != nil {
		return err
	}
	if global+size > 2*1024*1024*1024 || own+size > 512*1024*1024 || jobs >= 10000 {
		return securityexit.NewInspectionFailure("inspection_queue_capacity", nil)
	}
	_, err = tx.Exec(ctx, `INSERT INTO proxy_inspection_jobs(tenant_id,request_id,environment_scope,target_host,mode,total_parts,payload_bytes) VALUES($1,$2,$3,$4,$5,$6,$7)`, tenant, request, q.environment, host, mode, len(tasks), size)
	if err != nil {
		return err
	}
	batch := &pgx.Batch{}
	for i, enc := range encrypted {
		batch.Queue(`INSERT INTO proxy_inspection_parts(tenant_id,request_id,part_index,payload_encrypted) VALUES($1,$2,$3,$4)`, tenant, request, i, enc)
	}
	if err = tx.SendBatch(ctx, batch).Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (q *InspectionQueue) claim(ctx context.Context, tenant, request string) (*inspectionPart, error) {
	token := uuid.NewString()
	row := q.db.QueryRow(ctx, `WITH candidate AS (
 SELECT p.tenant_id,p.request_id,p.part_index FROM proxy_inspection_parts p
 JOIN proxy_inspection_jobs j USING(tenant_id,request_id)
 WHERE j.status IN ('pending','running') AND j.expires_at>now() AND j.environment_scope=$4
 AND ($1='' OR (p.tenant_id=$1 AND p.request_id=$2))
 AND (j.admission<>'waiting' OR $1<>'')
 AND (p.part_index=0 OR EXISTS(SELECT 1 FROM proxy_inspection_parts first_part WHERE first_part.tenant_id=p.tenant_id AND first_part.request_id=p.request_id AND first_part.part_index=0 AND first_part.status='completed'))
 AND ((p.status='pending' AND p.next_attempt_at<=now()) OR (p.status='running' AND p.lease_until<now()))
 ORDER BY j.last_claimed_at,p.next_attempt_at,p.part_index FOR UPDATE OF p SKIP LOCKED LIMIT 1
 ), claimed AS (
 UPDATE proxy_inspection_parts p SET status='running',attempts=attempts+1,lease_token=$3,lease_until=now()+interval '90 seconds'
 FROM candidate c WHERE p.tenant_id=c.tenant_id AND p.request_id=c.request_id AND p.part_index=c.part_index
 RETURNING p.*), touched AS (
 UPDATE proxy_inspection_jobs j SET last_claimed_at=now() FROM claimed c WHERE j.tenant_id=c.tenant_id AND j.request_id=c.request_id RETURNING j.request_id)
 SELECT c.tenant_id,c.request_id,c.part_index,c.payload_encrypted,c.result_encrypted,c.attempts,j.mode,j.inspection_version
 FROM claimed c JOIN proxy_inspection_jobs j USING(tenant_id,request_id)`, tenant, request, token, q.environment)
	p := &inspectionPart{Token: token}
	err := row.Scan(&p.Tenant, &p.Request, &p.Index, &p.Payload, &p.Previous, &p.Attempts, &p.Mode, &p.Epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return p, err
}
func inspectionComplete(result map[string]interface{}) bool {
	switch result["action"] {
	case "allow", "audit", "block", "reply", "deny", "mask", "redact", "quarantine":
	default:
		return false
	}
	if _, ok := result["findings"].([]interface{}); !ok {
		return false
	}
	if result["inspection_status"] == "incomplete" {
		return false
	}
	return cacheableSemanticResponse(result)
}
func mergeInspectionResult(previous, current map[string]interface{}) map[string]interface{} {
	if previous == nil {
		return current
	}
	if current == nil {
		return previous
	}
	seen := map[string]bool{}
	all := []interface{}{}
	for _, r := range []map[string]interface{}{previous, current} {
		if items, ok := r["findings"].([]interface{}); ok {
			for _, f := range items {
				b, _ := json.Marshal(f)
				if !seen[string(b)] {
					seen[string(b)] = true
					all = append(all, f)
				}
			}
		}
	}
	current["findings"] = all
	if inspectionActionRank(fmt.Sprint(previous["action"])) > inspectionActionRank(fmt.Sprint(current["action"])) {
		current["action"] = previous["action"]
	}
	return current
}
func inspectionActionRank(action string) int {
	switch action {
	case "block", "reply", "deny", "quarantine":
		return 4
	case "mask", "redact":
		return 3
	case "audit":
		return 2
	default:
		return 1
	}
}

func (q *InspectionQueue) execute(ctx context.Context, p *inspectionPart) error {
	raw, err := q.open(*p, "payload", p.Payload)
	var result map[string]interface{}
	reason := "inspection_engine_unavailable"
	if err == nil {
		var payload map[string]interface{}
		if err = json.Unmarshal(raw, &payload); err == nil {
			payload["inspection_cache_epoch"] = p.Epoch
			result, err = q.client.executeInspectionPart(ctx, payload, p.Index == 0)
		}
	} else {
		reason = "inspection_payload_unreadable"
	}
	if err != nil {
		reason = securityexit.FailureReason(err, reason)
	}
	if result == nil {
		result = map[string]interface{}{"action": "audit", "findings": []interface{}{}, "semantic_status": "incomplete", "semantic_reason": reason}
	}
	complete := err == nil && inspectionComplete(result)
	if p.Previous != "" {
		old, e := q.open(*p, "result", p.Previous)
		var previous map[string]interface{}
		if e != nil || json.Unmarshal(old, &previous) != nil {
			complete = false
			reason = "inspection_result_unreadable"
			result["semantic_reason"] = reason
		} else {
			result = mergeInspectionResult(previous, result)
		}
	}
	status := "pending"
	if complete {
		status = "completed"
		reason = ""
	} else if p.Attempts >= 8 || reason == "inspection_payload_unreadable" || reason == "inspection_result_unreadable" {
		status = "failed"
	}
	if !complete {
		if r, ok := result["semantic_reason"].(string); ok && r != "" {
			reason = r
		}
		if len(reason) > 100 {
			reason = "inspection_incomplete"
		}
	}
	encoded, _ := json.Marshal(result)
	sealed, err := q.seal(p.Tenant, p.Request, p.Index, "result", encoded)
	if err != nil {
		return err
	}
	// The caller's budget may have expired while the engine was running. Persist
	// the outcome under an independent short deadline, never lose acknowledged work.
	save, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ack, err := q.db.Exec(save, `UPDATE proxy_inspection_parts SET status=$4,result_encrypted=$5,last_error=$6,lease_until=NULL,lease_token=NULL,next_attempt_at=now()+($7*interval '1 second'),payload_encrypted=CASE WHEN $4='completed' THEN '' ELSE payload_encrypted END WHERE tenant_id=$1 AND request_id=$2 AND part_index=$3 AND lease_token=$8`, p.Tenant, p.Request, p.Index, status, sealed, reason, 1<<min(p.Attempts, 8), p.Token)
	if err == nil && ack.RowsAffected() == 1 && complete && p.Index == 0 {
		build, _ := result["engine_build"].(string)
		rules, _ := result["rule_pack_version"].(string)
		revision, _ := result["semantic_config_revision"].(string)
		epoch := ""
		if build != "" && rules != "" {
			epoch = fmt.Sprintf("%s|%s|%s", build, rules, revision)
		}
		_, err = q.db.Exec(save, `UPDATE proxy_inspection_jobs SET inspection_version=$3 WHERE tenant_id=$1 AND request_id=$2`, p.Tenant, p.Request, epoch)
	}
	return err
}

func (q *InspectionQueue) snapshot(ctx context.Context, tenant, request string) (string, []map[string]interface{}, string, error) {
	var expected int
	if err := q.db.QueryRow(ctx, `SELECT total_parts FROM proxy_inspection_jobs WHERE tenant_id=$1 AND request_id=$2`, tenant, request).Scan(&expected); err != nil {
		return "", nil, "block", err
	}
	rows, err := q.db.Query(ctx, `SELECT part_index,status,result_encrypted FROM proxy_inspection_parts WHERE tenant_id=$1 AND request_id=$2 ORDER BY part_index`, tenant, request)
	if err != nil {
		return "", nil, "block", err
	}
	defer rows.Close()
	state := "completed"
	action := "allow"
	findings := []map[string]interface{}{}
	seen := map[string]bool{}
	count := 0
	capacityReason := ""
	policy := q.client.inspectionPolicy(ctx)
	for rows.Next() {
		count++

		var index int
		var status, encoded string
		if err = rows.Scan(&index, &status, &encoded); err != nil {
			return "", nil, "block", err
		}
		if status == "failed" {
			state = "failed"
		} else if status != "completed" && state != "failed" {
			state = "pending"
		}
		if encoded == "" {
			continue
		}
		data, e := q.open(inspectionPart{Tenant: tenant, Request: request, Index: index}, "result", encoded)
		if e != nil {
			return "", nil, "block", e
		}
		var result map[string]interface{}
		if e = json.Unmarshal(data, &result); e != nil {
			return "", nil, "block", e
		}
		if reason, ok := result["semantic_reason"].(string); status != "completed" && ok && securityexit.IsCapacityReason(reason) {
			capacityReason = reason
		}
		partAction, items := q.client.parseResponse(result)
		scoped := items[:0:0]
		for _, f := range items {
			if inspectionFindingInScope(policy, f) {
				scoped = append(scoped, f)
			}
		}
		if len(scoped) < len(items) && inspectionActionRank(partAction) > 1 {
			// A result computed for a now-excluded source cannot keep its action.
			partAction = "allow"
			for _, f := range scoped {
				if a, ok := f["action"].(string); ok && inspectionActionRank(a) > inspectionActionRank(partAction) {
					partAction = a
				}
			}
		}
		items = scoped
		if inspectionActionRank(partAction) > inspectionActionRank(action) {
			action = partAction
		}
		for _, f := range items {
			if !proxyFindingCountsAsSecurity(f) {
				continue
			}
			b, _ := json.Marshal(f)
			if !seen[string(b)] {
				seen[string(b)] = true
				f["inspection_part_index"] = index
				findings = append(findings, f)
			}
		}
	}
	if count == 0 || count != expected {
		return "", nil, "block", errors.New("inspection work missing")
	}
	if err := rows.Err(); err != nil {
		return state, findings, action, err
	}
	if capacityReason != "" {
		return state, findings, action, securityexit.NewInspectionFailure(capacityReason, nil)
	}
	return state, findings, action, nil
}

func (q *InspectionQueue) inspect(ctx context.Context, tenant, request, host string, tasks []map[string]interface{}, auditOnly bool) (string, []map[string]interface{}, *FingerprintScanMeta) {
	mode := "enforce"
	budget := 45 * time.Second
	if auditOnly {
		mode = "audit"
		budget = 2 * time.Second
	}
	if err := q.enqueue(ctx, tenant, request, host, mode, tasks); err != nil {
		return proxyInspectionFailure(auditOnly, err, "inspection_queue_unavailable", q.client.detectionPolicy())
	}
	run, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for run.Err() == nil {
		part, err := q.claim(run, tenant, request)
		if err != nil || part == nil {
			break
		}
		if err = q.execute(run, part); err != nil {
			break
		}
	}
	save, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	status, findings, action, err := q.snapshot(save, tenant, request)
	if err != nil && securityexit.FailureCause(err) != securityexit.Capacity {
		// A snapshot that cannot be read (database error, undecryptable part,
		// missing inspection work) is a coverage gap, not a verdict: its
		// sentinel "block" must not interrupt traffic. Only findings that were
		// actually read may earn an action.
		action = "allow"
	}
	if len(findings) > 0 {
		if inspectionActionRank(action) < 2 {
			action = "audit"
		}
		for _, f := range findings {
			if a, ok := f["action"].(string); ok && inspectionActionRank(a) > inspectionActionRank(action) {
				action = a
			}
		}
	}
	reason := ""
	semantic := "completed"
	capacityRejected := false
	detectionRejected := false
	if err != nil || status != "completed" {
		semantic = "incomplete"
		reason = "inspection_queued"
		if status == "failed" {
			reason = "inspection_failed"
		}
		// Preserve verified findings, then apply the configured failure policy.
		action = strongerProxyRecordAction(action)
		failureAction, _, failureMeta := proxyInspectionFailure(auditOnly, err, reason, q.client.detectionPolicy())
		reason = failureMeta.SemanticReason
		capacityRejected, detectionRejected = failureMeta.CapacityRejected, failureMeta.DetectionRejected
		if inspectionActionRank(failureAction) > inspectionActionRank(action) {
			action = failureAction
		}
	}
	if auditOnly {
		action = clampFileDLPActionForAudit(action, true)
	} else if fileDLPActionBlocksExternalSend(action) {
		// A split scan cannot rewrite the original protocol body; a configured
		// block/deny/quarantine withholds the original request.
		action = "block"
	} else if action == "mask" || action == "redact" {
		// A configured mask the split scan cannot apply is forwarded and alerted.
		action = "audit"
	}
	admission := "forwarded"
	if fileDLPActionBlocksExternalSend(action) {
		admission = "blocked"
	}
	if status == "completed" {
		admission += "_complete"
	}
	if _, e := q.db.Exec(save, `UPDATE proxy_inspection_jobs SET admission=$3,updated_at=now() WHERE tenant_id=$1 AND request_id=$2`, tenant, request, admission); e != nil {
		failureAction, _, failureMeta := proxyInspectionFailure(auditOnly, e, "inspection_queue_unavailable", q.client.detectionPolicy())
		if inspectionActionRank(failureAction) > inspectionActionRank(action) {
			action = failureAction
		}
		failureMeta.CapacityRejected = failureMeta.CapacityRejected || capacityRejected
		failureMeta.DetectionRejected = failureMeta.DetectionRejected || detectionRejected
		return strongerProxyRecordAction(clampFileDLPActionForAudit(action, auditOnly)), findings, failureMeta
	}
	return action, findings, &FingerprintScanMeta{SemanticStatus: semantic, SemanticReason: reason, CapacityRejected: capacityRejected, DetectionRejected: detectionRejected}
}

// 后台消化 worker 数：默认 2（历史硬编码值，客户 16C/32GiB 基线的保守选择）。
// 用 PROXY_INSPECTION_WORKERS 可调到 64；GPU 裁判或高流量部署通常 4-16。
// 每 worker 一路 claim→execute 循环，吞吐近似线性增长，直到 judge/DB 一侧先到顶。
func inspectionWorkerCount() int {
	if v := os.Getenv("PROXY_INSPECTION_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 64 {
			return n
		}
		log.Printf("PROXY_INSPECTION_WORKERS=%q 无效（取 1-64 的整数），回落默认 2", v)
	}
	return 2
}

// Start uses bounded workers; outstanding database leases are recovered after a crash.
func (q *InspectionQueue) Start(ctx context.Context) {
	for i := 0; i < inspectionWorkerCount(); i++ {
		go func() {
			for ctx.Err() == nil {
				part, err := q.claim(ctx, "", "")
				if err == nil && part != nil {
					run, cancel := context.WithTimeout(ctx, 60*time.Second)
					if e := q.execute(run, part); e != nil && ctx.Err() == nil {
						log.Printf("inspection worker persistence failed: %T", e)
					}
					cancel()
					continue
				}
				if err != nil && ctx.Err() == nil {
					log.Printf("inspection queue claim failed: %T", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
		}()
	}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if e := q.reconcile(ctx); e != nil && ctx.Err() == nil {
					log.Printf("inspection reconciliation failed: %T", e)
				}
			}
		}
	}()
}

func (q *InspectionQueue) reconcile(ctx context.Context) error {
	// A crash before admission cannot authorize forwarding; recover work as blocked.
	_, err := q.db.Exec(ctx, `UPDATE proxy_inspection_jobs SET admission='blocked' WHERE admission='waiting' AND created_at<now()-interval '2 minutes';
 UPDATE proxy_inspection_parts p SET status='failed',last_error='inspection_expired',payload_encrypted='',lease_token=NULL FROM proxy_inspection_jobs j WHERE p.tenant_id=j.tenant_id AND p.request_id=j.request_id AND j.expires_at<now() AND p.status IN ('pending','running');
 UPDATE proxy_inspection_jobs j SET completed_parts=s.completed,status=CASE WHEN s.failed>0 THEN 'failed' WHEN s.completed=j.total_parts THEN 'completed' ELSE 'running' END,updated_at=now(),last_error=CASE WHEN s.failed>0 THEN 'inspection_retry_exhausted' ELSE '' END
 FROM (SELECT tenant_id,request_id,count(*) FILTER(WHERE status='completed') AS completed,count(*) FILTER(WHERE status='failed') AS failed FROM proxy_inspection_parts p WHERE EXISTS(SELECT 1 FROM proxy_inspection_jobs active WHERE active.tenant_id=p.tenant_id AND active.request_id=p.request_id AND active.status IN ('pending','running')) GROUP BY tenant_id,request_id) s
 WHERE j.tenant_id=s.tenant_id AND j.request_id=s.request_id AND j.status IN ('pending','running');`)
	if err != nil {
		return err
	}
	rows, err := q.db.Query(ctx, `SELECT j.tenant_id,j.request_id,j.target_host,j.status,j.admission,COALESCE(NULLIF(to_jsonb(r)->>'project_id',''),'project_default'),COALESCE(to_jsonb(r)->>'source_ip',to_jsonb(r)->>'proxy_source_ip',''),COALESCE(to_jsonb(r)->>'agent_type','') FROM proxy_inspection_jobs j JOIN LATERAL(SELECT r.* FROM request_logs r WHERE r.tenant_id=j.tenant_id AND r.request_id=j.request_id AND r.environment_scope=j.environment_scope LIMIT 1) r ON true WHERE j.environment_scope=$1 AND j.status IN ('completed','failed') AND j.admission<>'waiting' AND EXISTS(SELECT 1 FROM request_logs r WHERE r.tenant_id=j.tenant_id AND r.request_id=j.request_id AND r.environment_scope=j.environment_scope) AND NOT EXISTS(SELECT 1 FROM security_events e WHERE e.id=encode(sha256(convert_to('proxy-inspection:'||j.tenant_id||':'||j.request_id,'UTF8')),'hex')) LIMIT 100`, q.environment)
	if err != nil {
		return err
	}
	type done struct{ tenant, request, host, status, admission, project, sourceIP, agent string }
	var jobs []done
	for rows.Next() {
		var d done
		if err = rows.Scan(&d.tenant, &d.request, &d.host, &d.status, &d.admission, &d.project, &d.sourceIP, &d.agent); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, d)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, j := range jobs {
		_, findings, _, e := q.snapshot(ctx, j.tenant, j.request)
		if e != nil {
			j.status = "failed"
			findings = nil
			if _, err := q.db.Exec(ctx, `UPDATE proxy_inspection_jobs SET status='failed',last_error='inspection_result_unreadable' WHERE tenant_id=$1 AND request_id=$2`, j.tenant, j.request); err != nil {
				return err
			}
		}
		summary := map[string]interface{}{"target_host": j.host, "source_ip": j.sourceIP, "agent_type": j.agent, "stage": "input", "inspection_status": j.status, "inspection_completed": j.status == "completed", "enforcement_boundary": "post_send_audit", "findings_count": len(findings), "counts_as_security_finding": len(findings) > 0}
		putSecurityEventFindings(summary, findings)
		action := "audit"
		kind := "security_inspection_completed"
		severity := "low"
		if j.admission == "blocked" || j.admission == "blocked_complete" {
			summary["enforcement_boundary"] = "pre_send_blocked"
		}
		if j.admission == "forwarded_complete" || j.admission == "blocked_complete" {
			findings = nil
			summary["findings"] = []interface{}{}
			summary["findings_count"] = 0
			summary["counts_as_security_finding"] = false
		}
		if len(findings) > 0 {
			kind = "proxy_input_audit"
			severity = severityForActionAndFindings("audit", findings)
		} else if j.status == "failed" {
			kind = "security_check_failed"
			summary["semantic_status"] = "incomplete"
			summary["semantic_reason"] = "inspection_retry_exhausted"
		}
		summary["effective_severity"] = severity
		b, _ := json.Marshal(summary)
		_, err = q.db.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,evidence_ref,created_at,principal_key) VALUES($1,$2,$3,$9,$4,$5,$6,$7,$8,now(),NULLIF($10,'')) ON CONFLICT(id) DO NOTHING`, inspectionEventID(j.tenant, j.request), j.request, j.tenant, kind, severity, action, b, "request_logs:"+j.request, j.project, j.sourceIP)
		if err != nil {
			return err
		}
	}
	// Payload is never retained after completion; terminal metadata has a bounded lifetime.
	_, err = q.db.Exec(ctx, `UPDATE proxy_inspection_parts p SET payload_encrypted='' FROM proxy_inspection_jobs j WHERE p.tenant_id=j.tenant_id AND p.request_id=j.request_id AND j.status IN ('completed','failed');
 DELETE FROM proxy_inspection_parts p USING proxy_inspection_jobs j WHERE p.tenant_id=j.tenant_id AND p.request_id=j.request_id AND j.status IN ('completed','failed') AND j.updated_at<now()-interval '1 hour' AND EXISTS(SELECT 1 FROM security_events e WHERE e.id=encode(sha256(convert_to('proxy-inspection:'||j.tenant_id||':'||j.request_id,'UTF8')),'hex'));
 DELETE FROM proxy_inspection_jobs WHERE updated_at<now()-interval '7 days' AND status IN ('completed','failed')`)
	return err
}

type inspectionPermitKey struct{}

func (q *InspectionQueue) admit(ctx context.Context) (func(), error) {
	select {
	case q.slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-q.slots }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func inspectionEventID(tenant, request string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte("proxy-inspection:"+tenant+":"+request)))
}
