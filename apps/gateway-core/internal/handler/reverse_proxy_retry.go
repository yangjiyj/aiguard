package handler

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
	"github.com/yangjiyj/aiguard/packages/shared-go/backoff"
	"github.com/yangjiyj/aiguard/packages/shared-go/errclass"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/ratelog"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"time"
)

type reverseRetryPayload struct {
	RequireSemantic bool
	Path            string
	Body            json.RawMessage
}
type reverseRetryJob struct {
	ID, Tenant, Request, Stage, Encrypted, Token string
	Attempts                                     int
}
type reverseInspectionQueue struct {
	db   *pgxpool.Pool
	h    *ReverseProxyHandler
	aead cipher.AEAD
}

func newReverseInspectionQueue(h *ReverseProxyHandler) (*reverseInspectionQueue, error) {
	if h.db == nil || len(h.internalSecret) < 16 {
		return nil, errors.New("retry storage/key unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var ready bool
	if err := h.db.QueryRow(ctx, "SELECT to_regclass('gateway_inspection_retries') IS NOT NULL").Scan(&ready); err != nil || !ready {
		return nil, errors.New("inspection retry migration 852 required")
	}
	key := sha256.Sum256([]byte("jjdguard:reverse-inspection:v1:" + h.internalSecret))
	block, _ := aes.NewCipher(key[:])
	aead, _ := cipher.NewGCM(block)
	return &reverseInspectionQueue{db: h.db, h: h, aead: aead}, nil
}
func (q *reverseInspectionQueue) seal(id string, data []byte) (string, error) {
	n := make([]byte, q.aead.NonceSize())
	if _, e := rand.Read(n); e != nil {
		return "", e
	}
	return base64.RawStdEncoding.EncodeToString(q.aead.Seal(n, n, data, []byte(id))), nil
}
func (q *reverseInspectionQueue) open(id, value string) ([]byte, error) {
	b, e := base64.RawStdEncoding.DecodeString(value)
	n := q.aead.NonceSize()
	if e != nil || len(b) < n {
		return nil, errors.New("invalid retry ciphertext")
	}
	return q.aead.Open(nil, b[:n], b[n:], []byte(id))
}
func (q *reverseInspectionQueue) enqueue(request, path string, payload []byte, requiresSemantic ...bool) (string, error) {
	if path != "/check-input/" && path != "/check-output/" {
		return "", errors.New("invalid inspection endpoint")
	}
	needSemantic := len(requiresSemantic) > 0 && requiresSemantic[0]
	body, _ := json.Marshal(reverseRetryPayload{Path: path, Body: payload, RequireSemantic: needSemantic})
	if len(body) > 16*1024*1024 {
		return "", errors.New("inspection retry payload limit")
	}
	digest := sha256.Sum256(append([]byte(q.h.tenantID+"\x00"+request+"\x00"), body...))
	id := hex.EncodeToString(digest[:])
	enc, err := q.seal(id, body)
	if err != nil {
		return "", err
	}
	stage := "input"
	if path == "/check-output/" {
		stage = "output"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := q.db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(85220260921)"); err != nil {
		return "", err
	}
	var prior string
	err = tx.QueryRow(ctx, "SELECT status FROM gateway_inspection_retries WHERE id=$1", id).Scan(&prior)
	if err == nil {
		if prior == "pending" || prior == "running" {
			return id, nil
		}
		return "", errors.New("prior retry is terminal; cannot reuse old completion")
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	var size, own, count int64
	if err = tx.QueryRow(ctx, "SELECT coalesce(sum(payload_bytes),0),coalesce(sum(payload_bytes) FILTER(WHERE tenant_id=$1),0),count(*) FILTER(WHERE status IN ('pending','running')) FROM gateway_inspection_retries", q.h.tenantID).Scan(&size, &own, &count); err != nil {
		return "", err
	}
	if size+int64(len(enc)) > 512*1024*1024 || own+int64(len(enc)) > 128*1024*1024 || count >= 2000 {
		return "", errors.New("inspection retry capacity")
	}
	_, err = tx.Exec(ctx, `INSERT INTO gateway_inspection_retries(id,tenant_id,request_id,stage,environment_scope,payload_encrypted,payload_bytes,next_attempt_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+interval '5 seconds')`, id, q.h.tenantID, request, stage, configuredDeploymentEnvironmentScope(), enc, len(enc))
	if err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}
func (q *reverseInspectionQueue) claim(ctx context.Context) (*reverseRetryJob, error) {
	j := &reverseRetryJob{Token: uuid.NewString()}
	err := q.db.QueryRow(ctx, `WITH candidate AS (SELECT id FROM gateway_inspection_retries WHERE tenant_id=$1 AND environment_scope=$2 AND expires_at>now() AND EXISTS(SELECT 1 FROM request_logs r WHERE r.tenant_id=gateway_inspection_retries.tenant_id AND r.request_id=gateway_inspection_retries.request_id) AND ((status='pending' AND next_attempt_at<=now()) OR (status='running' AND lease_until<now())) ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT 1)
 UPDATE gateway_inspection_retries j SET status='running',attempts=attempts+1,lease_token=$3,lease_until=now()+interval '150 seconds',updated_at=now() FROM candidate c WHERE j.id=c.id RETURNING j.id,j.tenant_id,j.request_id,j.stage,j.payload_encrypted,j.attempts`, q.h.tenantID, configuredDeploymentEnvironmentScope(), j.Token).Scan(&j.ID, &j.Tenant, &j.Request, &j.Stage, &j.Encrypted, &j.Attempts)
	return j, err
}
func reverseInspectionComplete(r reverseProxySecurityResponse, err error) bool {
	if err != nil {
		return false
	}
	switch r.Action {
	case "allow", "audit", "block", "mask", "redact", "reply", "deny", "quarantine":
	default:
		return false
	}
	for _, f := range r.Findings {
		if f.EvidenceKind == "runtime" || f.Type == "engine_runtime" || f.Type == "semantic_telemetry" || f.Type == "regex_timeout" {
			return false
		}
	}
	if r.InspectionStatus != "" && r.InspectionStatus != "completed" {
		return false
	}
	switch r.SemanticStatus {
	case "incomplete", "failed", "unavailable":
		return false
	}
	return true
}
func (h *ReverseProxyHandler) postReverseInspection(ctx context.Context, path string, payload []byte) (reverseProxySecurityResponse, error) {
	var result reverseProxySecurityResponse
	ctx, cancel := context.WithTimeout(ctx, security.TimeoutBudget(len(payload)))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.securityURL+path, bytes.NewReader(payload))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headeraudit.InternalTokenHeader, h.internalSecret)
	// 反向代理的检测结果同样走前后文打码，需要引擎返回秘密本体。
	req.Header.Set(security.WantSecretTextHeader, "1")
	client := h.client
	if client == nil {
		client = http.DefaultClient
	}
	copyClient := *client
	copyClient.Timeout = 0
	resp, err := copyClient.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return result, securityexit.HTTPInspectionError(resp.StatusCode, body)
	}
	limited := io.LimitReader(resp.Body, 16*1024*1024+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return result, err
	}
	if len(b) > 16*1024*1024 {
		return result, errors.New("inspection response limit")
	}
	if err = json.Unmarshal(b, &result); err != nil {
		return result, errors.New("invalid inspection response")
	}
	return result, nil
}
func reverseRetryComplete(p reverseRetryPayload, r reverseProxySecurityResponse, err error) bool {
	return reverseInspectionComplete(r, err) && r.EngineBuild != "" && (!p.RequireSemantic || r.SemanticStatus == "completed") && r.SemanticReason != "inspection_scope_excluded"
}

func (q *reverseInspectionQueue) runJob(ctx context.Context, j *reverseRetryJob) error {
	raw, err := q.open(j.ID, j.Encrypted)
	var p reverseRetryPayload
	if err == nil {
		err = json.Unmarshal(raw, &p)
	}
	payloadError := err
	var result reverseProxySecurityResponse
	if err == nil && (p.Path == "/check-input/" || p.Path == "/check-output/") {
		result, err = q.h.postReverseInspection(ctx, p.Path, p.Body)
	} else {
		err = errors.New("invalid retry payload")
	}
	complete := reverseRetryComplete(p, result, err)
	reason := result.SemanticReason
	if err != nil {
		reason = "security_engine_unavailable"
	}
	if payloadError != nil {
		reason = "retry_payload_unreadable"
	}
	if reason == "" && !complete {
		reason = "inspection_incomplete"
	}
	// An open judge breaker is a known-downstream condition: burning the
	// attempt budget against a breaker that is guaranteed to fail only
	// destroys durable retries (the 2026-10-07..10-19 outage lost 5960
	// tasks this way). Park the job on a fixed long backoff without
	// consuming the attempt budget; expires_at still caps the queue.
	breakerOpen := !complete && payloadError == nil && reason == "breaker_open"
	status := "pending"
	if complete {
		status = "completed"
	} else if payloadError != nil || (j.Attempts >= 8 && !breakerOpen) {
		status = "failed"
	}
	backoff := 5 * (1 << min(j.Attempts, 6))
	if backoff > 300 {
		backoff = 300
	}
	if breakerOpen {
		backoff = 300
	}
	tx, e := q.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var valid bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM gateway_inspection_retries WHERE id=$1 AND tenant_id=$2 AND status='running' AND lease_token=$3)", j.ID, j.Tenant, j.Token).Scan(&valid); e != nil {
		return e
	}
	if !valid {
		return errors.New("stale retry lease")
	}
	// Findings and completion are one transaction. A crash cannot publish success
	// without its findings, and a stale lease cannot overwrite a later attempt.
	findings := convertSecurityFindings(result.Findings)
	var payload map[string]json.RawMessage
	_ = json.Unmarshal(p.Body, &payload)
	var source string
	_ = json.Unmarshal(payload["content_source"], &source)
	var extras map[string]interface{}
	_ = json.Unmarshal(payload["context"], &extras)
	if offset, ok := extras["output_window_start"].(float64); ok {
		for i := range findings {
			findings[i] = offsetStreamFinding(findings[i], int(offset))
		}
	}
	if len(findings) > 0 || complete {
		record := reverseProxyAuditRecord{RequestID: j.Request, TenantID: j.Tenant, OutputAlreadySent: j.Stage == "output"}
		attemptStatus := "incomplete"
		if complete {
			attemptStatus = "completed"
		}
		record.InputSemanticStatus, record.OutputSemanticStatus = attemptStatus, attemptStatus
		record.InputSemanticReason, record.OutputSemanticReason = reason, reason
		record.InputRetryIDs, record.OutputRetryIDs = []string{j.ID}, []string{j.ID}
		if host, ok := extras["target_host"].(string); ok {
			record.TargetHost = host
		}
		row := buildReverseProxySecurityEventRowWithContext(record, j.Stage, "audit", verifiedReverseProxyContentSource(source, extras), findings)
		if !hasSecurityFindings(findings) && complete {
			row.EventType = "security_inspection_completed"
			row.MatchedSummary["counts_as_security_finding"] = false
			row.MatchedSummary["inspection_status"] = "completed"
		}
		row.MatchedSummary["retry_task_id"] = j.ID
		row.MatchedSummary["retry_attempt"] = j.Attempts
		row.MatchedSummary["engine_build"] = result.EngineBuild
		row.MatchedSummary["semantic_config_revision"] = result.SemanticRevision
		data, _ := json.Marshal(row.MatchedSummary)
		_, e = tx.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,rule_id,action_taken,matched_summary,evidence_ref,created_at) VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,''),'audit',$8,$9,now()) ON CONFLICT(id) DO NOTHING`, fmt.Sprintf("retry_%s_%d", j.ID[:40], j.Attempts), j.Request, j.Tenant, defaultReverseProxyProjectID, row.EventType, row.Severity, row.RuleID, data, row.EvidenceRef)
		if e != nil {
			return e
		}
	}
	tag, e := tx.Exec(ctx, `UPDATE gateway_inspection_retries SET status=$4,last_reason=$5,engine_build=$6,semantic_revision=$7,next_attempt_at=now()+$8*interval '1 second',lease_token=NULL,lease_until=NULL,updated_at=now(),payload_encrypted=CASE WHEN $4 IN ('completed','failed') THEN '' ELSE payload_encrypted END,payload_bytes=CASE WHEN $4 IN ('completed','failed') THEN 0 ELSE payload_bytes END WHERE id=$1 AND tenant_id=$2 AND lease_token=$3 AND status='running' AND expires_at>now()`, j.ID, j.Tenant, j.Token, status, reason, result.EngineBuild, result.SemanticRevision, backoff)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("retry lease lost")
	}
	return tx.Commit(ctx)
}
func (q *reverseInspectionQueue) reconcile(ctx context.Context) error {
	_, err := q.db.Exec(ctx, `UPDATE gateway_inspection_retries SET status=CASE WHEN status IN ('pending','running') THEN 'expired' ELSE status END,payload_encrypted='',payload_bytes=0,updated_at=now() WHERE expires_at<now() AND payload_bytes>0`)
	if err != nil {
		return err
	}
	if _, err = q.db.Exec(ctx, "DELETE FROM gateway_inspection_retries WHERE created_at<now()-interval '30 days' AND status IN ('completed','failed','expired') AND payload_bytes=0"); err != nil {
		return err
	}
	_, err = q.db.Exec(ctx, `WITH progress AS (
 SELECT e.id,e.tenant_id,count(j.id) AS done_count,jsonb_array_length(CASE WHEN jsonb_typeof(e.matched_summary->'retry_task_ids')='array' THEN e.matched_summary->'retry_task_ids' ELSE '[]'::jsonb END) AS expected,
 bool_and(j.status='completed') AS completed,bool_or(j.status IN ('failed','expired')) AS exhausted
 FROM security_events e JOIN (SELECT DISTINCT tenant_id,request_id,stage FROM gateway_inspection_retries WHERE tenant_id=$1 AND updated_at>now()-interval '24 hours') scope ON scope.tenant_id=e.tenant_id AND scope.request_id=e.request_id AND scope.stage=e.matched_summary->>'stage' CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(e.matched_summary->'retry_task_ids')='array' THEN e.matched_summary->'retry_task_ids' ELSE '[]'::jsonb END) keys(id)
 LEFT JOIN gateway_inspection_retries j ON j.id=keys.id AND j.tenant_id=e.tenant_id AND j.request_id=e.request_id AND j.stage=e.matched_summary->>'stage'
 WHERE e.tenant_id=$1 AND e.created_at>now()-interval '30 days' AND e.matched_summary->>'source'='gateway_reverse_proxy' AND e.matched_summary->>'retry_unavailable'='false'
 GROUP BY e.id,e.tenant_id), updates AS (
 SELECT id,tenant_id,CASE WHEN done_count=expected AND completed THEN 'rechecked_complete' WHEN exhausted THEN 'retry_exhausted' ELSE 'retry_pending' END AS status FROM progress WHERE expected>0)
 UPDATE security_events e SET matched_summary=e.matched_summary||jsonb_build_object('remediation',jsonb_build_object('version','durable-retry-v1','status',u.status,'checked_at',now(),'coverage','original_payload','original_gap_resolved',u.status='rechecked_complete')) FROM updates u WHERE e.id=u.id AND e.tenant_id=u.tenant_id AND coalesce(e.matched_summary#>>'{remediation,status}','')<>u.status`, q.h.tenantID)
	return err
}

const (
	// 检查重试 worker 的节奏：健康时保持原来的 2 秒；连续失败（典型是库连接被打满）时指数退避，
	// 封顶 60 秒并带抖动，避免两个 worker 与 reconcile 在 too many clients 期间继续高频争抢连接。
	inspectionRetryBaseInterval         = 2 * time.Second
	inspectionRetryMaxInterval          = 60 * time.Second
	inspectionRetryReconcileInterval    = 60 * time.Second
	inspectionRetryReconcileMaxInterval = 5 * time.Minute
)

// inspectionRetryFailureLog 限频：首条必打，之后每 20 条一条（累计次数在 total=）。
var inspectionRetryFailureLog = ratelog.New(20)

// inspectionRetryPacer 决定一次尝试之后的等待时间：成功或没有待办任务（ErrNoRows）回到基础节奏，
// 其余错误视为失败并指数退避。每个 worker 自带一个，互不影响。
type inspectionRetryPacer struct{ b *backoff.Backoff }

func newInspectionRetryPacer() *inspectionRetryPacer {
	return newInspectionRetryPacerWith(inspectionRetryBaseInterval, inspectionRetryMaxInterval)
}

func newInspectionRetryPacerWith(base, max time.Duration) *inspectionRetryPacer {
	return &inspectionRetryPacer{b: backoff.New(base, max)}
}

func (p *inspectionRetryPacer) after(err error) time.Duration {
	if err == nil || errors.Is(err, pgx.ErrNoRows) {
		p.b.Reset()
		return p.b.Base()
	}
	return p.b.Next()
}

// logInspectionRetryFailure 只记录错误类别，不记录底层错误文本（pgx 连接错误会带用户名与库名）。
func logInspectionRetryFailure(component string, err error) {
	inspectionRetryFailureLog.Printf(component+"|"+errclass.Classify(err), "%s: %s", component, errclass.Summary(err))
}

// runInspectionRetryLoop 反复执行 attempt，按 pacer 决定间隔；ctx 取消立即返回。
// ErrNoRows（没有待办任务）不算失败；其它错误交给 onFailure 记录。
func runInspectionRetryLoop(ctx context.Context, pacer *inspectionRetryPacer, attempt func(context.Context) error, onFailure func(error)) {
	timer := time.NewTimer(pacer.b.Base())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		err := attempt(ctx)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) && ctx.Err() == nil {
			onFailure(err)
		}
		timer.Reset(pacer.after(err))
	}
}

func (q *reverseInspectionQueue) start() {
	for worker := 0; worker < 2; worker++ {
		go runInspectionRetryLoop(context.Background(), newInspectionRetryPacer(), func(parent context.Context) error {
			ctx, cancel := context.WithTimeout(parent, 120*time.Second)
			defer cancel()
			j, err := q.claim(ctx)
			if err == nil {
				err = q.runJob(ctx, j)
			}
			return err
		}, func(err error) { logInspectionRetryFailure("Inspection retry worker", err) })
	}
	// reconcile 聚合 30 天的 security_events：表数据多时 10 秒预算每次都超时刷屏，
	// 所以给 55 秒预算、60 秒节奏，空闲超时不当失败上报；库连接失败时再按退避拉长到 5 分钟。
	go runInspectionRetryLoop(context.Background(),
		newInspectionRetryPacerWith(inspectionRetryReconcileInterval, inspectionRetryReconcileMaxInterval),
		func(parent context.Context) error {
			ctx, cancel := context.WithTimeout(parent, 55*time.Second)
			defer cancel()
			return q.reconcile(ctx)
		}, func(err error) {
			if errors.Is(err, context.DeadlineExceeded) {
				return
			}
			logInspectionRetryFailure("Inspection retry progress", err)
		})
}
