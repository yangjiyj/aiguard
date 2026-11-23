package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/modelops"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type modelOperationsJobRequest struct {
	ModelIDs              []string          `json:"model_ids"`
	Protocols             []string          `json:"protocols,omitempty"`
	ConfirmCost           bool              `json:"confirm_cost"`
	ExpectedConfigVersion int64             `json:"expected_config_version"`
	IdempotencyKey        string            `json:"idempotency_key"`
	FrozenIdentities      map[string]string `json:"frozen_identities,omitempty"`
	FrozenConfig          modelops.Config   `json:"frozen_config"`
	TargetCount           int               `json:"target_count"`
	PlannedTargets        []modelops.Target `json:"planned_targets,omitempty"`
}

type modelOperationsJobWireRequest struct {
	ModelIDs              []string `json:"model_ids"`
	Protocols             []string `json:"protocols,omitempty"`
	ConfirmCost           bool     `json:"confirm_cost"`
	ExpectedConfigVersion int64    `json:"expected_config_version"`
	IdempotencyKey        string   `json:"idempotency_key"`
}

type ModelOperationsJob struct {
	ID                   string                   `json:"job_id"`
	State                string                   `json:"state"`
	Total                int                      `json:"total"`
	Completed            int                      `json:"completed"`
	Items                []modelops.ProbeRecord   `json:"items"`
	Skipped              []modelops.SkippedTarget `json:"skipped"`
	ErrorCode            string                   `json:"error_code"`
	CreatedAt            time.Time                `json:"created_at"`
	UpdatedAt            time.Time                `json:"updated_at"`
	CompletedAt          *time.Time               `json:"completed_at"`
	tenant, actor, token string
	request              modelOperationsJobRequest
}

type modelOperationsActiveJobError struct{ ID string }

func (e modelOperationsActiveJobError) Error() string {
	return "another model verification job is active"
}

var errModelOperationsJobReplay = errors.New("model verification idempotency payload conflict")

type ModelOperationsJobStore interface {
	Replay(context.Context, string, string, modelOperationsJobRequest) (ModelOperationsJob, bool, error)
	Create(context.Context, string, string, modelOperationsJobRequest) (ModelOperationsJob, bool, error)
	Get(context.Context, string, string) (ModelOperationsJob, error)
	Cancel(context.Context, string, string) (ModelOperationsJob, error)
	Start(context.Context, ModelOperationsJob) error
	Heartbeat(context.Context, ModelOperationsJob) error
	Finish(context.Context, ModelOperationsJob, string, string, modelops.TestResult) error
}

type PostgresModelOperationsJobStore struct{ pool *pgxpool.Pool }

func NewPostgresModelOperationsJobStore(pool *pgxpool.Pool) *PostgresModelOperationsJobStore {
	return &PostgresModelOperationsJobStore{pool: pool}
}

func modelOperationsRequestDigest(req modelOperationsJobRequest) string {
	req.FrozenIdentities = nil
	req.FrozenConfig = modelops.Config{}
	req.TargetCount = 0
	req.PlannedTargets = nil
	data, _ := json.Marshal(req)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s *PostgresModelOperationsJobStore) Replay(ctx context.Context, tenant, actor string, req modelOperationsJobRequest) (ModelOperationsJob, bool, error) {
	var digest string
	err := s.pool.QueryRow(ctx, `SELECT request_sha256 FROM model_operations_jobs WHERE tenant_id=$1 AND actor=$2 AND request_key=$3`, tenant, actor, req.IdempotencyKey).Scan(&digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return ModelOperationsJob{}, false, nil
	}
	if err != nil {
		return ModelOperationsJob{}, false, err
	}
	if digest != modelOperationsRequestDigest(req) {
		return ModelOperationsJob{}, false, errModelOperationsJobReplay
	}
	j, err := scanModelOperationsJob(s.pool.QueryRow(ctx, `SELECT `+modelOperationsJobColumns+` FROM model_operations_jobs WHERE tenant_id=$1 AND actor=$2 AND request_key=$3`, tenant, actor, req.IdempotencyKey))
	return j, true, err
}

const modelOperationsJobColumns = `id,tenant_id,actor,owner_token,request_json,state,result_json,error_code,created_at,updated_at,completed_at`

func scanModelOperationsJob(row pgx.Row) (ModelOperationsJob, error) {
	var j ModelOperationsJob
	var req, result []byte
	if err := row.Scan(&j.ID, &j.tenant, &j.actor, &j.token, &req, &j.State, &result, &j.ErrorCode, &j.CreatedAt, &j.UpdatedAt, &j.CompletedAt); err != nil {
		return j, err
	}
	if err := json.Unmarshal(req, &j.request); err != nil {
		return j, err
	}
	var value modelops.TestResult
	if len(result) > 0 {
		if err := json.Unmarshal(result, &value); err != nil {
			return j, err
		}
	}
	j.Items = value.Items
	j.Skipped = value.Skipped
	if j.Items == nil {
		j.Items = []modelops.ProbeRecord{}
	}
	if j.Skipped == nil {
		j.Skipped = []modelops.SkippedTarget{}
	}
	j.Completed = len(j.Items)
	j.Total = len(j.request.ModelIDs)
	if len(j.request.Protocols) > 0 {
		j.Total *= len(j.request.Protocols)
	}
	if j.request.TargetCount > 0 {
		j.Total = j.request.TargetCount
	}
	return j, nil
}

func (s *PostgresModelOperationsJobStore) Create(ctx context.Context, tenant, actor string, req modelOperationsJobRequest) (ModelOperationsJob, bool, error) {
	var zero ModelOperationsJob
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return zero, false, err
	}
	defer tx.Rollback(ctx)
	payload, err := json.Marshal(req)
	if err != nil {
		return zero, false, err
	}
	digest := modelOperationsRequestDigest(req)
	// Configuration is the shared serialization row for scheduled leases and
	// manual submissions. Existing idempotent requests are answered first.
	if _, err = tx.Exec(ctx, `INSERT INTO model_ops_configs(tenant_id) VALUES($1) ON CONFLICT DO NOTHING`, tenant); err != nil {
		return zero, false, err
	}
	var version int64
	if err = tx.QueryRow(ctx, `SELECT version FROM model_ops_configs WHERE tenant_id=$1 FOR UPDATE`, tenant).Scan(&version); err != nil {
		return zero, false, err
	}
	var oldDigest string
	if err = tx.QueryRow(ctx, `SELECT request_sha256 FROM model_operations_jobs WHERE tenant_id=$1 AND actor=$2 AND request_key=$3`, tenant, actor, req.IdempotencyKey).Scan(&oldDigest); err == nil {
		if oldDigest != digest {
			return zero, false, errModelOperationsJobReplay
		}
		j, e := scanModelOperationsJob(tx.QueryRow(ctx, `SELECT `+modelOperationsJobColumns+` FROM model_operations_jobs WHERE tenant_id=$1 AND actor=$2 AND request_key=$3`, tenant, actor, req.IdempotencyKey))
		return j, false, e
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return zero, false, err
	}
	if version != req.ExpectedConfigVersion {
		return zero, false, modelops.ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE model_operations_jobs SET state='interrupted',error_code='worker_interrupted',completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND state IN ('queued','running') AND lease_until<clock_timestamp()`, tenant); err != nil {
		return zero, false, err
	}
	var active string
	if err = tx.QueryRow(ctx, `SELECT id FROM model_operations_jobs WHERE tenant_id=$1 AND state IN ('queued','running')`, tenant).Scan(&active); err == nil {
		return zero, false, modelOperationsActiveJobError{ID: active}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return zero, false, err
	}
	var scheduled bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM model_ops_leases WHERE tenant_id=$1 AND expires_at>clock_timestamp() AND token<>'')`, tenant).Scan(&scheduled); err != nil {
		return zero, false, err
	}
	if scheduled {
		return zero, false, modelops.ErrLeaseLost
	}
	// Only the submitting process owns a newly created task. Expired tasks are
	// marked interrupted and never replayed, because network I/O may have billed.
	j, err := scanModelOperationsJob(tx.QueryRow(ctx, `INSERT INTO model_operations_jobs(id,tenant_id,actor,request_key,request_sha256,request_json,state,result_json,error_code,cancel_requested,owner_token,lease_until,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,'queued','{"items":[]}'::jsonb,'',false,$7,clock_timestamp()+interval '20 seconds',clock_timestamp(),clock_timestamp()) RETURNING `+modelOperationsJobColumns, "mojob_"+uuid.NewString(), tenant, actor, req.IdempotencyKey, digest, string(payload), uuid.NewString()))
	if err != nil {
		return zero, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return zero, false, err
	}
	return j, true, nil
}

func (s *PostgresModelOperationsJobStore) Get(ctx context.Context, tenant, id string) (ModelOperationsJob, error) {
	if _, err := s.pool.Exec(ctx, `UPDATE model_operations_jobs SET state='interrupted',error_code='worker_interrupted',completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state IN ('queued','running') AND lease_until<clock_timestamp()`, tenant, id); err != nil {
		return ModelOperationsJob{}, err
	}
	j, err := scanModelOperationsJob(s.pool.QueryRow(ctx, `SELECT `+modelOperationsJobColumns+` FROM model_operations_jobs WHERE tenant_id=$1 AND id=$2`, tenant, id))
	if errors.Is(err, pgx.ErrNoRows) {
		err = modelops.ErrUnavailable
	}
	return j, err
}

func (s *PostgresModelOperationsJobStore) Cancel(ctx context.Context, tenant, id string) (ModelOperationsJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ModelOperationsJob{}, err
	}
	defer tx.Rollback(ctx)
	j, err := scanModelOperationsJob(tx.QueryRow(ctx, `SELECT `+modelOperationsJobColumns+` FROM model_operations_jobs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return j, modelops.ErrUnavailable
	}
	if err != nil {
		return j, err
	}
	if j.State != "queued" && j.State != "running" {
		return j, nil
	}
	data := []byte(`{}`)
	if j.State == "queued" {
		data, err = json.Marshal(modelOperationsUnsentResult(j.request.PlannedTargets, "cancelled"))
		if err != nil {
			return j, err
		}
	}
	j, err = scanModelOperationsJob(tx.QueryRow(ctx, `UPDATE model_operations_jobs SET cancel_requested=true,state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END,result_json=CASE WHEN state='queued' THEN $3::jsonb ELSE result_json END,completed_at=CASE WHEN state='queued' THEN clock_timestamp() ELSE completed_at END,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 RETURNING `+modelOperationsJobColumns, tenant, id, string(data)))
	if err != nil {
		return j, err
	}
	if err = tx.Commit(ctx); err != nil {
		return j, err
	}
	return j, nil
}

func (s *PostgresModelOperationsJobStore) Reap(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE model_operations_jobs SET state='interrupted',error_code='worker_interrupted',completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE state IN ('queued','running') AND lease_until<clock_timestamp()`)
	return err
}

func (s *PostgresModelOperationsJobStore) Start(ctx context.Context, j ModelOperationsJob) error {
	result, err := s.pool.Exec(ctx, `UPDATE model_operations_jobs j SET state='running',updated_at=clock_timestamp(),lease_until=clock_timestamp()+interval '20 seconds' FROM model_ops_configs c WHERE j.id=$1 AND j.tenant_id=$2 AND j.owner_token=$3 AND j.state='queued' AND NOT j.cancel_requested AND j.lease_until>clock_timestamp() AND c.tenant_id=j.tenant_id AND c.version=$4`, j.ID, j.tenant, j.token, j.request.ExpectedConfigVersion)
	if err == nil && result.RowsAffected() != 1 {
		err = modelops.ErrLeaseLost
	}
	return err
}
func (s *PostgresModelOperationsJobStore) Heartbeat(ctx context.Context, j ModelOperationsJob) error {
	result, err := s.pool.Exec(ctx, `UPDATE model_operations_jobs j SET updated_at=clock_timestamp(),lease_until=clock_timestamp()+interval '20 seconds' FROM model_ops_configs c WHERE j.id=$1 AND j.tenant_id=$2 AND j.owner_token=$3 AND j.state='running' AND NOT j.cancel_requested AND j.lease_until>clock_timestamp() AND c.tenant_id=j.tenant_id AND c.version=$4`, j.ID, j.tenant, j.token, j.request.ExpectedConfigVersion)
	if err == nil && result.RowsAffected() != 1 {
		err = modelops.ErrLeaseLost
	}
	return err
}
func (s *PostgresModelOperationsJobStore) Finish(ctx context.Context, j ModelOperationsJob, state, code string, value modelops.TestResult) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	result, err := s.pool.Exec(ctx, `UPDATE model_operations_jobs SET state=CASE WHEN cancel_requested THEN 'cancelled' ELSE $4 END,result_json=$5::jsonb,error_code=CASE WHEN cancel_requested THEN 'cancelled' ELSE $6 END,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND tenant_id=$2 AND owner_token=$3 AND state IN ('queued','running') AND lease_until>clock_timestamp()`, j.ID, j.tenant, j.token, state, string(data), code)
	if err == nil && result.RowsAffected() != 1 {
		err = modelops.ErrLeaseLost
	}
	return err
}

type ModelOperationsJobsHandler struct {
	base      *ModelOperationsHandler
	store     ModelOperationsJobStore
	lifecycle context.Context
	mu        sync.Mutex
	cancels   map[string]context.CancelFunc
	wg        sync.WaitGroup
}

func NewModelOperationsJobsHandler(deps *Dependencies, service ModelOperationsService, store ModelOperationsJobStore, lifecycle context.Context) *ModelOperationsJobsHandler {
	h := &ModelOperationsJobsHandler{base: NewModelOperationsHandler(deps, service), store: store, lifecycle: lifecycle, cancels: map[string]context.CancelFunc{}}
	if reaper, ok := store.(interface{ Reap(context.Context) error }); ok {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				checkCtx, cancel := context.WithTimeout(lifecycle, 3*time.Second)
				_ = reaper.Reap(checkCtx)
				cancel()
				select {
				case <-lifecycle.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	return h
}

func (h *ModelOperationsJobsHandler) Submit(w http.ResponseWriter, r *http.Request) {
	user, ok := h.base.authorize(w, r, "write")
	if !ok || !modelOperationsQuery(w, r) {
		return
	}
	var wire modelOperationsJobWireRequest
	if !decodeModelOperationsBody(w, r, &wire) {
		return
	}
	req := modelOperationsJobRequest{ModelIDs: wire.ModelIDs, Protocols: wire.Protocols, ConfirmCost: wire.ConfirmCost, ExpectedConfigVersion: wire.ExpectedConfigVersion, IdempotencyKey: wire.IdempotencyKey}
	if !req.ConfirmCost {
		modelOperationsResponse(w, nil, modelops.ErrCostConfirmation)
		return
	}
	if req.ExpectedConfigVersion < 1 || len(req.IdempotencyKey) < 8 || !modelOperationsID(req.IdempotencyKey) || len(req.ModelIDs) < 1 || len(req.ModelIDs) > 50 || (len(req.Protocols) > 0 && modelops.ValidateProtocols(req.Protocols) != nil) {
		writeErrorWithStatus(w, 400, "invalid_request", "invalid model verification request")
		return
	}
	seen := map[string]bool{}
	for _, id := range req.ModelIDs {
		if !modelOperationsID(id) || seen[id] {
			writeErrorWithStatus(w, 400, "invalid_request", "invalid or duplicate model ID")
			return
		}
		seen[id] = true
	}
	if h.store == nil {
		modelOperationsResponse(w, nil, errors.New("job store unavailable"))
		return
	}
	if job, exists, err := h.store.Replay(r.Context(), user.TenantID, user.ID, req); err != nil {
		if errors.Is(err, errModelOperationsJobReplay) {
			writeErrorWithStatus(w, 409, "idempotency_conflict", "idempotency key is bound to a different request")
		} else {
			modelOperationsResponse(w, nil, err)
		}
		return
	} else if exists {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(job)
		return
	}
	config, err := h.base.service.Config(r.Context(), user.TenantID)
	if err != nil {
		modelOperationsResponse(w, nil, err)
		return
	}
	if config.Version != req.ExpectedConfigVersion {
		writeErrorWithStatus(w, 409, "config_conflict", "probe configuration changed; confirm current cost before retrying")
		return
	}
	req.FrozenConfig = config
	// Reject all missing or foreign targets before creating any billable work.
	targets, err := h.base.service.Targets(r.Context(), user.TenantID)
	if err != nil {
		modelOperationsResponse(w, nil, err)
		return
	}
	owned := map[string]modelops.Target{}
	req.FrozenIdentities = map[string]string{}
	for _, target := range targets {
		owned[target.ModelID] = target
		if seen[target.ModelID] {
			req.FrozenIdentities[target.ModelID] = target.IdentityDigest
		}
	}
	for _, id := range req.ModelIDs {
		target, found := owned[id]
		if !found {
			modelOperationsResponse(w, nil, modelops.ErrUnavailable)
			return
		}
		protocols := []string{target.Protocol}
		if len(req.Protocols) > 0 {
			protocols = req.Protocols
			if strings.EqualFold(strings.TrimSpace(target.ProviderType), "anthropic") {
				foundMessages := false
				for _, protocol := range req.Protocols {
					if protocol == "messages" {
						foundMessages = true
					}
				}
				if !foundMessages {
					writeErrorWithStatus(w, 400, "invalid_request", "native Anthropic models require messages protocol")
					return
				}
				protocols = []string{"messages"}
			}
		}
		for _, protocol := range protocols {
			planned := target
			planned.Protocol = protocol
			req.PlannedTargets = append(req.PlannedTargets, planned)
		}
	}
	req.TargetCount = len(req.PlannedTargets)
	if req.TargetCount > 50 {
		writeErrorWithStatus(w, 400, "invalid_request", "select at most 50 model protocol targets")
		return
	}
	job, created, err := h.store.Create(r.Context(), user.TenantID, user.ID, req)
	if err != nil {
		var active modelOperationsActiveJobError
		switch {
		case errors.As(err, &active):
			writeErrorWithStatusAndDetails(w, 409, "verification_job_active", "another model verification job is active", map[string]string{"job_id": active.ID})
		case errors.Is(err, modelops.ErrConflict):
			writeErrorWithStatus(w, 409, "config_conflict", "probe configuration changed; confirm current cost before retrying")
		case errors.Is(err, errModelOperationsJobReplay):
			writeErrorWithStatus(w, 409, "idempotency_conflict", "idempotency key is bound to a different request")
		default:
			modelOperationsResponse(w, nil, err)
		}
		return
	}
	if created {
		h.launch(job)
	}
	logAudit(r, h.base.deps, "submit_model_operations_job", map[string]interface{}{"job_id": job.ID, "total": job.Total, "config_version": req.ExpectedConfigVersion, "created": created}, "model_operations_job", job.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(job)
}

func (h *ModelOperationsJobsHandler) Get(w http.ResponseWriter, r *http.Request) {
	user, ok := h.base.authorize(w, r, "read")
	if !ok || !modelOperationsQuery(w, r) {
		return
	}
	if h.store == nil {
		modelOperationsResponse(w, nil, errors.New("job store unavailable"))
		return
	}
	id := chi.URLParam(r, "id")
	if !modelOperationsID(id) {
		writeErrorWithStatus(w, 400, "invalid_request", "invalid job ID")
		return
	}
	job, err := h.store.Get(r.Context(), user.TenantID, id)
	if err == nil {
		job, err = h.progress(r.Context(), user.TenantID, job)
	}
	modelOperationsResponse(w, job, err)
}
func (h *ModelOperationsJobsHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	user, ok := h.base.authorize(w, r, "write")
	if !ok || !modelOperationsQuery(w, r) {
		return
	}
	if h.store == nil {
		modelOperationsResponse(w, nil, errors.New("job store unavailable"))
		return
	}
	id := chi.URLParam(r, "id")
	if !modelOperationsID(id) {
		writeErrorWithStatus(w, 400, "invalid_request", "invalid job ID")
		return
	}
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if len(body) > 0 || err != nil {
			writeErrorWithStatus(w, 400, "invalid_request", "cancel body must be empty")
			return
		}
	}
	job, err := h.store.Cancel(r.Context(), user.TenantID, id)
	if err == nil {
		h.mu.Lock()
		cancel := h.cancels[id]
		h.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		logAudit(r, h.base.deps, "cancel_model_operations_job", map[string]interface{}{"job_id": id}, "model_operations_job", id)
		job, err = h.progress(r.Context(), user.TenantID, job)
	}
	modelOperationsResponse(w, job, err)
}

func (h *ModelOperationsJobsHandler) progress(ctx context.Context, tenant string, j ModelOperationsJob) (ModelOperationsJob, error) {
	page, err := h.base.service.History(ctx, tenant, modelops.HistoryFilter{InvocationID: j.ID, Source: "manual", Limit: 100, WindowHours: 168})
	if err != nil {
		return j, err
	}
	if len(page.Items) > 0 || len(j.Items) == 0 {
		j.Items = page.Items
	}
	if j.Items == nil {
		j.Items = []modelops.ProbeRecord{}
	}
	if j.State == "interrupted" {
		covered := map[string]bool{}
		for _, item := range j.Items {
			covered[item.Key()] = true
		}
		for _, item := range j.Skipped {
			covered[item.Key()] = true
		}
		for _, target := range j.request.PlannedTargets {
			if !covered[target.Key()] {
				j.Skipped = append(j.Skipped, modelops.SkippedTarget{Target: target, Reason: "unknown_after_interruption"})
			}
		}
	}
	j.Completed = len(j.Items)
	return j, nil
}

func (h *ModelOperationsJobsHandler) launch(j ModelOperationsJob) {
	ctx, cancel := context.WithTimeout(h.lifecycle, 30*time.Minute)
	h.mu.Lock()
	h.cancels[j.ID] = cancel
	h.mu.Unlock()
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		defer cancel()
		defer func() { h.mu.Lock(); delete(h.cancels, j.ID); h.mu.Unlock() }()
		if err := h.store.Start(ctx, j); err != nil {
			code := "worker_interrupted"
			checkCtx, done := context.WithTimeout(context.Background(), 3*time.Second)
			current, checkErr := h.base.service.Config(checkCtx, j.tenant)
			done()
			if checkErr == nil && current.Version != j.request.ExpectedConfigVersion {
				code = "configuration_changed"
			}
			h.finish(j, "interrupted", code, modelOperationsUnsentResult(j.request.PlannedTargets, code))
			return
		}
		stopHeartbeat := make(chan struct{})
		heartbeatDone := make(chan struct{})
		go func() {
			defer close(heartbeatDone)
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopHeartbeat:
					return
				case <-ticker.C:
					checkCtx, done := context.WithTimeout(ctx, 3*time.Second)
					err := h.store.Heartbeat(checkCtx, j)
					done()
					if err != nil {
						cancel()
						return
					}
				}
			}
		}()
		req := modelops.TestRequest{ModelIDs: j.request.ModelIDs, Protocols: j.request.Protocols, ConfirmCost: true, ExpectedConfigVersion: j.request.ExpectedConfigVersion}
		probeCtx := modelops.WithTargetIdentities(modelops.WithJobOwner(ctx, j.ID, j.token), j.request.FrozenIdentities)
		value, err := h.base.service.Test(probeCtx, j.tenant, j.actor, req)
		close(stopHeartbeat)
		<-heartbeatDone
		state, code := "completed", ""
		if err != nil || ctx.Err() != nil {
			state, code = "failed", "verification_failed"
			if errors.Is(err, modelops.ErrConflict) || errors.Is(err, modelops.ErrIdentityChanged) {
				state, code = "interrupted", "configuration_changed"
			} else if ctx.Err() != nil {
				state, code = "interrupted", "worker_interrupted"
				checkCtx, done := context.WithTimeout(context.Background(), 3*time.Second)
				current, checkErr := h.base.service.Config(checkCtx, j.tenant)
				done()
				if checkErr == nil && current.Version != j.request.ExpectedConfigVersion {
					code = "configuration_changed"
				}
			}
		}
		if len(value.Items) == 0 && len(value.Skipped) == 0 && (code == "configuration_changed" || ctx.Err() != nil) {
			reason := code
			if reason == "worker_interrupted" {
				reason = "cancelled"
			}
			value = modelOperationsUnsentResult(j.request.PlannedTargets, reason)
		}
		h.finish(j, state, code, value)
	}()
}

func (h *ModelOperationsJobsHandler) finish(j ModelOperationsJob, state, code string, value modelops.TestResult) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.store.Finish(ctx, j, state, code, value); err != nil {
		log.Printf("model verification job %s terminal persistence failed; expiry will mark interruption: %v", j.ID, err)
	}
}

func modelOperationsUnsentResult(targets []modelops.Target, reason string) modelops.TestResult {
	value := modelops.TestResult{Items: []modelops.ProbeRecord{}, Skipped: []modelops.SkippedTarget{}}
	for _, target := range targets {
		value.Skipped = append(value.Skipped, modelops.SkippedTarget{Target: target, Reason: reason})
	}
	return value
}

func (h *ModelOperationsJobsHandler) Wait(ctx context.Context) {
	done := make(chan struct{})
	go func() { h.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
