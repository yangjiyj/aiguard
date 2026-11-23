package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
)

// serviceHealthEvidenceWindowHours bounds every DB-evidence query of the
// service-health read model.
const serviceHealthEvidenceWindowHours = 24

// auditProcessingThresholdSeconds bounds "young pending": pending audit
// outcomes younger than this are reported as processing, which explicitly
// does NOT assert processed success; older backlogs are degraded.
const auditProcessingThresholdSeconds = 3600

// GetServiceHealthReadModel handles GET /admin/v1/service-health/readmodel.
//
// Platform-admin only: the read model exposes infrastructure-wide DB/evidence
// statistics across tenants, so tenant-scoped admin roles are rejected (403).
//
// Every component reports its evidence source and observed_at. Components
// without a real health source report status "unknown" instead of a guess;
// components with zero traffic samples report "unknown" instead of a perfect
// score. Probes to gateway-core / security-engine /health are free liveness
// GETs with a 2s timeout, redirects rejected, and a 30s cache — never metered
// API calls. Probe evidence never contains the target URL or raw error text:
// failures carry stable reason codes only.
func GetServiceHealthReadModel(deps ReadModelDeps) http.HandlerFunc {
	cache := newProbeCache(readModelProbeTTL)
	client := newReadModelHTTPClient(readModelProbeTimeout)
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		// Operations-tier view: cross-tenant infrastructure evidence.
		if user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "platform admin only")
			return
		}

		components := []map[string]interface{}{}
		components = append(components, controlPlaneComponent(r.Context(), deps))
		components = append(components, probedComponent(r.Context(), client, cache, "gateway-core", deps.GatewayCoreURL))
		components = append(components, probedComponent(r.Context(), client, cache, "security-engine", deps.SecurityEngineURL))
		components = append(components, judgeComponent(r.Context(), deps))
		components = append(components, auditPipelineComponent(r.Context(), deps))
		components = append(components, billingCompensationComponent(r.Context(), deps))

		writeJSON(w, map[string]interface{}{
			"data": map[string]interface{}{
				"components": components,
				// Upstream quality (TTFT vs end-to-end latency, failures,
				// auth failures) already has a request-log-backed source in
				// the provider metrics endpoint. It is not duplicated here so
				// there are never two divergent aggregates.
				"upstream_quality_note": "provider-level TTFT/failure metrics with sample gating are served by the existing provider metrics endpoint",
				"evidence_window_hours": serviceHealthEvidenceWindowHours,
				"generated_at":          time.Now().UTC(),
			},
		})
	}
}

// controlPlaneComponent reuses the local /health evidence: db + redis ping,
// each bounded to its own 2s budget so a hung dependency cannot stall the
// read model for the full request timeout.
func controlPlaneComponent(ctx context.Context, deps ReadModelDeps) map[string]interface{} {
	dbStatus, redisStatus := "ok", "ok"
	if deps.DB != nil {
		pingCtx, cancel := context.WithTimeout(ctx, readModelProbeTimeout)
		if err := deps.DB.Ping(pingCtx); err != nil {
			dbStatus = "error"
		}
		cancel()
	} else {
		dbStatus = "unknown"
	}
	if deps.RedisClient != nil {
		pingCtx, cancel := context.WithTimeout(ctx, readModelProbeTimeout)
		if err := deps.RedisClient.Ping(pingCtx).Err(); err != nil {
			redisStatus = "error"
		}
		cancel()
	} else {
		redisStatus = "unknown"
	}
	status := "healthy"
	if dbStatus == "error" || redisStatus == "error" {
		status = "degraded"
	} else if dbStatus == "unknown" || redisStatus == "unknown" {
		status = "unknown"
	}
	return map[string]interface{}{
		"component":   "control-plane",
		"status":      status,
		"database":    dbStatus,
		"redis":       redisStatus,
		"observed_at": time.Now().UTC(),
		"evidence":    "local database and redis ping (same checks as GET /health)",
	}
}

// probedComponent covers gateway-core and security-engine /health liveness.
// An empty URL means the component was not configured: unknown, not down.
// Evidence never carries the target URL (internal addresses must not leak to
// the console); failures carry stable reason codes.
func probedComponent(ctx context.Context, client *http.Client, cache *probeCache, component, baseURL string) map[string]interface{} {
	comp := map[string]interface{}{
		"component":   component,
		"status":      "unknown",
		"observed_at": nil,
		"evidence":    "no health URL configured",
	}
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return comp
	}
	comp["evidence"] = "upstream /health liveness probe (target address withheld)"
	url := baseURL + "/health"
	if cached, hit, ageSeconds := cache.get(url); hit {
		applyProbe(comp, cached, true, ageSeconds)
		return comp
	}
	res := probeHTTP(ctx, client, url)
	cache.put(url, res)
	applyProbe(comp, res, false, 0)
	return comp
}

func applyProbe(comp map[string]interface{}, res probeResult, cached bool, cacheAgeSeconds int64) {
	comp["http_status"] = res.HTTPCode
	comp["latency_ms"] = res.LatencyMS
	comp["observed_at"] = res.CheckedAt
	comp["cached"] = cached
	comp["cache_age_seconds"] = cacheAgeSeconds
	comp["stale"] = cached // cached=true means the observation is up to TTL old
	switch {
	case res.Err != "":
		comp["status"] = "unreachable"
		comp["reason_code"] = res.Err // stable code, never a raw error string
	case res.HTTPCode == http.StatusOK:
		comp["status"] = "healthy"
	case res.HTTPCode/100 == 3:
		comp["status"] = "degraded"
		comp["reason_code"] = "redirect_rejected"
	default:
		comp["status"] = "degraded"
	}
	if comp["component"] == "security-engine" {
		applyEngineRuntime(comp, res.Body)
	}
}

// judgeComponent reads the authenticated runtime source shared with the
// semantic settings view; a zero fault count alone never proves health.
func judgeComponent(ctx context.Context, deps ReadModelDeps) map[string]interface{} {
	return judgeRuntimeComponent(ctx, deps, time.Now().UTC())
}

// auditPipelineComponent is DB-evidence based: pending audit outcomes and
// their age inside the window. Without traffic samples the status is unknown.
// Pending-but-young is "processing": the outcome is not yet recorded and this
// is NOT a claim that processing succeeded; only a clean window is healthy.
func auditPipelineComponent(ctx context.Context, deps ReadModelDeps) map[string]interface{} {
	comp := map[string]interface{}{
		"component":   "audit-pipeline",
		"status":      "unknown",
		"observed_at": time.Now().UTC(),
		"evidence":    "request_logs.audit_outcome within the evidence window",
		"status_note": "processing = outcomes still pending but young; this does not assert processed success",
	}
	if deps.DB == nil {
		comp["evidence"] = "database not configured"
		return comp
	}
	repo := repositoryForReadModels(deps)
	stats, err := repo.AuditPipelineStats(ctx, serviceHealthEvidenceWindowHours)
	if err != nil {
		comp["evidence"] = "evidence query failed"
		comp["reason_code"] = "evidence_query_failed"
		return comp
	}
	comp["requests_24h"] = stats.RequestCount
	comp["pending_24h"] = stats.PendingCount
	comp["oldest_pending_age_seconds"] = stats.OldestPendingAge
	comp["processing_threshold_seconds"] = auditProcessingThresholdSeconds
	switch {
	case stats.RequestCount == 0:
		comp["status"] = "unknown" // no samples in window
	case stats.PendingCount == 0:
		comp["status"] = "healthy"
	case stats.OldestPendingAge != nil && *stats.OldestPendingAge > auditProcessingThresholdSeconds:
		comp["status"] = "degraded" // backlog older than threshold
	default:
		comp["status"] = "processing"
	}
	return comp
}

// billingCompensationComponent combines backlog evidence with local worker activity.
func billingCompensationComponent(ctx context.Context, deps ReadModelDeps) map[string]interface{} {
	now := time.Now().UTC()
	comp := map[string]interface{}{
		"component":                "billing-compensation",
		"status":                   "unknown",
		"backlog_status":           "unknown",
		"worker_status":            "unknown",
		"observed_at":              now,
		"evidence":                 "billing_reservations status=reserved age and billing_request_leases within the evidence window",
		"status_note":              "backlog_status reflects database evidence; worker_status reflects this control-plane process",
		"worker_last_started_at":   nil,
		"worker_last_completed_at": nil,
		"worker_running":           false,
		"worker_reason_code":       "monitor_unavailable",
		"worker_heartbeat":         nil,
		"worker_heartbeat_note":    "local process activity; not a persisted or cross-instance heartbeat",
	}
	worker := deps.BillingCompensationMonitor.Snapshot(now)
	comp["worker_status"] = worker.Status
	comp["worker_reason_code"] = worker.ReasonCode
	comp["worker_running"] = worker.Running
	if !worker.LastStartedAt.IsZero() {
		comp["worker_last_started_at"] = worker.LastStartedAt
		comp["worker_heartbeat"] = worker.LastStartedAt
	}
	if !worker.LastCompletedAt.IsZero() {
		comp["worker_last_completed_at"] = worker.LastCompletedAt
		comp["worker_result"] = map[string]int{
			"settled":  worker.Result.Settled,
			"released": worker.Result.Released,
			"pending":  worker.Result.Pending,
			"failed":   worker.Result.Failed,
		}
		if worker.LastCompletedAt.After(worker.LastStartedAt) {
			comp["worker_heartbeat"] = worker.LastCompletedAt
		}
	}
	if deps.BillingStore == nil {
		comp["status"] = "disabled"
		comp["backlog_status"] = "disabled"
		comp["worker_status"] = "disabled"
		comp["worker_reason_code"] = "not_required"
		comp["evidence"] = "billing disabled (BillingStore nil)"
		return comp
	}
	if worker.Status == "disabled" {
		comp["status"] = "disabled"
		comp["backlog_status"] = "disabled"
		comp["reason_code"] = "not_required"
		comp["evidence"] = "prepaid reconciliation worker not required by billing mode"
		return comp
	}
	if deps.DB == nil {
		comp["evidence"] = "database not configured"
		return comp
	}
	repo := repositoryForReadModels(deps)
	stats, err := repo.BillingCompensationStats(ctx, 15)
	if err != nil {
		comp["evidence"] = "evidence query failed"
		comp["reason_code"] = "evidence_query_failed"
		return comp
	}
	comp["stale_reserved_count"] = stats.StaleReservedCount
	comp["oldest_stale_age_seconds"] = stats.OldestStaleReservedAge
	comp["active_lease_count"] = stats.ActiveLeaseCount
	comp["expired_unreleased_lease_count"] = stats.ExpiredUnreleasedLeases
	comp["oldest_expired_unreleased_seconds"] = stats.OldestExpiredUnreleased
	if stats.StaleReservedCount == 0 && stats.ExpiredUnreleasedLeases == 0 {
		comp["backlog_status"] = "clean"
		comp["status"] = worker.Status
	} else {
		comp["backlog_status"] = "backlog"
		comp["status"] = "degraded"
	}
	return comp
}

// applyEngineRuntime copies an explicit allowlist of engine runtime values
// from the /health payload into the service-health read model. The payload is
// never returned verbatim: no URLs, no raw errors, no arbitrary upstream keys.
// These fields drive the P1 profile panel and the C2 judge/fingerprint panel.
func applyEngineRuntime(comp map[string]interface{}, body map[string]interface{}) {
	runtime := nestedHealthMap(body, "runtime")
	if runtime == nil {
		return
	}
	profile := nestedHealthMap(runtime, "resource_profile")
	effective := nestedHealthMap(profile, "effective")
	metrics := nestedHealthMap(runtime, "metrics")
	metricsEffective := nestedHealthMap(metrics, "effective")
	shared := nestedHealthMap(runtime, "shared_state")

	fields := []struct {
		target string
		from   map[string]interface{}
		key    string
	}{
		{"engine_node_id", runtime, "node_id"},
		{"engine_resource_profile", profile, "resolved"},
		{"engine_resource_profile_mode", profile, "profile"},
		{"engine_judge_budget_status", profile, "judge_budget_status"},
		{"engine_detected_cpus", profile, "detected_cpus"},
		{"engine_web_concurrency", effective, "web_concurrency"},
		{"engine_input_workers", effective, "input_workers"},
		{"engine_tier1_workers", effective, "tier1_workers"},
		{"engine_tier1_threads", effective, "tier1_threads"},
		{"engine_tier1_inference_workers", effective, "tier1_inference_workers"},
		{"engine_tier1_inference_capacity", effective, "tier1_inference_capacity"},
		{"engine_tier1_concurrency_status", profile, "tier1_concurrency_status"},
		{"engine_tier1_replicas", profile, "tier1_replicas"},
		{"engine_tier1_scale_mode", profile, "tier1_scale_mode"},
		{"engine_judge_capacity", effective, "judge_capacity"},
		{"engine_judge_global_concurrency", effective, "judge_global_concurrency"},
		{"engine_metrics_scope", metrics, "scope"},
	}
	for _, f := range fields {
		if f.from == nil {
			continue
		}
		if value, ok := f.from[f.key].(string); ok && value != "" {
			comp[f.target] = value
		}
	}
	for _, f := range []struct{ target, key string }{
		{"judge_calls_per_request_avg", "judge_calls_per_request_avg"},
		{"fingerprint_hit_rate", "fingerprint_hit_rate"},
		{"engine_metrics_requests", "requests_observed"},
	} {
		if value, ok := metricsEffective[f.key].(float64); ok {
			comp[f.target] = value
		}
	}
	if value, ok := shared["healthy"].(bool); ok {
		comp["engine_shared_state_healthy"] = value
	}
	// R3: what the tier1 container itself reports. Flat, allowlisted keys only:
	// the probe payload is never forwarded verbatim.
	if tier1 := nestedHealthMap(runtime, "tier1_runtime"); tier1 != nil {
		for _, f := range []struct{ target, key string }{
			{"engine_tier1_live_reachable", "reachable"},
			{"engine_tier1_live_model_loaded", "model_loaded"},
			{"engine_tier1_live_provider", "execution_provider"},
		} {
			if value, ok := tier1[f.key].(string); ok && value != "" {
				comp[f.target] = value
			} else if value, ok := tier1[f.key].(bool); ok {
				comp[f.target] = value
			}
		}
		for _, f := range []struct{ target, key string }{
			{"engine_tier1_live_threads", "threads"},
			{"engine_tier1_live_batch_windows", "batch_windows"},
			// S1: the pool the sidecar really runs with, so the console can
			// compare it with the autotuned profile instead of trusting it.
			{"engine_tier1_live_inference_workers", "inference_workers"},
			{"engine_tier1_live_inference_capacity", "inference_capacity"},
			{"engine_tier1_live_uvicorn_workers", "uvicorn_workers"},
		} {
			if value, ok := tier1[f.key].(float64); ok {
				comp[f.target] = value
			}
		}
		// true = the sidecar pool equals the autotuned profile; false = claimed
		// and real diverge (or the sidecar is too old to report); absent = no
		// autotuned profile to compare against.
		if value, ok := tier1["capacity_matches_profile"].(bool); ok {
			comp["engine_tier1_capacity_matches_profile"] = value
		}
	}
	comp["engine_cascade_warnings"] = healthStringList(runtime["cascade_warnings"])
	comp["engine_degradation_reasons"] = healthStringList(runtime["degradation_reasons"])
	if scope, ok := metrics["scope"].(string); ok && scope != "cluster" {
		comp["engine_metrics_note"] = "指标来自单次探针命中的单个进程；多副本部署需启用共享状态才能看到集群聚合值。"
	}
}

func nestedHealthMap(parent map[string]interface{}, key string) map[string]interface{} {
	if parent == nil {
		return nil
	}
	child, _ := parent[key].(map[string]interface{})
	return child
}

func healthStringList(raw interface{}) []string {
	values, ok := raw.([]interface{})
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok && text != "" && len(out) < 8 {
			out = append(out, text)
		}
	}
	return out
}
