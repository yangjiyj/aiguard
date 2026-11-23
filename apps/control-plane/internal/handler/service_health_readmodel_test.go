package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// TestGetServiceHealthReadModel covers probe statuses, caching, evidence
// hygiene (no internal URLs, stable reason codes), and the evidence-first
// stance: components without sources stay unknown.
func TestGetServiceHealthReadModel(t *testing.T) {
	s := miniredis.RunT(t)
	mr := redis.NewClient(&redis.Options{Addr: s.Addr()})
	t.Cleanup(func() { _ = mr.Close() })

	databaseURL := os.Getenv("BILLING_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("BILLING_TEST_DATABASE_URL not set; skipping real-DB test")
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	// Probe targets: one healthy, one degraded.
	var gwHits, seHits int64
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&gwHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer gw.Close()
	se := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&seHits, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer se.Close()

	deps := ReadModelDeps{
		DB:                pool,
		RedisClient:       mr,
		GatewayCoreURL:    gw.URL,
		SecurityEngineURL: se.URL,
		// BillingStore nil: billing-compensation must report disabled.
	}
	router := http.NewServeMux()
	router.HandleFunc("GET /admin/v1/service-health/readmodel", GetServiceHealthReadModel(deps))

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/service-health/readmodel", nil)
		req = withBudgetUserCtx(req, "tenant_default", "user_admin")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	rec := do()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var raw struct {
		Data struct {
			Components []map[string]interface{} `json:"components"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byName := map[string]map[string]interface{}{}
	for _, c := range raw.Data.Components {
		name, _ := c["component"].(string)
		byName[name] = c
	}
	if len(raw.Data.Components) != 6 {
		t.Fatalf("components = %d, want 6: %v", len(raw.Data.Components), raw.Data.Components)
	}
	if byName["control-plane"]["status"] != "healthy" {
		t.Fatalf("control-plane status = %v", byName["control-plane"]["status"])
	}
	if byName["gateway-core"]["status"] != "healthy" || byName["gateway-core"]["http_status"].(float64) != 200 {
		t.Fatalf("gateway-core wrong: %v", byName["gateway-core"])
	}
	if byName["security-engine"]["status"] != "degraded" {
		t.Fatalf("security-engine status = %v, want degraded", byName["security-engine"]["status"])
	}
	if byName["judge"]["status"] != "unknown" {
		t.Fatalf("judge status = %v, want unknown", byName["judge"]["status"])
	}
	if byName["judge"]["fault_events_24h"] == nil {
		t.Fatalf("judge fault evidence missing")
	}

	// Audit-pipeline expectation is derived from the same evidence query:
	// the shared one-off test DB may carry request_logs fixtures from other
	// packages in a full-suite run. Pending-but-young is "processing" (no
	// processed-success claim); old backlog is degraded.
	repoStats, statsErr := repository.NewServiceHealthReadModelRepository(pool).AuditPipelineStats(context.Background(), 24)
	if statsErr != nil {
		t.Fatalf("AuditPipelineStats: %v", statsErr)
	}
	wantAudit := "unknown"
	if repoStats.RequestCount > 0 {
		if repoStats.PendingCount == 0 {
			wantAudit = "healthy"
		} else if repoStats.OldestPendingAge != nil && *repoStats.OldestPendingAge > auditProcessingThresholdSeconds {
			wantAudit = "degraded"
		} else {
			wantAudit = "processing"
		}
	}
	if byName["audit-pipeline"]["status"] != wantAudit {
		t.Fatalf("audit-pipeline status = %v, want %v (stats=%+v)", byName["audit-pipeline"]["status"], wantAudit, repoStats)
	}
	if byName["billing-compensation"]["status"] != "disabled" {
		t.Fatalf("billing-compensation status = %v, want disabled", byName["billing-compensation"]["status"])
	}

	// Evidence hygiene: internal probe URLs and raw error strings must not
	// reach the response body.
	body := rec.Body.String()
	for _, leaked := range []string{gw.URL, se.URL, "127.0.0.1", "connection refused"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("response leaks internal evidence %q", leaked)
		}
	}
	// Every component must carry observed_at.
	for _, c := range raw.Data.Components {
		if _, has := c["observed_at"]; !has {
			t.Fatalf("component %v missing observed_at", c["component"])
		}
	}

	// Second call within TTL must be served from cache: probe hit counts
	// unchanged, cached=true and cache_age_seconds present.
	rec2 := do()
	var raw2 struct {
		Data struct {
			Components []map[string]interface{} `json:"components"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &raw2)
	for _, c := range raw2.Data.Components {
		if c["component"] == "gateway-core" {
			if c["cached"] != true {
				t.Fatalf("gateway-core second call cached = %v, want true", c["cached"])
			}
			if _, has := c["cache_age_seconds"]; !has {
				t.Fatalf("gateway-core missing cache_age_seconds")
			}
		}
	}
	if atomic.LoadInt64(&gwHits) != 1 || atomic.LoadInt64(&seHits) != 1 {
		t.Fatalf("probe hits gw=%d se=%d, want 1/1 (cache must absorb repeats)", gwHits, seHits)
	}
}

// TestServiceHealthRedirectNotFollowed is the negative sample: a 302 to
// another host must not be followed; the redirect target stays untouched and
// the probe reports the redirect as degraded evidence.
func TestServiceHealthRedirectNotFollowed(t *testing.T) {
	var targetHits int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&targetHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/evil", http.StatusFound)
	}))
	defer redirector.Close()

	client := newReadModelHTTPClient(readModelProbeTimeout)
	res := probeHTTP(context.Background(), client, redirector.URL+"/health")
	if atomic.LoadInt64(&targetHits) != 0 {
		t.Fatalf("redirect target was followed %d times, want 0", targetHits)
	}
	if res.HTTPCode != http.StatusFound {
		t.Fatalf("probe http code = %d, want 302 (redirect surface as evidence)", res.HTTPCode)
	}
	comp := map[string]interface{}{}
	applyProbe(comp, res, false, 0)
	if comp["status"] != "degraded" || comp["reason_code"] != "redirect_rejected" {
		t.Fatalf("redirect probe = %v, want degraded/redirect_rejected", comp)
	}
}

// TestServiceHealthTimeoutReasonCode verifies slow probes surface the stable
// timeout code instead of a raw error string.
func TestServiceHealthTimeoutReasonCode(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * readModelProbeTimeout)
	}))
	defer slow.Close()
	client := newReadModelHTTPClient(100 * time.Millisecond)
	res := probeHTTP(context.Background(), client, slow.URL+"/health")
	if res.Err != "timeout" {
		t.Fatalf("slow probe reason = %q, want stable code timeout", res.Err)
	}
	if strings.Contains(res.Err, "context") {
		t.Fatalf("reason code leaked raw error text: %q", res.Err)
	}
}

// TestGetServiceHealthReadModelForbidden guards the platform-admin-only
// stance: tenant-scoped roles (including tenant admin tiers) get 403.
func TestGetServiceHealthReadModelForbidden(t *testing.T) {
	deps := ReadModelDeps{}
	router := http.NewServeMux()
	router.HandleFunc("GET /admin/v1/service-health/readmodel", GetServiceHealthReadModel(deps))
	for _, role := range []string{"developer", "tenant_admin", "admin"} {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/service-health/readmodel", nil)
		u := &repository.User{ID: "u1", TenantID: "t1", Role: role, Status: "active"}
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, u))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("role %s status = %d, want 403 (platform admin only)", role, rec.Code)
		}
	}
}

// TestProbeHTTPUnreachable verifies transport failures surface as stable
// evidence codes, never as raw error strings.
func TestProbeHTTPUnreachable(t *testing.T) {
	client := newReadModelHTTPClient(time.Second)
	res := probeHTTP(context.Background(), client, "http://127.0.0.1:1/health")
	if res.Err != "unreachable" {
		t.Fatalf("unreachable probe reason = %q, want stable code unreachable", res.Err)
	}
	if res.HTTPCode != 0 {
		t.Fatalf("unreachable probe http code = %d, want 0", res.HTTPCode)
	}
}
