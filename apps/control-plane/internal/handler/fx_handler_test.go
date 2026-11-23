package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/fx"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/org"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// setupFxHandlerDB opens a test database and seeds tenant + user fixtures.
func setupFxHandlerDB(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "tfx_" + sfx
	userID := "ufx_" + sfx

	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		 VALUES ($1, $2, $3, $4, 'x', 'platform_admin', 'active')`,
		userID, tenantID, userID, userID+"@test.com",
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	t.Cleanup(func() {
		// Clean up test fx_rates inserted during test
		_, _ = pool.Exec(ctx, `DELETE FROM fx_rates WHERE created_by = 'api'`)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		pool.Close()
	})

	return pool, tenantID, userID
}

func buildFxHandlerDeps(t *testing.T, pool *pgxpool.Pool) *Dependencies {
	t.Helper()

	s := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: s.Addr()})

	teamRepo := repository.NewTeamRepository(pool)
	teamMemberRepo := repository.NewTeamMemberRepository(pool)
	quotaPolicyRepo := repository.NewQuotaPolicyRepository(pool)
	orgService := org.NewService(teamRepo, teamMemberRepo, quotaPolicyRepo)
	fxRepo := fx.NewRepository(pool)
	fxSvc := fx.NewService(fxRepo)

	return &Dependencies{
		SessionRepo:           repository.NewSessionRepository(redisClient),
		UserRepo:              repository.NewUserRepository(pool),
		TenantRepo:            repository.NewTenantRepository(pool),
		ProjectRepo:           repository.NewProjectRepository(pool),
		ProjectUserRepo:       repository.NewProjectUserRepository(pool),
		KeyRepo:               repository.NewInternalKeyRepository(pool),
		ProviderRepo:          repository.NewProviderRepository(pool),
		ModelRepo:             repository.NewModelRepository(pool),
		ModelPolicyRepo:       repository.NewModelPolicyRepository(pool),
		QuotaPolicyRepo:       quotaPolicyRepo,
		RequestLogRepo:        repository.NewRequestLogRepository(pool),
		SecurityEventRepo:     repository.NewSecurityEventRepository(pool),
		AuditDispositionRepo:  repository.NewAuditDispositionRepository(pool),
		UsageDailyRepo:        repository.NewUsageDailyRepository(pool),
		RuleSetRepo:           repository.NewRuleSetRepository(pool),
		RuleRepo:              repository.NewRuleRepository(pool),
		AgentSessionRepo:      repository.NewAgentSessionRepository(pool),
		ContentLogRepo:        repository.NewContentLogRepository(pool),
		ToolCallLogRepo:       repository.NewToolCallLogRepository(pool),
		ToolRiskConfigRepo:    repository.NewToolRiskConfigRepository(pool),
		SystemRepo:            repository.NewSystemRepository(pool),
		ProxyWhitelistRepo:    repository.NewProxyWhitelistRepository(pool),
		ReverseProxyRouteRepo: repository.NewReverseProxyRouteRepository(pool),
		CACertificatesRepo:    repository.NewCACertificateRepository(pool),
		TeamRepo:              teamRepo,
		TeamMemberRepo:        teamMemberRepo,
		OrgService:            orgService,
		PauseLogRepo:          repository.NewPauseLogRepository(pool),
		BudgetSnapshot:        budget.NewSnapshotReader(redisClient),
		RedisClient:           redisClient,
		FxService:             fxSvc,
	}
}

// withFxTestUser injects a platform_admin user context into the request.
func withFxTestUser(userID string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), auth.UserKey, &repository.User{
			ID:   userID,
			Role: "platform_admin",
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TestFxHandler_SetAndGet tests PUT /fx + GET /fx/current round-trip
func TestFxHandler_SetAndGet(t *testing.T) {
	pool, _, userID := setupFxHandlerDB(t)
	deps := buildFxHandlerDeps(t, pool)

	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return withFxTestUser(userID, next)
	})
	r.Put("/fx", SetFxRate(deps))
	r.Get("/fx/current", GetCurrentFxRate(deps))

	// PUT /fx
	body, _ := json.Marshal(map[string]interface{}{
		"rate":         7.35,
		"effective_at": time.Now().UTC().Format(time.RFC3339),
	})
	req := httptest.NewRequest("PUT", "/fx", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /fx: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// GET /fx/current
	req2 := httptest.NewRequest("GET", "/fx/current", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("GET /fx/current: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w2.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	rate, ok := resp["rate"].(float64)
	if !ok {
		t.Fatalf("response missing rate field: %v", resp)
	}
	if rate != 7.35 {
		t.Errorf("expected rate 7.35, got %f", rate)
	}
}

// TestFxHandler_GetCurrent_NoRate tests GET /fx/current when no rate exists (expects 404)
func TestFxHandler_GetCurrent_NoRate(t *testing.T) {
	pool, _, _ := setupFxHandlerDB(t)
	deps := buildFxHandlerDeps(t, pool)

	// Clear any fx_rates that might exist
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `DELETE FROM fx_rates`)

	r := chi.NewRouter()
	r.Get("/fx/current", GetCurrentFxRate(deps))

	req := httptest.NewRequest("GET", "/fx/current", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when no rate exists, got %d: %s", w.Code, w.Body.String())
	}
}

// 7.10: the rate is stored and returned exactly; a value finer than the
// DECIMAL(18,6) column is rejected instead of being silently rounded.
func TestFxHandlerKeepsRateExactAndRejectsUnrepresentablePrecision(t *testing.T) {
	pool, _, userID := setupFxHandlerDB(t)
	deps := buildFxHandlerDeps(t, pool)
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler { return withFxTestUser(userID, next) })
	r.Put("/fx", SetFxRate(deps))
	r.Get("/fx/current", GetCurrentFxRate(deps))

	put := func(raw string) *httptest.ResponseRecorder {
		body := []byte(`{"rate":` + raw + `,"effective_at":"` + time.Now().UTC().Format(time.RFC3339) + `"}`)
		req := httptest.NewRequest("PUT", "/fx", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	if w := put("7.1234567"); w.Code != http.StatusBadRequest {
		t.Fatalf("7-decimal rate: got %d, want 400 (would be rounded by DECIMAL(18,6)): %s", w.Code, w.Body.String())
	}
	if w := put("7.123456"); w.Code != http.StatusOK {
		t.Fatalf("PUT /fx: %d %s", w.Code, w.Body.String())
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/fx/current", nil))
	var resp struct {
		Rate    json.Number `json:"rate"`
		RatePPM int64       `json:"rate_ppm"`
	}
	decoder := json.NewDecoder(w.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Rate.String() != "7.123456" || resp.RatePPM != 7_123_456 {
		t.Fatalf("current rate=%s ppm=%d, want exact 7.123456 / 7123456", resp.Rate, resp.RatePPM)
	}
}
