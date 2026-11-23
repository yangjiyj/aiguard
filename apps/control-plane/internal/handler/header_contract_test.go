package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type headerContractSystemRepo struct {
	count   int
	eventID string
	payload map[string]any
	err     error
}

func (r *headerContractSystemRepo) Get(context.Context, string) (*repository.SystemSetting, error) {
	return nil, nil
}
func (r *headerContractSystemRepo) GetAll(context.Context) ([]*repository.SystemSetting, error) {
	return nil, nil
}
func (r *headerContractSystemRepo) Set(context.Context, string, string) error            { return nil }
func (r *headerContractSystemRepo) SetMultiple(context.Context, map[string]string) error { return nil }
func (r *headerContractSystemRepo) CreateAuditOperation(context.Context, *repository.AuditOperation) error {
	return nil
}
func (r *headerContractSystemRepo) ListAuditOperations(context.Context, int, int, string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (r *headerContractSystemRepo) GetBool(context.Context, string) (bool, error) { return false, nil }
func (r *headerContractSystemRepo) CreateHeaderContractConflictOnce(_ context.Context, eventID string, payload map[string]any) error {
	r.count++
	r.eventID, r.payload = eventID, payload
	return r.err
}

type headerContractChain struct {
	count   int
	eventID string
	payload map[string]any
	err     error
}

func (c *headerContractChain) Append(context.Context, string, string, string, map[string]any) error {
	return nil
}
func (c *headerContractChain) AppendHeaderContractConflictOnce(_ context.Context, _ string, eventID string, payload map[string]any) error {
	c.count++
	c.eventID, c.payload = eventID, payload
	return c.err
}

func newHeaderContractDeps(sys *headerContractSystemRepo, chain *headerContractChain, disabled bool) *Dependencies {
	return &Dependencies{SystemRepo: sys, AuditAppender: audit_chain.NewAppender(chain, disabled)}
}

func TestInternalTokenConflictRequiresTwoDurableAcksBefore401(t *testing.T) {
	const newCanary, oldCanary = "internal-new-canary", "internal-old-canary"
	sys, chain := &headerContractSystemRepo{}, &headerContractChain{}
	deps := newHeaderContractDeps(sys, chain, false)
	next := 0
	h := InternalAPIMiddleware("expected-secret", deps)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next++ }))
	req := httptest.NewRequest(http.MethodGet, "/internal", nil)
	req.RemoteAddr = "203.0.113.20:4567"
	req.Header["X-JJDGuard-Internal-Token"] = []string{newCanary}
	req.Header["x-newapi-internal-token"] = []string{oldCanary}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || next != 0 || sys.count != 1 || chain.count != 1 {
		t.Fatalf("status=%d next=%d durable=(%d,%d)", w.Code, next, sys.count, chain.count)
	}
	if sys.eventID == "" || sys.eventID != chain.eventID || sys.payload["header_kind"] != "internal_token" {
		t.Fatalf("bad durable identity/payload: %q %#v", sys.eventID, sys.payload)
	}
	for _, encoded := range []string{w.Body.String(), stringify(sys.payload), stringify(chain.payload)} {
		if strings.Contains(encoded, newCanary) || strings.Contains(encoded, oldCanary) {
			t.Fatal("canary leaked")
		}
	}
}

func TestConflictAuditUnavailableReturns503AndNeverCallsDownstream(t *testing.T) {
	sys, chain := &headerContractSystemRepo{}, &headerContractChain{err: errors.New("worm down")}
	deps := newHeaderContractDeps(sys, chain, false)
	next := 0
	h := EvalIntegrationAPIMiddleware("secret", deps)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next++ }))
	req := httptest.NewRequest(http.MethodGet, "/eval", nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header["X-JJDGuard-Tenant-Id"] = []string{"tenant-new-canary"}
	req.Header["X-NewAPI-Tenant-Id"] = []string{"tenant-old-canary"}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || next != 0 || sys.count != 1 || chain.count != 1 {
		t.Fatalf("status=%d next=%d durable=(%d,%d)", w.Code, next, sys.count, chain.count)
	}
	if !strings.Contains(w.Body.String(), "header_conflict_audit_unavailable") || strings.Contains(w.Body.String(), "canary") {
		t.Fatalf("unsafe response: %s", w.Body.String())
	}
}

func TestEvalAndPortalTenantLegacyCompatibilityCanonicalizes(t *testing.T) {
	for _, tc := range []struct {
		name string
		mw   func(string, *Dependencies) func(http.Handler) http.Handler
	}{
		{"eval", EvalIntegrationAPIMiddleware},
		{"portal", PortalIntegrationAPIMiddleware},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ""
			h := tc.mw("secret", &Dependencies{})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Header.Get("X-JJDGuard-Tenant-Id") }))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer secret")
			req.Header.Set("X-NewAPI-Tenant-Id", "tenant-legacy")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if got != "tenant-legacy" {
				t.Fatalf("canonical tenant=%q", got)
			}
		})
	}
}

func stringify(v any) string { return fmt.Sprint(v) }

func (r *headerContractSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}
