package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/org"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// ReadModelDeps carries the dependencies of the billing/health read-model
// handlers. It is intentionally separate from Dependencies so integration can
// wire these routes without touching the shared Dependencies struct; every
// field maps to a variable that already exists in cmd/server/main.go.
type ReadModelDeps struct {
	DB                         *pgxpool.Pool
	KeyRepo                    *repository.InternalKeyRepository
	BillingStore               *billing.Store
	BudgetSnapshot             *budget.SnapshotReader
	OrgService                 *org.Service
	RedisClient                *redis.Client
	GatewayCoreURL             string
	SecurityEngineURL          string
	BillingCompensationMonitor *billing.ReconciliationMonitor
	SemanticDeps               *Dependencies
}

// readModelProbeTTL bounds how often the health read model actually probes
// gateway-core / security-engine /health endpoints, so console refreshes do
// not hammer those services.
const readModelProbeTTL = 30 * time.Second

// readModelProbeTimeout fails fast: a slow probe is itself evidence, but the
// health endpoint must stay responsive.
const readModelProbeTimeout = 2 * time.Second

// newReadModelHTTPClient builds the probe client. Redirects are never
// followed: a health endpoint must answer directly, and a redirect could
// bounce the probe to an arbitrary host.
func newReadModelHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// probeResult is one cached liveness probe observation. Err carries a stable
// reason code (timeout | unreachable), never a raw error string.
type probeResult struct {
	HTTPCode  int
	LatencyMS int64
	Err       string
	CheckedAt time.Time
	// Body is the bounded /health JSON payload. Only an explicit allowlist of
	// scalar runtime fields is forwarded to the console (see
	// applyEngineRuntime); the raw payload never reaches an HTTP response.
	Body map[string]interface{}
}

// probeCache is a tiny TTL cache keyed by probe URL. Get also reports the
// cache entry age so responses can expose cache_age/stale semantics.
type probeCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]probeResult
}

func newProbeCache(ttl time.Duration) *probeCache {
	return &probeCache{ttl: ttl, entries: map[string]probeResult{}}
}

func (c *probeCache) get(url string) (probeResult, bool, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[url]
	if !ok || time.Since(e.CheckedAt) > c.ttl {
		return probeResult{}, false, 0
	}
	return e, true, int64(time.Since(e.CheckedAt).Seconds())
}

func (c *probeCache) put(url string, e probeResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[url] = e
}

// probeHTTP performs a bounded GET and records latency. Any response counts
// as evidence; transport failures are reduced to stable reason codes. The
// client must have redirects disabled (see newReadModelHTTPClient).
func probeHTTP(ctx context.Context, client *http.Client, url string) probeResult {
	start := time.Now()
	res := probeResult{CheckedAt: start.UTC()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Err = "unreachable"
		return res
	}
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	res.LatencyMS = latency
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, http.ErrHandlerTimeout) {
			res.Err = "timeout"
		} else {
			res.Err = "unreachable"
		}
		return res
	}
	defer resp.Body.Close()
	res.HTTPCode = resp.StatusCode
	if resp.StatusCode == http.StatusOK {
		payload, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if readErr == nil {
			var parsed map[string]interface{}
			if json.Unmarshal(payload, &parsed) == nil {
				res.Body = parsed
			}
		}
	}
	return res
}
