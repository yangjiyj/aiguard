package modelrouter

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelrouting"
)

// PolicyCache caches legacy v1 routing policies with a configurable TTL and
// also provides uncached reads for v2 model-routing policies.
type PolicyCache struct {
	db    *pgxpool.Pool
	ttl   time.Duration
	mu    sync.RWMutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	policy *RoutingPolicy
	at     time.Time
}

// NewPolicyCache creates a new PolicyCache backed by the given DB pool.
func NewPolicyCache(db *pgxpool.Pool, ttl time.Duration) *PolicyCache {
	return &PolicyCache{
		db:    db,
		ttl:   ttl,
		cache: make(map[string]cacheEntry),
	}
}

// GetV2Policy returns a model override when present, otherwise the tenant
// default. It deliberately ignores every schema_version=1 row. V2 policy
// results are not cached: control-plane writes occur in another process and
// there is not yet a reliable cross-process invalidation channel.
func (c *PolicyCache) GetV2Policy(ctx context.Context, tenantID, modelName string) (*V2RoutingPolicy, error) {
	const query = `
		SELECT scope_type, scope_ref, strategy, config_json, config_version
		FROM routing_policies
		WHERE tenant_id = $1 AND schema_version = 2 AND layer = 'provider' AND enabled = true
		  AND ((scope_type = 'model' AND scope_ref = $2)
		       OR (scope_type = 'tenant' AND scope_ref = $1))
		ORDER BY CASE scope_type WHEN 'model' THEN 1 ELSE 2 END
		LIMIT 1`
	var scopeType, scopeRef, strategy string
	var configJSON []byte
	var configVersion int64
	err := c.db.QueryRow(ctx, query, tenantID, modelName).Scan(&scopeType, &scopeRef, &strategy, &configJSON, &configVersion)
	if err != nil {
		if err != pgx.ErrNoRows {
			return nil, fmt.Errorf("load model routing policy: %w", err)
		}
		return nil, nil
	}

	var config modelrouting.Config
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return nil, fmt.Errorf("decode model routing policy: %w", err)
	}
	if string(config.Strategy) != strategy {
		return nil, fmt.Errorf("model routing policy strategy is inconsistent")
	}
	scope := modelrouting.ScopeDefault
	policyModelName := ""
	if scopeType == "model" {
		scope = modelrouting.ScopeOverride
		policyModelName = scopeRef
	} else if scopeType != "tenant" {
		return nil, fmt.Errorf("model routing policy scope is invalid")
	}
	if err := config.Validate(scope); err != nil {
		return nil, fmt.Errorf("validate model routing policy: %w", err)
	}
	policy := &V2RoutingPolicy{Scope: scope, ModelName: policyModelName, ConfigVersion: configVersion, Config: config}
	return policy, nil
}

// GetPolicy returns the most specific enabled routing policy for the given scope combination and layer.
// Scope priority: model > project > tenant (most specific wins).
// Returns nil if no matching policy is found (caller should fail-open with default behaviour).
func (c *PolicyCache) GetPolicy(ctx context.Context, tenantID, scopeType, scopeRef, layer string) (*RoutingPolicy, error) {
	cacheKey := tenantID + ":" + scopeType + ":" + scopeRef + ":" + layer

	// Fast path: check cache
	c.mu.RLock()
	entry, ok := c.cache[cacheKey]
	c.mu.RUnlock()
	if ok && time.Since(entry.at) < c.ttl {
		return entry.policy, nil
	}

	// Slow path: query DB with priority ordering
	// Scope types ranked by specificity: model > project > tenant
	const query = `
		SELECT id, scope_type, scope_ref, layer, strategy, config_json, enabled
		FROM routing_policies
		WHERE tenant_id = $1
		  AND schema_version = 1
		  AND layer = $2
		  AND enabled = true
		  AND (
		    (scope_type = 'model'   AND scope_ref = $4) OR
		    (scope_type = 'project' AND scope_ref = $3) OR
		    (scope_type = 'tenant'  AND scope_ref = $1)
		  )
		ORDER BY
		  CASE scope_type
		    WHEN 'model'   THEN 1
		    WHEN 'project' THEN 2
		    WHEN 'tenant'  THEN 3
		    ELSE 4
		  END
		LIMIT 1
	`

	// scopeRef is used for project/model scope; for tenant scope we use tenantID
	row := c.db.QueryRow(ctx, query, tenantID, layer, scopeRef, scopeRef)

	var (
		id, dbScopeType, dbScopeRef, dbLayer, strategy string
		configJSON                                     []byte
		enabled                                        bool
	)
	err := row.Scan(&id, &dbScopeType, &dbScopeRef, &dbLayer, &strategy, &configJSON, &enabled)
	if err != nil {
		// No row found or scan error — cache nil (no policy) and fail-open
		c.mu.Lock()
		c.cache[cacheKey] = cacheEntry{policy: nil, at: time.Now()}
		c.mu.Unlock()
		return nil, nil //nolint:nilerr
	}

	var config map[string]any
	if len(configJSON) > 0 {
		if jerr := json.Unmarshal(configJSON, &config); jerr != nil {
			config = map[string]any{}
		}
	}

	policy := &RoutingPolicy{
		ID:        id,
		ScopeType: dbScopeType,
		ScopeRef:  dbScopeRef,
		Layer:     dbLayer,
		Strategy:  strategy,
		Config:    config,
		Enabled:   enabled,
	}

	c.mu.Lock()
	c.cache[cacheKey] = cacheEntry{policy: policy, at: time.Now()}
	c.mu.Unlock()

	return policy, nil
}
