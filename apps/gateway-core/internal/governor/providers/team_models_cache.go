package providers

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// teamModelsCacheEntry holds a cached set of allowed model IDs for a team.
type teamModelsCacheEntry struct {
	allowed   map[string]bool // model_id -> allowed bool
	allActive bool
	expiresAt time.Time
}

// TeamModelsCache provides team model whitelist lookups with in-memory TTL caching.
// It implements the governor.ModelChecker interface.
type TeamModelsCache struct {
	db  *pgxpool.Pool
	ttl time.Duration

	mu    sync.Mutex
	cache map[string]teamModelsCacheEntry // key = team_id
}

// NewTeamModelsCache creates a TeamModelsCache with the given TTL (default 5 min).
func NewTeamModelsCache(db *pgxpool.Pool, ttl time.Duration) *TeamModelsCache {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	return &TeamModelsCache{
		db:    db,
		ttl:   ttl,
		cache: make(map[string]teamModelsCacheEntry),
	}
}

// IsModelAllowedForTeam returns true if the model is in the team's whitelist.
// Falls back to true (fail-open) on DB errors so availability is preserved.
func (c *TeamModelsCache) IsModelAllowedForTeam(ctx context.Context, teamID, modelID string) (bool, error) {
	if teamID == "" {
		return true, nil // no team = fall back to old behavior
	}

	c.mu.Lock()
	if e, ok := c.cache[teamID]; ok && time.Now().Before(e.expiresAt) {
		if e.allActive {
			c.mu.Unlock()
			return true, nil
		}
		allowed, found := e.allowed[modelID]
		c.mu.Unlock()
		if !found {
			// Model not in whitelist at all = not allowed (zero trust)
			return false, nil
		}
		return allowed, nil
	}
	c.mu.Unlock()

	// Load from DB
	allowed, allActive, err := c.loadTeamModels(ctx, teamID)
	if err != nil {
		log.Printf("[team_models_cache] load error for team %s: %v", teamID, err)
		return true, err // fail-open: let through on DB error
	}

	c.mu.Lock()
	c.cache[teamID] = teamModelsCacheEntry{
		allowed:   allowed,
		allActive: allActive,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
	if allActive {
		return true, nil
	}

	val, found := allowed[modelID]
	if !found {
		return false, nil
	}
	return val, nil
}

// loadTeamModels fetches all team_models entries for a team from the DB.
// If the team has NO entries, returns an empty map (zero-trust: no models allowed).
func (c *TeamModelsCache) loadTeamModels(ctx context.Context, teamID string) (map[string]bool, bool, error) {
	var accessMode string
	if err := c.db.QueryRow(ctx,
		`SELECT model_access_mode FROM teams WHERE id = $1`, teamID,
	).Scan(&accessMode); err != nil {
		return nil, false, err
	}
	if accessMode == "all_active" {
		return map[string]bool{}, true, nil
	}
	if accessMode == "deny_all" {
		return map[string]bool{}, false, nil
	}
	rows, err := c.db.Query(ctx,
		`SELECT model_id, allowed FROM team_models WHERE team_id = $1`,
		teamID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	result := make(map[string]bool)
	for rows.Next() {
		var modelID string
		var allowed bool
		if err := rows.Scan(&modelID, &allowed); err != nil {
			return nil, false, err
		}
		result[modelID] = allowed
	}
	return result, false, rows.Err()
}
