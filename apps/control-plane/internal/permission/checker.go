package permission

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Grant represents a permission_grants row
type Grant struct {
	ID        string
	UserID    string
	TenantID  string
	ScopeType string // tenant | team | project
	ScopeID   string
	Role      string
	GrantedBy string
}

// grantsLoaderFunc loads a user's grants together with the department_version
// revision observed at load time. The revision is stored alongside cached grants
// so a department migration invalidates the entry even if the cache
// TTL has not elapsed and the outbox-driven Invalidate signal was delayed.
type grantsLoaderFunc func(ctx context.Context, userID, tenantID string) ([]Grant, int64, error)
type currentVersionLoaderFunc func(ctx context.Context, userID, tenantID string) (int64, bool, error)

// systemPermChecker decouples rolesHavePermission from the live DB so the
// versioned reload path stays unit-testable.
type systemPermChecker interface {
	rolesHavePermission(ctx context.Context, roles map[string]bool, resource, action string) (bool, error)
}

// Checker evaluates whether a user has a permission
type Checker struct {
	db                   *pgxpool.Pool
	cache                *GrantsCache
	grantsLoader         grantsLoaderFunc
	currentVersionLoader currentVersionLoaderFunc
	systemPermCheck      systemPermChecker
}

// NewChecker creates a permission checker with the given DB and cache
func NewChecker(db *pgxpool.Pool, cache *GrantsCache) *Checker {
	c := &Checker{db: db, cache: cache}
	c.grantsLoader = c.loadGrantsFromDB
	if db != nil {
		c.currentVersionLoader = c.loadCurrentDepartmentVersion
	}
	c.systemPermCheck = c
	return c
}

// HasPermission returns true if the user has (resource, action) in the given scope.
// scope: {scope_type}:{scope_id}  e.g. "tenant:tenant_default", "team:team_abc", "project:proj_1"
// For tenant scope, scope_id is the tenant id.
// It also accepts scopeType+scopeID separately via the ScopeRequest helper below.
func (c *Checker) HasPermission(ctx context.Context, userID, tenantID, scopeType, scopeID, resource, action string) (bool, error) {
	grants, err := c.getGrantsForUser(ctx, userID, tenantID)
	if err != nil {
		return false, fmt.Errorf("load grants: %w", err)
	}

	// Collect candidate scope_ids to check: tenant always included, plus the requested scope
	candidateScopeKeys := buildScopeCandidates(tenantID, scopeType, scopeID)

	// Collect matching role names
	matchedRoles := map[string]bool{}
	for _, g := range grants {
		key := g.ScopeType + ":" + g.ScopeID
		if candidateScopeKeys[key] {
			matchedRoles[g.Role] = true
		}
	}

	if len(matchedRoles) == 0 {
		return false, nil
	}

	// Check if any matched role has (resource, action) permission
	return c.systemPermCheck.rolesHavePermission(ctx, matchedRoles, resource, action)
}

// HasPermissionForTeamPath is like HasPermission but also includes all parent teams from path
// path format: "/parent_id/child_id/..." (teams.path field)
func (c *Checker) HasPermissionForTeamPath(ctx context.Context, userID, tenantID, teamID, teamPath, resource, action string) (bool, error) {
	grants, err := c.getGrantsForUser(ctx, userID, tenantID)
	if err != nil {
		return false, fmt.Errorf("load grants: %w", err)
	}

	// Build set of team ids from path (split "/" and filter empty)
	teamIDs := extractTeamIDsFromPath(teamPath)
	teamIDs[teamID] = true

	candidateScopeKeys := map[string]bool{
		"tenant:" + tenantID: true,
	}
	for tid := range teamIDs {
		candidateScopeKeys["team:"+tid] = true
	}

	matchedRoles := map[string]bool{}
	for _, g := range grants {
		key := g.ScopeType + ":" + g.ScopeID
		if candidateScopeKeys[key] {
			matchedRoles[g.Role] = true
		}
	}

	if len(matchedRoles) == 0 {
		return false, nil
	}

	return c.systemPermCheck.rolesHavePermission(ctx, matchedRoles, resource, action)
}

// getGrantsForUser fetches grants from cache or DB.
//
// It uses the department_version-aware cache path so that a department
// migration (advancing users.department_version) forces a reload even
// when the cache TTL has not expired. This is the belt-and-suspenders to the
// outbox-driven InvalidateUserCache: if the invalidation signal is delayed
// (multi-instance cache, worker lag), the version mismatch still guarantees
// stale pre-migration grants cannot be served.
func (c *Checker) getGrantsForUser(ctx context.Context, userID, tenantID string) ([]Grant, error) {
	grants, _, err := c.grantsForUserVersioned(ctx, userID, tenantID)
	return grants, err
}

// grantsForUserVersioned validates every versioned cache hit against the
// authoritative users.department_version value. This closes the worker-lag
// window: an outbox invalidation may be delayed, but a department change cannot
// reuse grants bound to the previous version.
func (c *Checker) grantsForUserVersioned(ctx context.Context, userID, tenantID string) ([]Grant, int64, error) {
	if grants, cachedVersion, ok := c.cache.GetWithVersion(userID); ok {
		if c.currentVersionLoader == nil {
			return grants, cachedVersion, nil
		}
		currentVersion, exists, err := c.currentVersionLoader(ctx, userID, tenantID)
		if err != nil {
			return nil, 0, err
		}
		if exists && currentVersion != 0 && currentVersion == cachedVersion {
			return grants, cachedVersion, nil
		}
		c.cache.Invalidate(userID)
	}

	// Only explicitly DB-less test checkers may consume legacy unversioned
	// entries. Production NewChecker always installs currentVersionLoader.
	if c.currentVersionLoader == nil {
		if grants, ok := c.cache.Get(userID); ok {
			return grants, 0, nil
		}
	}

	grants, version, err := c.grantsLoader(ctx, userID, tenantID)
	if err != nil {
		return nil, 0, err
	}
	if version == 0 {
		c.cache.Invalidate(userID)
		return nil, 0, nil
	}
	c.cache.SetWithVersion(userID, grants, version)
	return grants, version, nil
}

// loadGrantsFromDB fetches grants and the user's current department_version
// users so cache entries track the authoritative department authority, not
// the team_members compatibility projection.
func (c *Checker) loadGrantsFromDB(ctx context.Context, userID, tenantID string) ([]Grant, int64, error) {
	const query = `
		SELECT COALESCE(g.id, ''), COALESCE(g.user_id, ''), COALESCE(g.tenant_id, ''),
		       COALESCE(g.scope_type, ''), COALESCE(g.scope_id, ''), COALESCE(g.role, ''),
		       COALESCE(g.granted_by, ''), u.department_version
		FROM users u
		LEFT JOIN permission_grants g ON g.tenant_id = u.tenant_id AND g.user_id = u.id
		WHERE u.id = $1 AND u.tenant_id = $2
	`
	rows, err := c.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("query grants: %w", err)
	}
	defer rows.Close()

	var grants []Grant
	var version int64
	for rows.Next() {
		var grant Grant
		if err := rows.Scan(&grant.ID, &grant.UserID, &grant.TenantID, &grant.ScopeType, &grant.ScopeID, &grant.Role, &grant.GrantedBy, &version); err != nil {
			return nil, 0, fmt.Errorf("scan grant: %w", err)
		}
		if grant.ID != "" {
			grants = append(grants, grant)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate grants: %w", err)
	}
	return grants, version, nil
}

func (c *Checker) loadCurrentDepartmentVersion(ctx context.Context, userID, tenantID string) (int64, bool, error) {
	var version int64
	err := c.db.QueryRow(ctx, `
		SELECT department_version
		FROM users
		WHERE id = $1 AND tenant_id = $2
	`, userID, tenantID).Scan(&version)
	if err == pgx.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("query department version: %w", err)
	}
	return version, true, nil
}

func (c *Checker) rolesHavePermission(ctx context.Context, roles map[string]bool, resource, action string) (bool, error) {
	// platform_admin has all permissions
	if roles["platform_admin"] {
		return true, nil
	}

	if len(roles) == 0 {
		return false, nil
	}

	// Build role list for query
	roleList := make([]string, 0, len(roles))
	for r := range roles {
		roleList = append(roleList, r)
	}

	query := `
		SELECT COUNT(*) FROM system_permissions
		WHERE role_name = ANY($1)
		  AND resource = $2
		  AND action = $3
		  AND role_name IS NOT NULL
	`
	var count int
	err := c.db.QueryRow(ctx, query, roleList, resource, action).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check permissions: %w", err)
	}
	return count > 0, nil
}

// InvalidateUserCache removes a user's cached grants
func (c *Checker) InvalidateUserCache(userID string) {
	c.cache.Invalidate(userID)
	log.Printf("[permission] cache invalidated for user %s", userID)
}

// buildScopeCandidates returns the set of scope keys to check for a request
// Always includes tenant scope; includes team/project scope if relevant
func buildScopeCandidates(tenantID, scopeType, scopeID string) map[string]bool {
	candidates := map[string]bool{
		"tenant:" + tenantID: true,
	}
	if scopeType == "team" && scopeID != "" {
		candidates["team:"+scopeID] = true
	} else if scopeType == "project" && scopeID != "" {
		candidates["project:"+scopeID] = true
	}
	return candidates
}

// extractTeamIDsFromPath parses a teams.path like "/parent_id/child_id" into a set of IDs
func extractTeamIDsFromPath(path string) map[string]bool {
	ids := map[string]bool{}
	for _, part := range strings.Split(path, "/") {
		part = strings.TrimSpace(part)
		if part != "" {
			ids[part] = true
		}
	}
	return ids
}

// sanitizedLoaderError collapses any underlying loader failure into a fixed
// message so logs/audit/outbox never carry DSN, raw SQL, claims, emails, or
// driver-internal detail. Callers wrap the real error themselves; this helper
// only governs what may surface out of the permission package.
func sanitizedLoaderError(_ string) string {
	return "permission grants load failed"
}
