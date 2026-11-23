package permission

import (
	"sync"
	"time"
)

// cacheEntry holds cached grants for a user, bound to the department_version
// revision observed at load time. When the user is migrated to a new department,
// users.department_version advances and the entry
// must be treated as stale so callers reload grants instead of reusing the
// pre-migration authorization.
type cacheEntry struct {
	grants            []Grant
	loadedAt          time.Time
	departmentVersion int64 // zero value = no version tracking (legacy callers)
}

// GrantsCache caches user permission grants in memory for up to 1 minute.
// Entries carry a department_version so a long-lived session cannot reuse
// grants computed against the user's previous department after migration.
type GrantsCache struct {
	mu  sync.Map
	ttl time.Duration
}

// NewGrantsCache creates a new in-memory grants cache with 1 minute TTL
func NewGrantsCache() *GrantsCache {
	return &GrantsCache{ttl: time.Minute}
}

// Get returns cached grants for a user if fresh; nil otherwise.
// Legacy path: entries written via Set() carry no department version and are
// returned without version checks (preserves backward compatibility for any
// caller that has not migrated to the versioned API).
func (c *GrantsCache) Get(userID string) ([]Grant, bool) {
	val, ok := c.mu.Load(userID)
	if !ok {
		return nil, false
	}
	entry := val.(cacheEntry)
	if time.Since(entry.loadedAt) > c.ttl {
		c.mu.Delete(userID)
		return nil, false
	}
	return entry.grants, true
}

// Set stores grants for a user without a department version (legacy).
// Prefer SetWithVersion for any caller whose grants depend on department
// membership.
func (c *GrantsCache) Set(userID string, grants []Grant) {
	c.mu.Store(userID, cacheEntry{grants: grants, loadedAt: time.Now()})
}

// SetWithVersion stores grants bound to a department_version revision.
// If the user is later migrated, that revision advances and
// GetWithVersion/MatchVersion will report the stale entry as a miss.
func (c *GrantsCache) SetWithVersion(userID string, grants []Grant, departmentVersion int64) {
	c.mu.Store(userID, cacheEntry{grants: grants, loadedAt: time.Now(), departmentVersion: departmentVersion})
}

// GetWithVersion returns cached grants and the bound department_version.
// It reports ok=false when the entry is missing, expired, OR has no version
// attached (zero value) — callers needing version guarantees must reload.
func (c *GrantsCache) GetWithVersion(userID string) ([]Grant, int64, bool) {
	val, ok := c.mu.Load(userID)
	if !ok {
		return nil, 0, false
	}
	entry := val.(cacheEntry)
	if time.Since(entry.loadedAt) > c.ttl {
		c.mu.Delete(userID)
		return nil, 0, false
	}
	if entry.departmentVersion == 0 {
		return nil, 0, false
	}
	return entry.grants, entry.departmentVersion, true
}

// MatchVersion reports whether the cached entry's department_version equals
// the version the caller carries (typically from a long-lived session).
// A mismatch means the user's department changed since the session was
// established and the caller must drop its cached authorization and reload.
// Unknown users (no entry) never match.
func (c *GrantsCache) MatchVersion(userID string, sessionVersion int64) bool {
	val, ok := c.mu.Load(userID)
	if !ok {
		return false
	}
	entry := val.(cacheEntry)
	if entry.departmentVersion == 0 || sessionVersion == 0 {
		return false
	}
	return entry.departmentVersion == sessionVersion
}

// Invalidate removes a user's cached grants (e.g., after grant/revoke or
// department migration). Clears the version too, so a subsequent versioned
// lookup cannot accidentally reuse a stale version snapshot.
func (c *GrantsCache) Invalidate(userID string) {
	c.mu.Delete(userID)
}
