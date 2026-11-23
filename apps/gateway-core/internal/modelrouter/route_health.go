package modelrouter

import (
	"sync"
	"time"
)

const (
	circuitOpenPeriod  = 30 * time.Second
	preferenceCooldown = 5 * time.Minute
	healthStateTTL     = 15 * time.Minute
	maxHealthStateKeys = 10000
)

type routeCircuit struct {
	openUntil           time.Time
	probeInFlight       bool
	consecutiveFailures int
	recent              []bool
	lastSeen            time.Time
}
type RouteHealth struct {
	mu       sync.Mutex
	now      func() time.Time
	circuits map[RouteKey]*routeCircuit
}

func NewRouteHealth(clock func() time.Time) *RouteHealth {
	if clock == nil {
		clock = time.Now
	}
	return &RouteHealth{now: clock, circuits: make(map[RouteKey]*routeCircuit)}
}

// Allow also grants the atomic half-open probe lease. Exactly one caller can
// pass after the open interval until Record reports that probe's outcome.
func (h *RouteHealth) Allow(key RouteKey) bool {
	if !validRouteKey(key) {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.circuits[key]
	if c == nil || c.openUntil.IsZero() {
		return true
	}
	if h.now().Before(c.openUntil) || c.probeInFlight {
		return false
	}
	c.probeInFlight = true
	return true
}

// Available is a non-reserving eligibility check used while scoring. Allow
// must still be called for the selected primary to atomically lease a probe.
func (h *RouteHealth) Available(key RouteKey) bool {
	if !validRouteKey(key) {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.circuits[key]
	return c == nil || c.openUntil.IsZero() || (!h.now().Before(c.openUntil) && !c.probeInFlight)
}

func (h *RouteHealth) Closed(key RouteKey) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.circuits[key]
	return c == nil || c.openUntil.IsZero()
}

// Opened reports whether the route has entered the circuit-open lifecycle,
// including the half-open probe period, until a successful probe recovers it.
func (h *RouteHealth) Opened(key RouteKey) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.circuits[key]
	return c != nil && !c.openUntil.IsZero()
}

// Release clears only a half-open probe lease. It deliberately preserves the
// open circuit and its failure history because no upstream attempt occurred.
func (h *RouteHealth) Release(key RouteKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c := h.circuits[key]; c != nil {
		c.probeInFlight = false
	}
}
func (h *RouteHealth) Record(key RouteKey, result AttemptResult) {
	if !validRouteKey(key) {
		return
	}
	// Circuit timing is based only on the injected local monotonic clock.
	// OccurredAt is observational metadata and may be delayed or future-skewed.
	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.circuits[key]
	if result.HealthNeutral {
		if c == nil {
			h.pruneLocked(now)
			if len(h.circuits) >= maxHealthStateKeys {
				h.evictOldestLocked()
			}
			c = &routeCircuit{}
			h.circuits[key] = c
		}
		c.lastSeen = laterTime(c.lastSeen, now)
		c.probeInFlight = false
		return
	}
	if !result.Success && !result.Retryable {
		if c != nil {
			lastSeen := laterTime(c.lastSeen, now)
			if c.probeInFlight {
				*c = routeCircuit{lastSeen: lastSeen}
			} else {
				c.consecutiveFailures = 0
				c.lastSeen = lastSeen
			}
		}
		return
	}
	if c == nil {
		h.pruneLocked(now)
		if len(h.circuits) >= maxHealthStateKeys {
			h.evictOldestLocked()
		}
		c = &routeCircuit{}
		h.circuits[key] = c
	}
	c.lastSeen = laterTime(c.lastSeen, now)
	if c.probeInFlight {
		c.probeInFlight = false
		if result.Success {
			*c = routeCircuit{lastSeen: c.lastSeen}
			return
		}
		c.openUntil = now.Add(circuitOpenPeriod)
		return
	}
	if result.Success {
		c.consecutiveFailures = 0
	} else {
		c.consecutiveFailures++
	}
	c.recent = append(c.recent, result.Retryable)
	if len(c.recent) > 10 {
		c.recent = append([]bool(nil), c.recent[len(c.recent)-10:]...)
	}
	failures := 0
	for _, failed := range c.recent {
		if failed {
			failures++
		}
	}
	if c.consecutiveFailures >= 3 || (len(c.recent) == 10 && failures*2 >= len(c.recent)) {
		c.openUntil = now.Add(circuitOpenPeriod)
		c.probeInFlight = false
	}
}

func laterTime(current, candidate time.Time) time.Time {
	if candidate.After(current) {
		return candidate
	}
	return current
}

func (h *RouteHealth) pruneLocked(now time.Time) {
	for key, c := range h.circuits {
		if !c.probeInFlight && !c.lastSeen.IsZero() && now.Sub(c.lastSeen) > healthStateTTL {
			delete(h.circuits, key)
		}
	}
}
func (h *RouteHealth) evictOldestLocked() {
	var key RouteKey
	var oldest time.Time
	first := true
	for candidate, c := range h.circuits {
		if c.probeInFlight {
			continue
		}
		if first || c.lastSeen.Before(oldest) {
			first = false
			oldest = c.lastSeen
			key = candidate
		}
	}
	if !first {
		delete(h.circuits, key)
	}
}

type RoutePreferenceKey struct{ TenantID, ModelName string }
type preferenceState struct {
	current, challenger   string
	streak                int
	switchedAt, lastSeen  time.Time
	lastEvaluationVersion uint64
	hasEvaluationVersion  bool
}
type PreferenceSwitch struct {
	mu     sync.Mutex
	now    func() time.Time
	states map[RoutePreferenceKey]*preferenceState
}

func NewPreferenceSwitch(clock func() time.Time) *PreferenceSwitch {
	if clock == nil {
		clock = time.Now
	}
	return &PreferenceSwitch{now: clock, states: make(map[RoutePreferenceKey]*preferenceState)}
}
func (p *PreferenceSwitch) Current(key RoutePreferenceKey) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if state := p.states[key]; state != nil {
		return state.current
	}
	return ""
}

// SetBaseline replaces dynamic preference state with an administrator-priority
// baseline. It deliberately clears challenger streak and cooldown so a later
// warm window starts a fresh three-cycle evaluation.
func (p *PreferenceSwitch) SetBaseline(key RoutePreferenceKey, current string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.pruneLocked(now)
	if _, exists := p.states[key]; !exists && len(p.states) >= maxHealthStateKeys {
		p.evictOldestLocked()
	}
	p.states[key] = &preferenceState{current: current, lastSeen: now}
}
func (p *PreferenceSwitch) Choose(key RoutePreferenceKey, current string, currentScore float64, candidate string, candidateScore float64, forced bool) string {
	return p.choose(key, current, currentScore, candidate, candidateScore, forced, 0, false)
}
func (p *PreferenceSwitch) ChooseVersioned(key RoutePreferenceKey, current string, currentScore float64, candidate string, candidateScore float64, forced bool, version uint64) string {
	return p.choose(key, current, currentScore, candidate, candidateScore, forced, version, true)
}
func (p *PreferenceSwitch) choose(key RoutePreferenceKey, current string, currentScore float64, candidate string, candidateScore float64, forced bool, version uint64, versioned bool) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	state := p.states[key]
	if state == nil {
		p.pruneLocked(now)
		if len(p.states) >= maxHealthStateKeys {
			p.evictOldestLocked()
		}
		state = &preferenceState{current: current, lastSeen: now}
		p.states[key] = state
	}
	if state.current == "" {
		state.current = current
	}
	state.lastSeen = now
	if forced {
		state.current = candidate
		state.challenger = ""
		state.streak = 0
		state.switchedAt = now
		state.hasEvaluationVersion = false
		return candidate
	}
	if candidate == "" || candidate == state.current {
		state.challenger = ""
		state.streak = 0
		return state.current
	}
	if versioned && state.hasEvaluationVersion && state.lastEvaluationVersion == version {
		return state.current
	}
	if versioned {
		state.lastEvaluationVersion = version
		state.hasEvaluationVersion = true
	}
	if !state.switchedAt.IsZero() && now.Sub(state.switchedAt) < preferenceCooldown {
		return state.current
	}
	threshold := currentScore * 1.15
	if candidateScore <= currentScore || candidateScore+1e-12 < threshold {
		state.challenger = ""
		state.streak = 0
		return state.current
	}
	if state.challenger != candidate {
		state.challenger = candidate
		state.streak = 1
	} else {
		state.streak++
	}
	if state.streak >= 3 {
		state.current = candidate
		state.challenger = ""
		state.streak = 0
		state.switchedAt = now
	}
	return state.current
}

func (p *PreferenceSwitch) pruneLocked(now time.Time) {
	for key, state := range p.states {
		if now.Sub(state.lastSeen) > healthStateTTL {
			delete(p.states, key)
		}
	}
}
func (p *PreferenceSwitch) evictOldestLocked() {
	var key RoutePreferenceKey
	var oldest time.Time
	first := true
	for candidate, state := range p.states {
		if first || state.lastSeen.Before(oldest) {
			first = false
			oldest = state.lastSeen
			key = candidate
		}
	}
	if !first {
		delete(p.states, key)
	}
}
