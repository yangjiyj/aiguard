package handler

import (
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

// Capacity/availability incomplete reasons describe the engine being out of
// capacity or unreachable, never a property of the request content. One
// overloaded judge must not mint a fresh alert group per message: the first
// occurrence of a (conversation, stage, reason) stays a full security event,
// and repeats fold into that representative event as occurrences. The group's
// occurrence_count keeps "detection incomplete" visible; it is simply not
// alerted once per message.
var capacityIncompleteReasons = map[string]bool{
	"judge_capacity_deferred":      true,
	"judge_capacity_overflow":      true,
	"breaker_open":                 true,
	"inspection_queue_unavailable": true,
	"judge_timeout":                true,
	"judge_unavailable":            true,
	"window_timeout":               true,
	"tier1_inference_timeout":      true,
	"tier1_queue_timeout":          true,
	"tier1_unavailable":            true,
	"tier1_http_error":             true,
	"security_pipeline_timeout":    true,
	"security_engine_unavailable":  true,
}

func isCapacityIncompleteReason(reason string) bool {
	return capacityIncompleteReasons[strings.ToLower(strings.TrimSpace(reason))]
}

type capacityDedupeEntry struct {
	representativeEventID string
	expiresAt             time.Time
}

// capacityIncompleteDedupe remembers the representative security event for each
// (tenant, conversation, stage, reason) so repeats inside the TTL can be
// recorded as occurrences instead of new events. Entries expire so a genuinely
// new incident window opens a fresh representative event. Safe for concurrent
// use; the zero value is ready when constructed via newCapacityIncompleteDedupe.
type capacityIncompleteDedupe struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]capacityDedupeEntry
	now     func() time.Time
}

func newCapacityIncompleteDedupe(ttl time.Duration) *capacityIncompleteDedupe {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &capacityIncompleteDedupe{
		ttl:     ttl,
		entries: map[string]capacityDedupeEntry{},
		now:     time.Now,
	}
}

func (d *capacityIncompleteDedupe) conversationKey(envelope *modelrouter.RequestEnvelope, stage, reason string) string {
	if envelope == nil {
		return ""
	}
	parts := []string{
		envelope.TenantID,
		envelope.ConversationKey,
		strings.ToLower(strings.TrimSpace(stage)),
		strings.ToLower(strings.TrimSpace(reason)),
	}
	return scanfp.SHA256Hex(strings.Join(parts, "\x00"))
}

// representative returns the representative event ID for a repeat occurrence
// and true when this key was seen inside the TTL. On a first-seen key it
// returns ("", false); the caller then writes the full event and calls register.
func (d *capacityIncompleteDedupe) representative(envelope *modelrouter.RequestEnvelope, stage, reason string) (string, bool) {
	if d == nil || !isCapacityIncompleteReason(reason) {
		return "", false
	}
	key := d.conversationKey(envelope, stage, reason)
	if key == "" {
		return "", false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.entries) > 100000 {
		d.entries = map[string]capacityDedupeEntry{}
	}
	now := d.now()
	if entry, ok := d.entries[key]; ok && now.Before(entry.expiresAt) {
		entry.expiresAt = now.Add(d.ttl)
		d.entries[key] = entry
		return entry.representativeEventID, true
	}
	return "", false
}

// register stores the representative event for a first-seen key. A concurrent
// first write wins; later registers for the same key are ignored.
func (d *capacityIncompleteDedupe) register(envelope *modelrouter.RequestEnvelope, stage, reason, representativeEventID string) {
	if d == nil || representativeEventID == "" || !isCapacityIncompleteReason(reason) {
		return
	}
	key := d.conversationKey(envelope, stage, reason)
	if key == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if entry, ok := d.entries[key]; ok && now.Before(entry.expiresAt) {
		return
	}
	d.entries[key] = capacityDedupeEntry{
		representativeEventID: representativeEventID,
		expiresAt:             now.Add(d.ttl),
	}
}

// occurrenceContextKey derives the stable context key shared by the
// representative event and its occurrences for this (conversation, reason).
func (d *capacityIncompleteDedupe) occurrenceContextKey(envelope *modelrouter.RequestEnvelope, stage, reason string) string {
	key := d.conversationKey(envelope, stage, reason)
	if key == "" {
		return ""
	}
	return scanfp.SHA256Hex("capacity-incomplete\x00" + key)
}

// capacityDedupe lazily builds the handler's shared dedupe. The handler is a
// singleton, so the dedupe is shared across requests; nil is never returned
// unless the handler itself is nil.
func (h *ChatCompletionsHandler) capacityDedupe() *capacityIncompleteDedupe {
	if h == nil {
		return nil
	}
	h.capacityDedupeMu.Lock()
	defer h.capacityDedupeMu.Unlock()
	if h.capacityIncomplete == nil {
		h.capacityIncomplete = newCapacityIncompleteDedupe(0)
	}
	return h.capacityIncomplete
}
