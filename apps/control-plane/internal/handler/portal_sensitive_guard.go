package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type portalSensitiveWindow struct {
	count int
	start time.Time
}

var portalSensitiveFallback = struct {
	sync.Mutex
	windows map[string]portalSensitiveWindow
}{windows: map[string]portalSensitiveWindow{}}

// Redis shares limits between control-plane instances; isolated/minimal setups
// use the same bounded window in-process.
func portalSensitiveAction(w http.ResponseWriter, r *http.Request, deps *Dependencies, tenant, user, action string) bool {
	name := "portal_sensitive:" + tenant + ":" + user + ":" + action
	count := int64(0)
	if deps.RedisClient != nil {
		result, err := deps.RedisClient.Eval(r.Context(), `local n=redis.call('INCR',KEYS[1]);if n==1 then redis.call('EXPIRE',KEYS[1],60) end;return n`, []string{name}).Int64()
		if err != nil {
			writeErrorWithStatus(w, 503, "portal_guard_unavailable", "personal security guard unavailable")
			return false
		}
		count = result
	} else {
		portalSensitiveFallback.Lock()
		now := time.Now()
		for key, bucket := range portalSensitiveFallback.windows {
			if now.Sub(bucket.start) >= time.Minute {
				delete(portalSensitiveFallback.windows, key)
			}
		}
		bucket := portalSensitiveFallback.windows[name]
		if bucket.start.IsZero() {
			bucket.start = now
		}
		bucket.count++
		portalSensitiveFallback.windows[name] = bucket
		count = int64(bucket.count)
		portalSensitiveFallback.Unlock()
	}
	if count <= 5 {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(60))
	writeErrorWithStatus(w, http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("too many personal %s attempts", action))
	return false
}
