package handler

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// Two independent fixed-window limits stop credential spraying and distributed
// attacks on a single account. All attempts count; Redis failures fail closed.
func allowServiceLoginAttempt(w http.ResponseWriter, r *http.Request, deps *Dependencies, username string) bool {
	if deps.RedisClient == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_login_unavailable", "login limiter unavailable")
		return false
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	for _, scope := range []struct {
		value string
		max   int64
	}{{"user:" + username, 10}, {"ip:" + ip, 60}} {
		key := fmt.Sprintf("auth:service-login:%x", sha256.Sum256([]byte(scope.value)))
		n, err := deps.RedisClient.Eval(r.Context(), `
			local n = redis.call('INCR', KEYS[1])
			if n == 1 then redis.call('EXPIRE', KEYS[1], 60) end
			return n
		`, []string{key}).Int64()
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_login_unavailable", "login limiter unavailable")
			return false
		}
		if n > scope.max {
			w.Header().Set("Retry-After", "60")
			writeErrorWithStatus(w, http.StatusTooManyRequests, "service_login_locked", "service login temporarily locked")
			return false
		}
	}
	log.Printf("[service-login] attempt account=%x remote=%x", sha256.Sum256([]byte(username)), sha256.Sum256([]byte(ip)))
	return true
}

func auditServiceLogin(r *http.Request, deps *Dependencies, user *repository.User, result string) {
	log.Printf("[service-login] user_id=%s tenant_id=%s result=%s", user.ID, user.TenantID, result)
	r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, user))
	logAudit(r, deps, "service.login", map[string]interface{}{"result": result}, "user", user.ID)
}

// Explicit projection: never pass through untrusted matched_summary, rule names,
// evidence pointers or event bodies, even when future gateway fields are added.
func connectorRiskMetadata(e *repository.SecurityEvent) map[string]interface{} {
	return map[string]interface{}{
		"id": e.ID, "request_id": e.RequestID, "tenant_id": e.TenantID,
		"project_id": e.ProjectID, "user_id": e.UserID, "event_type": e.EventType,
		"severity": e.Severity, "rule_id": e.RuleID, "action_taken": e.ActionTaken,
		"principal_key": e.PrincipalKey, "created_at": e.CreatedAt,
		"agent_instance_id": e.AgentInstanceID,
		"risk_category":     connectorRiskCategory(e),
		"risk_factors":      connectorRiskFactors(e),
		"native_url":        "/security/alerts?request_id=" + url.QueryEscape(e.RequestID) + "&event_id=" + url.QueryEscape(e.ID),
	}
}
