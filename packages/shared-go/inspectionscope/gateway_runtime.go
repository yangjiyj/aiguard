package inspectionscope

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"time"
	"unicode"
)

const RuntimeFreshnessTTL = 2 * time.Minute

// RuntimeStatus identifies the actual consumer. ConfigComponent names the signed
// projection it consumes; it never changes the consumer into a gateway process.
type RuntimeStatus struct {
	Component       string                `json:"component"`
	ConfigComponent string                `json:"config_component"`
	NodeID          string                `json:"node_id"`
	Status          string                `json:"status"`
	ConfigLoaded    bool                  `json:"config_loaded"`
	AppliedRevision string                `json:"applied_revision,omitempty"`
	HeldRevision    string                `json:"held_revision,omitempty"`
	Fresh           bool                  `json:"fresh"`
	LastAttemptAt   string                `json:"last_attempt_at,omitempty"`
	LastSuccessAt   string                `json:"last_success_at,omitempty"`
	ErrorCode       string                `json:"error_code,omitempty"`
	Posture         *ProxySecurityPosture `json:"posture,omitempty"`
}

type runtimeConfigError string

func (e runtimeConfigError) Error() string { return string(e) }
func runtimeFailureCode(err error) string {
	if code, ok := err.(runtimeConfigError); ok {
		return string(code)
	}
	return "config_invalid"
}

func (r *GatewayReader) runtimeNow() time.Time {
	if r.now != nil {
		return r.now().UTC()
	}
	return time.Now().UTC()
}

func ProxyRuntimeNodeID() string {
	node := strings.TrimSpace(os.Getenv("PROXY_RUNTIME_NODE_ID"))
	if node == "" {
		node = strings.TrimSpace(os.Getenv("HOSTNAME"))
	}
	if node == "" {
		node, _ = os.Hostname()
	}
	if node == "" {
		node = "default"
	}
	node = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '_'
		}
		return r
	}, node)
	node = "proxy-server:" + node
	if len(node) > 128 {
		sum := sha256.Sum256([]byte(node))
		node = node[:110] + ":" + hex.EncodeToString(sum[:8])
	}
	return node
}

func (r *GatewayReader) RuntimeStatus() RuntimeStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := r.runtimeNow()
	out := RuntimeStatus{Component: "proxy-server", ConfigComponent: "gateway-core", NodeID: ProxyRuntimeNodeID(), Status: "pending", ConfigLoaded: r.revision != "", AppliedRevision: r.revision, HeldRevision: r.revision, ErrorCode: r.errorCode}
	if !r.lastAttempt.IsZero() {
		out.LastAttemptAt = r.lastAttempt.Format(time.RFC3339Nano)
	}
	if !r.lastSuccess.IsZero() {
		out.LastSuccessAt = r.lastSuccess.Format(time.RFC3339Nano)
	}
	if out.ErrorCode != "" {
		out.Status = "degraded"
		return out
	}
	if !out.ConfigLoaded {
		return out
	}
	age := now.Sub(r.lastSuccess)
	if r.lastSuccess.IsZero() || age < 0 || age > RuntimeFreshnessTTL {
		out.Status = "degraded"
		out.ErrorCode = "config_stale"
		return out
	}
	out.Fresh = true
	out.Status = "applied"
	return out
}
