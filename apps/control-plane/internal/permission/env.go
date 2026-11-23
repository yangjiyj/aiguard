package permission

import (
	"os"
	"strings"
)

// RBACEnforceEnabled reports whether the control-plane RBAC middleware should
// deny unauthorized requests. The environment name is intentionally kept in
// one place so startup wiring and tests cannot drift apart.
// Only an explicit true enables enforcement; an unset or invalid value keeps
// the existing dry-run default for backwards-compatible rollouts.
func RBACEnforceEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("UAG_RBAC_ENFORCE")), "true")
}
