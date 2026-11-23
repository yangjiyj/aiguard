// Package roles is the single source of truth for console platform roles
// (users.role) and the three-officer separation of duties.
//
// It is a leaf package (no internal imports) so that handler, permission and
// bootstrap code can all depend on it without cycles.
//
// Responsibilities for assignable roles:
//   - ChatUser: Chat only, inherits its department's model ceiling.
//   - TenantAdmin: existing tenant-scoped business administration.
//   - DeptManager: existing department-scoped read-only business views.
//   - Developer and Viewer: existing console business roles; never inferred
//     from an employee sign-in and never upgraded by a Chat session.
//
// Three officers:
//   - SystemAdmin (platform_admin): users, resources, system configuration
//     and security policy configuration. Since the 2026-10-01 decision it
//     also reads (and exports) audit data, login history and retained
//     content evidence.
//   - SecurityOfficer (security_officer): security policies and alert
//     handling. Cannot manage users or system configuration, cannot read audit data.
//   - Auditor (auditor): read-only access to operation audit, content
//     evidence, compliance overview and login history. Cannot see business configuration.
package roles

const (
	SystemAdmin     = "platform_admin"
	SecurityOfficer = "security_officer"
	Auditor         = "auditor"

	TenantAdmin = "tenant_admin"
	DeptManager = "dept_manager"
	Developer   = "developer"
	Viewer      = "viewer"
	ChatUser    = "chat_user" // 普通用户：无后台管理职责；所有人类账号均可进入个人门户。

	// Legacy values that may still exist on upgraded installations.
	LegacyAdmin       = "admin"
	LegacyTenantOwner = "tenant_owner"
	LegacyOperator    = "operator"
)

// assignable is the authoritative set of values an administrator may write to users.role.
var assignable = map[string]bool{
	SystemAdmin:     true,
	SecurityOfficer: true,
	Auditor:         true,
	TenantAdmin:     true,
	DeptManager:     true,
	Developer:       true,
	Viewer:          true,
	ChatUser:        true,
}

// IsAssignable reports whether role may be written to users.role.
func IsAssignable(role string) bool { return assignable[role] }

// Assignable returns the assignable roles in display order.
func Assignable() []string {
	return []string{SystemAdmin, SecurityOfficer, Auditor, TenantAdmin, DeptManager, Developer, Viewer, ChatUser}
}

// IsSystemAdmin reports whether role acts as the system administrator.
// The legacy "admin" value is treated the same way; migration 890 rewrites it.
func IsSystemAdmin(role string) bool { return role == SystemAdmin || role == LegacyAdmin }

// IsSecurityOfficer reports whether role is the security officer.
func IsSecurityOfficer(role string) bool { return role == SecurityOfficer }

// IsAuditor reports whether role is the security auditor.
func IsAuditor(role string) bool { return role == Auditor }

// CanManageSecurityPolicy reports whether role may change platform-wide security
// policies (rules, detectors, content security, tool risk, reply policy).
// Decision 2026-09-30: the system administrator keeps this right alongside the
// security officer so upgraded installations are never left without a policy owner.
func CanManageSecurityPolicy(role string) bool {
	return role == SystemAdmin || role == SecurityOfficer
}

// CanViewRawEvidence 报告 role 能否查看脱敏原文留证（脱敏前的输入/输出原文）。
// 只有系统管理员与安全保密员；审计员、租户管理员等其他角色只能看脱敏版本。
// 旧 admin 角色值不放行：与现有内容留证（canReadFullTenantContentEvidence）一致，迁移 890 已改写它。
func CanViewRawEvidence(role string) bool {
	return role == SystemAdmin || IsSecurityOfficer(role)
}

// CanHandleAlerts reports whether role may change alert dispositions.
func CanHandleAlerts(role string) bool {
	switch role {
	case SystemAdmin, SecurityOfficer, TenantAdmin, LegacyTenantOwner:
		return true
	}
	return false
}

// IsTenantWideSecurityReader reports whether role sees security records for the
// whole tenant (instead of being narrowed to its own departments).
func IsTenantWideSecurityReader(role string) bool {
	switch role {
	case SystemAdmin, SecurityOfficer, Auditor, TenantAdmin, LegacyTenantOwner:
		return true
	}
	return false
}

// CanLoginConsole is the management console login boundary: who may sign in to the
// console at all. It includes the three officers (system administrator, security
// officer, auditor) and the tenant administrators. Employees and business roles
// (chat_user, developer, viewer, dept_manager, ...) sign in through Chat instead.
//
// History: 942eecff9 (2026-10-12) introduced this boundary to isolate employee sign-in from
// administrator sessions, but listed only the administrator roles and so shut out the
// security officer and auditor that the 2026-09-30 three-officer separation of duties
// (6da5a2770) had just created with menus, routes, seeded permissions and SoD classes.
// The three officers are console roles by design; what each may do after signing in is decided
// by the permission middleware and the SoD guard, never by this function.
func CanLoginConsole(role string) bool {
	switch role {
	case SystemAdmin, SecurityOfficer, Auditor, TenantAdmin, LegacyAdmin, LegacyTenantOwner:
		return true
	}
	return false
}

// SessionRoleMatches reports whether a session's role snapshot still matches the user's current role.
// Normalization follows this package: platform_admin and its legacy alias admin are the same role
// (migration 890 rewrites admin); every other role, including tenant_owner versus tenant_admin, matches only
// itself. An empty role never matches: a session without an identity snapshot cannot be trusted.
func SessionRoleMatches(sessionRole, userRole string) bool {
	if sessionRole == "" || userRole == "" {
		return false
	}
	if sessionRole == userRole {
		return true
	}
	return IsSystemAdmin(sessionRole) && IsSystemAdmin(userRole)
}

// IsConsoleAdministrator reports the administrator tier used where a handler grants an
// administrative capability on its own (deleting keys, unlocking another account's login,
// resetting another account's two-factor). It is deliberately narrower than CanLoginConsole:
// being allowed to sign in must not widen those capabilities for the security officer or
// the auditor. (They are also refused by the SoD guard, which classifies those routes as
// system functions.)
func IsConsoleAdministrator(role string) bool {
	switch role {
	case SystemAdmin, TenantAdmin, LegacyAdmin, LegacyTenantOwner:
		return true
	}
	return false
}

// RequiresLoginHardening reports whether the console login hardening (administrator source-IP
// allowlist, mandatory two-factor) applies. It applies to every role that can sign in to the
// console, the three officers included: widening the login boundary must never create a
// weaker sign-in path.
func RequiresLoginHardening(role string) bool { return CanLoginConsole(role) }

// PortalRoles are human account roles. Portal sessions always carry the personal
// audience, regardless of the account's separate management responsibilities.
func PortalRoles() []string {
	return append(Assignable(), LegacyAdmin, LegacyTenantOwner, LegacyOperator)
}
func CanLoginPortal(role string) bool {
	for _, allowed := range PortalRoles() {
		if role == allowed {
			return true
		}
	}
	return false
}
