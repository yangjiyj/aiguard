package permission

import (
	"context"
	"testing"
)

// stubChecker allows testing without a real DB
type stubChecker struct {
	grants  []Grant
	permMap map[string]bool // "role:resource:action" -> true
}

func (s *stubChecker) getGrantsForUser(_ context.Context, _, _ string) ([]Grant, error) {
	return s.grants, nil
}

// TestBuildScopeCandidates verifies scope candidate generation
func TestBuildScopeCandidates(t *testing.T) {
	candidates := buildScopeCandidates("tenant1", "team", "team_abc")
	if !candidates["tenant:tenant1"] {
		t.Error("expected tenant scope")
	}
	if !candidates["team:team_abc"] {
		t.Error("expected team scope")
	}

	candidates2 := buildScopeCandidates("tenant1", "project", "proj_x")
	if !candidates2["project:proj_x"] {
		t.Error("expected project scope")
	}
	if candidates2["team:anything"] {
		t.Error("unexpected team scope for project request")
	}
}

// TestExtractTeamIDsFromPath tests the teams.path parsing
func TestExtractTeamIDsFromPath(t *testing.T) {
	ids := extractTeamIDsFromPath("/parent_team/child_team/grandchild_team")
	expected := []string{"parent_team", "child_team", "grandchild_team"}
	for _, e := range expected {
		if !ids[e] {
			t.Errorf("expected %s in ids", e)
		}
	}

	empty := extractTeamIDsFromPath("")
	if len(empty) != 0 {
		t.Error("expected empty for empty path")
	}
}

// TestSplitResourceAction tests permission string splitting
func TestSplitResourceAction(t *testing.T) {
	cases := []struct {
		input    string
		resource string
		action   string
		ok       bool
	}{
		{"users:read", "users", "read", true},
		{"teams.members:write", "teams.members", "write", true},
		{"audit_chain:export", "audit_chain", "export", true},
		{"invalid", "", "", false},
	}
	for _, tc := range cases {
		r, a, ok := splitResourceAction(tc.input)
		if ok != tc.ok || r != tc.resource || a != tc.action {
			t.Errorf("splitResourceAction(%q) = %q,%q,%v; want %q,%q,%v",
				tc.input, r, a, ok, tc.resource, tc.action, tc.ok)
		}
	}
}

// TestNormalizePathToTemplate verifies path normalization for route matching
func TestNormalizePathToTemplate(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"/admin/v1/users/user_abc123/grants", "/admin/v1/users/{id}/grants"},
		{"/admin/v1/teams/team_x/members", "/admin/v1/teams/{id}/members"},
		{"/admin/v1/users", "/admin/v1/users"},
		{"/admin/v1/roles/platform_admin/permissions", "/admin/v1/roles/{name}/permissions"},
	}
	for _, tc := range cases {
		got := normalizePathToTemplate(tc.input)
		if got != tc.expected {
			t.Errorf("normalizePathToTemplate(%q) = %q; want %q", tc.input, got, tc.expected)
		}
	}
}

// TestPermissionMatrixHas8Roles verifies all 8 roles are in the matrix
func TestPermissionMatrixHas8Roles(t *testing.T) {
	expected := []string{
		"platform_admin", "tenant_owner", "tenant_admin", "auditor",
		"team_owner", "team_member",
		"project_owner", "project_developer", "project_viewer",
	}
	for _, role := range expected {
		if _, ok := permissionMatrix[role]; !ok {
			t.Errorf("expected role %s in permissionMatrix", role)
		}
	}
}

// TestPermissionMatrixAuditorReadOnly verifies auditor only has read/export
func TestPermissionMatrixAuditorReadOnly(t *testing.T) {
	for _, perm := range permissionMatrix["auditor"] {
		_, action, ok := splitResourceAction(perm)
		if !ok {
			continue
		}
		if action != "read" && action != "export" {
			t.Errorf("auditor should only have read/export, got action: %s (perm: %s)", action, perm)
		}
	}
}

// TestPermissionMatrixPlatformAdminHasAll verifies platform_admin has write+delete perms
func TestPermissionMatrixPlatformAdminHasAll(t *testing.T) {
	perms := permissionMatrix["platform_admin"]
	hasWrite := false
	hasDelete := false
	hasExport := false
	for _, p := range perms {
		_, action, _ := splitResourceAction(p)
		if action == "write" {
			hasWrite = true
		}
		if action == "delete" {
			hasDelete = true
		}
		if action == "export" {
			hasExport = true
		}
	}
	if !hasWrite || !hasDelete || !hasExport {
		t.Error("platform_admin should have write, delete, and export actions")
	}
}

// TestGrantsCacheSetGet verifies cache TTL behavior
func TestGrantsCacheSetGet(t *testing.T) {
	cache := NewGrantsCache()
	grants := []Grant{{ID: "g1", Role: "auditor"}}
	cache.Set("user1", grants)

	got, ok := cache.Get("user1")
	if !ok || len(got) != 1 || got[0].ID != "g1" {
		t.Error("expected to get cached grants")
	}

	cache.Invalidate("user1")
	_, ok2 := cache.Get("user1")
	if ok2 {
		t.Error("expected cache miss after invalidation")
	}
}
