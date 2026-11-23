package handler

import (
	"context"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func authorizeQuotaScope(r *http.Request, deps *Dependencies, scopeType, scopeID string, key *repository.InternalKey, write bool) bool {
	user := auth.GetUser(r.Context())
	if user == nil || user.DepartmentAssignmentMode == "emergency" {
		return false
	}
	if isFullTenantRole(user.Role) {
		return true
	}

	switch scopeType {
	case "tenant":
		return false
	case "team":
		if write && user.Role != "team_owner" {
			return false
		}
		return quotaDepartmentContainsTeam(r.Context(), deps, user, scopeID)
	case "project":
		return quotaActorMayAccessProject(r.Context(), deps, user, scopeID, write)
	case "user":
		if write {
			return false
		}
		if scopeID == user.ID {
			return true
		}
		if user.Role != "dept_manager" && user.Role != "team_owner" {
			return false
		}
		return quotaDepartmentContainsUser(r.Context(), deps, user, scopeID)
	case "key":
		if key == nil || key.TenantID != user.TenantID || key.ProjectID == "" {
			return false
		}
		return quotaActorMayAccessProject(r.Context(), deps, user, key.ProjectID, write)
	default:
		return false
	}
}

func quotaActorMayAccessProject(ctx context.Context, deps *Dependencies, user *repository.User, projectID string, write bool) bool {
	if deps == nil || deps.ProjectRepo == nil || projectID == "" {
		return false
	}
	project, err := deps.ProjectRepo.GetByID(ctx, user.TenantID, projectID)
	if err != nil || project == nil || project.TenantID != user.TenantID {
		return false
	}

	switch user.Role {
	case "dept_manager", "team_member", "auditor":
		if write {
			return false
		}
		return quotaDepartmentContainsProject(ctx, deps, user, projectID)
	case "team_owner":
		return quotaDepartmentContainsProject(ctx, deps, user, projectID)
	case "project_owner", "project_developer", "project_viewer", "developer", "viewer":
		if write && user.Role != "project_owner" {
			return false
		}
		if project.OwnerUserID == user.ID {
			return true
		}
		lookup := deps.QuotaProjectMembershipLookup
		if lookup == nil && deps.ProjectUserRepo != nil {
			lookup = deps.ProjectUserRepo
		}
		if lookup == nil {
			return false
		}
		role, err := lookup.GetUserRole(ctx, projectID, user.ID)
		if err != nil {
			return false
		}
		if write {
			return role == "owner"
		}
		return role != ""
	default:
		return false
	}
}

func quotaScopeTargetExists(
	ctx context.Context,
	deps *Dependencies,
	tenantID string,
	scopeType string,
	scopeID string,
	key *repository.InternalKey,
) (bool, error) {
	if deps == nil {
		return false, nil
	}
	switch scopeType {
	case "tenant":
		return true, nil
	case "project":
		if deps.ProjectRepo == nil {
			return false, nil
		}
		project, err := deps.ProjectRepo.GetByID(ctx, tenantID, scopeID)
		if err != nil {
			return false, err
		}
		return project != nil && project.TenantID == tenantID, nil
	case "team":
		lookup := deps.DepartmentStore
		if lookup == nil && deps.TeamRepo != nil {
			lookup = deps.TeamRepo
		}
		if lookup == nil {
			return false, nil
		}
		team, err := lookup.GetByID(ctx, scopeID)
		if err != nil {
			return false, err
		}
		return team != nil && team.TenantID == tenantID, nil
	case "user":
		lookup := deps.QuotaUserLookup
		if lookup == nil && deps.UserRepo != nil {
			lookup = deps.UserRepo
		}
		if lookup == nil {
			return false, nil
		}
		target, err := lookup.GetByID(ctx, scopeID)
		if err != nil {
			return false, err
		}
		return target != nil && target.TenantID == tenantID, nil
	case "key":
		return key != nil && key.TenantID == tenantID && key.ID == scopeID, nil
	default:
		return false, nil
	}
}

func quotaDepartmentContainsTeam(ctx context.Context, deps *Dependencies, user *repository.User, teamID string) bool {
	lookup := quotaDepartmentLookup(deps)
	if lookup == nil {
		return false
	}
	teamIDs, err := lookup.ListTeamSubtreeIDsByUser(ctx, user.TenantID, user.ID)
	return err == nil && containsStr(teamIDs, teamID)
}

func quotaDepartmentContainsProject(ctx context.Context, deps *Dependencies, user *repository.User, projectID string) bool {
	lookup := quotaDepartmentLookup(deps)
	if lookup == nil {
		return false
	}
	projectIDs, err := lookup.ListProjectIDsByUserTeams(ctx, user.TenantID, user.ID)
	return err == nil && containsStr(projectIDs, projectID)
}

func quotaDepartmentContainsUser(ctx context.Context, deps *Dependencies, user *repository.User, targetUserID string) bool {
	lookup := quotaDepartmentLookup(deps)
	if lookup == nil {
		return false
	}
	userLookup := deps.QuotaUserLookup
	if userLookup == nil && deps.UserRepo != nil {
		userLookup = deps.UserRepo
	}
	if userLookup == nil {
		return false
	}
	target, err := userLookup.GetByID(ctx, targetUserID)
	if err != nil || target == nil || target.TenantID != user.TenantID || target.DepartmentID == "" {
		return false
	}
	teamIDs, err := lookup.ListTeamSubtreeIDsByUser(ctx, user.TenantID, user.ID)
	return err == nil && containsStr(teamIDs, target.DepartmentID)
}

func quotaDepartmentLookup(deps *Dependencies) QuotaDepartmentScopeLookup {
	if deps == nil {
		return nil
	}
	if deps.QuotaDepartmentScopeLookup != nil {
		return deps.QuotaDepartmentScopeLookup
	}
	if deps.TeamMemberRepo != nil {
		return deps.TeamMemberRepo
	}
	return nil
}
