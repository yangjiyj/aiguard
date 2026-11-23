package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type orgStatsResponse struct {
	Data struct {
		Units []struct {
			ID           string `json:"id"`
			DeptCount    int    `json:"dept_count"`
			UserCount    int    `json:"user_count"`
			ProjectCount int    `json:"project_count"`
		} `json:"units"`
		TotalUnits int `json:"total_units"`
		TotalDepts int `json:"total_depts"`
		TotalUsers int `json:"total_users"`
	} `json:"data"`
}

func buildOrgStatsDeps(pool *pgxpool.Pool) *Dependencies {
	return &Dependencies{
		TenantRepo:      repository.NewTenantRepository(pool),
		TeamRepo:        repository.NewTeamRepository(pool),
		TeamMemberRepo:  repository.NewTeamMemberRepository(pool),
		UserRepo:        repository.NewUserRepository(pool),
		ProjectRepo:     repository.NewProjectRepository(pool),
		ProjectUserRepo: repository.NewProjectUserRepository(pool),
	}
}

func orgStatsRequest(tenantID, userID, role string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/stats/org", nil)
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       userID,
		TenantID: tenantID,
		Role:     role,
		Status:   "active",
	}))
}

func readOrgStatsResponse(t *testing.T, w *httptest.ResponseRecorder) orgStatsResponse {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("GetOrgStats status=%d body=%s", w.Code, w.Body.String())
	}
	var resp orgStatsResponse
	if err := json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, w.Body.String())
	}
	return resp
}

func TestGetOrgStatsDeveloperUsesTeamSubtreeOnly(t *testing.T) {
	pool := setupUsageScopeDB(t)
	tenantID, userID := seedUsageScopeTenantUser(t, pool, "developer")
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())

	rootTeamID := "team_org_stats_root_" + suffix
	childTeamID := "team_org_stats_child_" + suffix
	hiddenTeamID := "team_org_stats_hidden_" + suffix
	childUserID := "user_org_stats_child_" + suffix
	hiddenUserID := "user_org_stats_hidden_" + suffix

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM team_members WHERE team_id IN (SELECT id FROM teams WHERE tenant_id = $1)`, tenantID)
	})

	if _, err := pool.Exec(ctx, `INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $3, $4, $5), ($6, $2, $7, $4, $5)`, childUserID, tenantID, childUserID, "developer", "active", hiddenUserID, hiddenUserID); err != nil {
		t.Fatalf("insert users: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO teams (id, tenant_id, name, parent_team_id, path) VALUES
			($1, $2, $3, NULL, $4),
			($5, $2, $6, $1, $7),
			($8, $2, $9, NULL, $10)
	`, rootTeamID, tenantID, "可见部门", "/"+rootTeamID, childTeamID, "可见子部门", "/"+rootTeamID+"/"+childTeamID, hiddenTeamID, "不可见部门", "/"+hiddenTeamID); err != nil {
		t.Fatalf("insert teams: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE users
		SET department_id=CASE id
				WHEN $1 THEN $2
				WHEN $3 THEN $4
				WHEN $5 THEN $6
			END,
			department_assignment_mode='manual',
			department_assignment_source='admin'
		WHERE tenant_id=$7 AND id IN ($1,$3,$5)
	`, userID, rootTeamID, childUserID, childTeamID, hiddenUserID, hiddenTeamID, tenantID); err != nil {
		t.Fatalf("assign user departments: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO projects (id, tenant_id, name, owner_user_id, status, team_id) VALUES
			($1, $2, $3, $4, $5, $6),
			($7, $2, $8, $4, $5, $9),
			($10, $2, $11, $4, $5, $12)
	`, "proj_org_stats_root_"+suffix, tenantID, "可见根应用", userID, "active", rootTeamID, "proj_org_stats_child_"+suffix, "可见子应用", childTeamID, "proj_org_stats_hidden_"+suffix, "不可见应用", hiddenTeamID); err != nil {
		t.Fatalf("insert projects: %v", err)
	}

	w := httptest.NewRecorder()
	GetOrgStats(buildOrgStatsDeps(pool))(w, orgStatsRequest(tenantID, userID, "developer"))
	resp := readOrgStatsResponse(t, w)

	if resp.Data.TotalUnits != 1 || len(resp.Data.Units) != 1 {
		t.Fatalf("expected one scoped unit, got %+v", resp.Data)
	}
	unit := resp.Data.Units[0]
	if unit.DeptCount != 2 || unit.UserCount != 2 || unit.ProjectCount != 2 || resp.Data.TotalDepts != 2 || resp.Data.TotalUsers != 2 {
		t.Fatalf("developer org stats should only include own team subtree, got unit=%+v totals=%+v", unit, resp.Data)
	}
}

func TestGetOrgStatsTenantOwnerUsesFullTenant(t *testing.T) {
	pool := setupUsageScopeDB(t)
	tenantID, userID := seedUsageScopeTenantUser(t, pool, "tenant_owner")
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	teamID := "team_org_stats_owner_" + suffix
	projectID := "proj_org_stats_owner_" + suffix

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM team_members WHERE team_id IN (SELECT id FROM teams WHERE tenant_id = $1)`, tenantID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO teams (id, tenant_id, name, path) VALUES ($1, $2, $3, $4)`, teamID, tenantID, "部门", "/"+teamID); err != nil {
		t.Fatalf("insert team: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, owner_user_id, status, team_id) VALUES ($1, $2, $3, $4, $5, $6)`, projectID, tenantID, "应用", userID, "active", teamID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	w := httptest.NewRecorder()
	GetOrgStats(buildOrgStatsDeps(pool))(w, orgStatsRequest(tenantID, userID, "tenant_owner"))
	resp := readOrgStatsResponse(t, w)

	if len(resp.Data.Units) != 1 || resp.Data.Units[0].DeptCount != 1 || resp.Data.Units[0].UserCount != 1 || resp.Data.Units[0].ProjectCount != 1 {
		t.Fatalf("tenant owner should see full tenant stats, got %+v", resp.Data)
	}
}
