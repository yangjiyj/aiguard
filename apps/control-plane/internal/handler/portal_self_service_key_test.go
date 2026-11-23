package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestPortalEmployeeKeyGuards(t *testing.T) {
	if !portalProjectAssigned([]string{"project-a", "project-b"}, "project-b") {
		t.Fatal("assigned project was rejected")
	}
	if portalProjectAssigned([]string{"project-a"}, "project-other") {
		t.Fatal("unassigned project was accepted")
	}
	keys := []*repository.InternalKey{
		{Status: "active"},
		{Status: "revoked"},
		nil,
		{Status: "active"},
	}
	if got := portalActiveKeyCount(keys); got != 2 {
		t.Fatalf("active key count = %d, want 2", got)
	}
	if maxPortalUserActiveKeys != 5 {
		t.Fatalf("self-service key limit = %d, want 5", maxPortalUserActiveKeys)
	}
}

func TestPortalEmployeeCreatesKeyOnlyForAssignedProject(t *testing.T) {
	deps, pool, tenantID, userID, projectID := portalProjectFixture(t)
	ctx := context.Background()
	projectRepo := deps.ProjectRepo
	projectUserRepo := deps.ProjectUserRepo
	keyRepo := deps.KeyRepo
	project, err := projectRepo.GetByID(ctx, tenantID, projectID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := deps.UserRepo.GetByID(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	unassigned, err := deps.TeamRepo.GetBySystemKey(ctx, tenantID, "unassigned")
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, "UPDATE users SET department_id=$2,department_assignment_mode='unassigned' WHERE id=$1", userID, unassigned.ID)
	mustExec(t, pool, "DELETE FROM project_users WHERE user_id=$1", userID)

	create := func(name string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"project_id":%q,"user_id":%q,"name":%q,"scopes":["chat","responses","embeddings","models"]}`, project.ID, userID, name)
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/keys", strings.NewReader(body))
		req.Header.Set(portalIntegrationTenantHeader, tenantID)
		w := httptest.NewRecorder()
		CreatePortalKey(deps)(w, req)
		return w
	}

	denied := create("未绑定尝试")
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "project_access_denied") {
		t.Fatalf("unassigned create status=%d body=%s", denied.Code, denied.Body.String())
	}

	mustExec(t, pool, "UPDATE users SET department_id=$2,department_assignment_mode='manual' WHERE id=$1", userID, original.DepartmentID)
	if err := projectUserRepo.BindUser(ctx, project.ID, userID); err != nil {
		t.Fatal(err)
	}
	created := create("员工自助 Key")
	if created.Code != http.StatusOK {
		t.Fatalf("assigned create status=%d body=%s", created.Code, created.Body.String())
	}
	var response struct {
		ID        string   `json:"id"`
		UserID    string   `json:"user_id"`
		ProjectID string   `json:"project_id"`
		FullKey   string   `json:"full_key"`
		Scopes    []string `json:"scopes"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ID == "" || response.FullKey == "" || response.UserID != userID || response.ProjectID != project.ID {
		t.Fatal("created key response is missing identity or plaintext")
	}
	if strings.Join(response.Scopes, ",") != "chat,responses,embeddings,models" {
		t.Fatalf("unexpected scopes: %v", response.Scopes)
	}

	keys, err := keyRepo.ListByUser(ctx, tenantID, userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != response.ID || keys[0].Name != "员工自助 Key" {
		t.Fatalf("admin-visible keys = %+v", keys)
	}

	for i := 2; i <= maxPortalUserActiveKeys; i++ {
		w := create(fmt.Sprintf("员工自助 Key %d", i))
		if w.Code != http.StatusOK {
			t.Fatalf("create %d status=%d body=%s", i, w.Code, w.Body.String())
		}
	}
	limited := create("超限 Key")
	if limited.Code != http.StatusConflict || !strings.Contains(limited.Body.String(), "key_limit_reached") {
		t.Fatalf("limit status=%d body=%s", limited.Code, limited.Body.String())
	}
}
