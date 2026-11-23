package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func portalAuthorizationRequest(tenantID, userID string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/users/"+userID+"/authorization-context", nil)
	request.Header.Set("X-JJDGuard-Tenant-Id", tenantID)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", userID)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
}

func TestPortalUserAuthorizationContextBehavior(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	departmentName := "authorization-context"
	teamID := ensureDepartment(t, pool, tenantID, departmentName)
	mustExec(t, pool, `UPDATE teams SET model_access_mode='allowlist',model_access_configured=true WHERE id=$1`, teamID)
	resolvedAt := time.Unix(2000, 123000)
	if _, err := pool.Exec(context.Background(), "UPDATE users SET department_id=$1, department_resolved_at=$2, department_assignment_mode=$3 WHERE id=$4", teamID, resolvedAt, "automatic", userID); err != nil {
		t.Fatal(err)
	}
	providerID, modelIDs := wtProviderModels(t, pool, tenantID, "marketing-model", "denied-model")
	var expectedDepartmentVersion int64
	if err := pool.QueryRow(context.Background(), "SELECT department_version FROM users WHERE id=$1", userID).Scan(&expectedDepartmentVersion); err != nil {
		t.Fatal(err)
	}

	// A -> B -> A must never reuse an authorization revision, even when the
	// audit timestamp is identical for both moves.
	teamB := ensureDepartment(t, pool, tenantID, "authorization-context-b")
	if _, err := pool.Exec(context.Background(), "UPDATE users SET department_id=$1, department_resolved_at=$2 WHERE id=$3", teamB, resolvedAt, userID); err != nil {
		t.Fatal(err)
	}
	var versionB int64
	if err := pool.QueryRow(context.Background(), "SELECT department_version FROM users WHERE id=$1", userID).Scan(&versionB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), "UPDATE users SET department_id=$1, department_resolved_at=$2 WHERE id=$3", teamID, resolvedAt, userID); err != nil {
		t.Fatal(err)
	}
	var versionA2 int64
	if err := pool.QueryRow(context.Background(), "SELECT department_version FROM users WHERE id=$1", userID).Scan(&versionA2); err != nil {
		t.Fatal(err)
	}
	if expectedDepartmentVersion == 0 || versionB == 0 || versionA2 == 0 ||
		expectedDepartmentVersion == versionB || versionB == versionA2 || expectedDepartmentVersion == versionA2 {
		t.Fatalf("department revisions must be unique across A-B-A: %d, %d, %d", expectedDepartmentVersion, versionB, versionA2)
	}
	expectedDepartmentVersion = versionA2
	t.Cleanup(func() {
		mustExec(t, pool, "DELETE FROM team_models WHERE team_id=$1", teamID)
		mustExec(t, pool, "DELETE FROM models WHERE provider_id=$1", providerID)
		mustExec(t, pool, "DELETE FROM providers WHERE id=$1", providerID)
	})
	modelRepo := repository.NewTeamModelRepository(pool)
	if err := modelRepo.Upsert(context.Background(), &repository.TeamModel{TeamID: teamID, ModelID: modelIDs[0], Allowed: true}); err != nil {
		t.Fatal(err)
	}
	if err := modelRepo.Upsert(context.Background(), &repository.TeamModel{TeamID: teamID, ModelID: modelIDs[1], Allowed: false}); err != nil {
		t.Fatal(err)
	}
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool), TeamModelRepo: modelRepo}

	response := httptest.NewRecorder()
	GetPortalUserAuthorizationContext(deps).ServeHTTP(response, portalAuthorizationRequest(tenantID, userID))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			UserID            string   `json:"user_id"`
			DepartmentID      string   `json:"department_id"`
			DepartmentName    string   `json:"department_name"`
			DepartmentVersion int64    `json:"department_version"`
			ChatAllowed       bool     `json:"chat_allowed"`
			ModelIDs          []string `json:"model_ids"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.UserID != userID || payload.Data.DepartmentID != teamID || payload.Data.DepartmentName != departmentName || payload.Data.DepartmentVersion != expectedDepartmentVersion || !payload.Data.ChatAllowed {
		t.Fatalf("unexpected authorization context: %+v", payload.Data)
	}
	if len(payload.Data.ModelIDs) != 1 || payload.Data.ModelIDs[0] != "marketing-model" {
		t.Fatalf("unexpected model ids: %v", payload.Data.ModelIDs)
	}

	response = httptest.NewRecorder()
	GetPortalUserAuthorizationContext(deps).ServeHTTP(response, portalAuthorizationRequest("other-tenant", userID))
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant status=%d body=%s", response.Code, response.Body.String())
	}

	for _, state := range []struct{ status, mode string }{{"active", "emergency"}, {"disabled", "automatic"}} {
		if _, err := pool.Exec(context.Background(), "UPDATE users SET status=$1, department_assignment_mode=$2 WHERE id=$3", state.status, state.mode, userID); err != nil {
			t.Fatal(err)
		}
		response = httptest.NewRecorder()
		GetPortalUserAuthorizationContext(deps).ServeHTTP(response, portalAuthorizationRequest(tenantID, userID))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"chat_allowed":false`) {
			t.Fatalf("state=%+v status=%d body=%s", state, response.Code, response.Body.String())
		}
	}
}

func TestPortalUserAuthorizationContextHidesStorageError(t *testing.T) {
	_, tenantID, userID := setupOrgHandlerPool(t)
	errorPool, err := pgxpool.New(context.Background(), os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	deps := &Dependencies{UserRepo: repository.NewUserRepository(errorPool), TeamModelRepo: repository.NewTeamModelRepository(errorPool)}
	errorPool.Close()
	response := httptest.NewRecorder()
	GetPortalUserAuthorizationContext(deps).ServeHTTP(response, portalAuthorizationRequest(tenantID, userID))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "closed pool") || strings.Contains(response.Body.String(), "postgres") {
		t.Fatalf("storage detail leaked: %s", response.Body.String())
	}
}
