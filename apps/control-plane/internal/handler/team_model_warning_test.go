package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPutTeamModelsWarningUsesActualDefaultApplication(t *testing.T) {
	for _, mode := range []string{"all_active", "deny_all", "allowlist"} {
		for _, appStatus := range []string{"active", "inactive", "deleted", "missing"} {
			t.Run(mode+"/"+appStatus, func(t *testing.T) {
				pool, tenantID, userID := setupOrgHandlerPool(t)
				deps := buildWTDeps(pool)
				suffix := fmt.Sprintf("%d", time.Now().UnixNano())
				teamID, projectID := "warning_team_"+suffix, "warning_project_"+suffix
				mustExec(t, pool, `INSERT INTO teams(id,tenant_id,name,path) VALUES($1,$2,'部门',$3)`, teamID, tenantID, "/"+teamID)
				if appStatus != "missing" {
					mustExec(t, pool, `INSERT INTO projects(id,tenant_id,name,code,team_id,status) VALUES($1,$2,'已有应用',$1,$3,$4)`, projectID, tenantID, teamID, appStatus)
				}
				t.Cleanup(func() {
					mustExec(t, pool, `DELETE FROM model_policies WHERE tenant_id=$1`, tenantID)
					mustExec(t, pool, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
				})
				req := httptest.NewRequest(http.MethodPut, "/admin/v1/teams/"+teamID+"/models", bytes.NewBufferString(`{"mode":"`+mode+`","models":[]}`))
				req = chiCtxWithID(withOrgUserCtx(req, tenantID, userID), teamID)
				w := httptest.NewRecorder()
				PutTeamModels(deps)(w, req)
				if w.Code != http.StatusOK {
					t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
				}
				var response map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				hasWarning := response["warning"] != nil
				if hasWarning != (appStatus != "active") {
					t.Fatalf("warning must reflect actual active default application, independent of policy propagation: mode=%s application=%s response=%v", mode, appStatus, response)
				}
			})
		}
	}
}
