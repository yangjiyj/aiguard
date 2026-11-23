package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGroupMappingRuleCRUDAndPortalRead(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildWTDeps(pool)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	projID := "pgmr_" + sfx
	mustExec(t, pool, `INSERT INTO projects (id,tenant_id,name,code) VALUES ($1,$2,$3,$4)`, projID, tenantID, "portal-dev-eng", projID)
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM group_mapping_rules WHERE tenant_id=$1`, tenantID)
		mustExec(t, pool, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
	})

	// --- Create ---
	body := bytes.NewReader([]byte(`{"match_value":"rd","mapped_group":"研发部","gateway_project_id":"` + projID + `","priority":100}`))
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/group-mapping-rules", body)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	CreateGroupMappingRule(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var created groupMappingRuleDTO
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.ID == "" || created.MatchValue != "rd" || created.GatewayProjectID != projID || created.MatchType != "department" {
		t.Fatalf("bad created: %+v", created)
	}

	// --- List ---
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/admin/v1/group-mapping-rules", nil)
	req2 = withOrgUserCtx(req2, tenantID, userID)
	ListGroupMappingRules(deps)(w2, req2)
	if w2.Code != http.StatusOK || !strings.Contains(w2.Body.String(), "rd") {
		t.Fatalf("list bad: %d %s", w2.Code, w2.Body.String())
	}

	// --- Update ---
	ubody := bytes.NewReader([]byte(`{"match_value":"rd","mapped_group":"研发部","gateway_project_id":"` + projID + `","priority":50,"enabled":false}`))
	req3 := httptest.NewRequest(http.MethodPatch, "/admin/v1/group-mapping-rules/"+created.ID, ubody)
	req3 = withOrgUserCtx(req3, tenantID, userID)
	req3 = chiCtxWithID(req3, created.ID)
	w3 := httptest.NewRecorder()
	UpdateGroupMappingRule(deps)(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", w3.Code, w3.Body.String())
	}
	var updated groupMappingRuleDTO
	_ = json.Unmarshal(w3.Body.Bytes(), &updated)
	if updated.Priority != 50 || updated.Enabled != false {
		t.Fatalf("update not applied: %+v", updated)
	}

	// --- Portal read（snake_case + 租户走 header）---
	req4 := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/group-mapping-rules", nil)
	req4.Header.Set("X-JJDGuard-Tenant-Id", tenantID)
	w4 := httptest.NewRecorder()
	GetPortalGroupMappingRules(deps)(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("portal read status=%d body=%s", w4.Code, w4.Body.String())
	}
	pb := w4.Body.String()
	if !strings.Contains(pb, `"match_value":"rd"`) || !strings.Contains(pb, `"gateway_project_id":"`+projID+`"`) {
		t.Fatalf("portal read missing snake keys: %s", pb)
	}

	// --- Delete ---
	req5 := httptest.NewRequest(http.MethodDelete, "/admin/v1/group-mapping-rules/"+created.ID, nil)
	req5 = withOrgUserCtx(req5, tenantID, userID)
	req5 = chiCtxWithID(req5, created.ID)
	w5 := httptest.NewRecorder()
	DeleteGroupMappingRule(deps)(w5, req5)
	if w5.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d", w5.Code)
	}
}

func TestCreateGroupMappingRuleValidation(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildWTDeps(pool)
	// 缺 gateway_project_id → 400
	body := bytes.NewReader([]byte(`{"match_value":"rd","mapped_group":"研发部"}`))
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/group-mapping-rules", body)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	CreateGroupMappingRule(deps)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %s", w.Code, w.Body.String())
	}
}
