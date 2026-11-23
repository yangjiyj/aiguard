package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// withChiIDParam injects a chi URL param so handlers that read {id} via
// chi.URLParam work under httptest without mounting the full router.
func withChiIDParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// buildIdentityDepartmentDeps wires the new IdentityDepartmentMappingRepo
// alongside the legacy identity source deps used by the compatibility layer.
func buildIdentityDepartmentDeps(pool *pgxpool.Pool) *Dependencies {
	deps := buildIdentityDeps(pool)
	deps.TeamRepo = repository.NewTeamRepository(pool)
	deps.IdentityDepartmentMappingRepo = repository.NewIdentityDepartmentMappingRepository(pool)
	return deps
}

// seedDepartmentForMapping inserts a non-system team for the tenant and returns its id.
func seedDepartmentForMapping(t *testing.T, pool *pgxpool.Pool, tenantID, name string) string {
	t.Helper()
	ctx := context.Background()
	teamID := "tmd_" + name + "_" + tenantID[len("toh_"):]
	_, err := pool.Exec(ctx, `
		INSERT INTO teams (id, tenant_id, name, path, is_system)
		VALUES ($1, $2, $3, $4, FALSE)
	`, teamID, tenantID, name, "/"+teamID)
	if err != nil {
		t.Fatalf("seed department: %v", err)
	}
	return teamID
}

// createMappingViaAPI is a helper that POSTs a new mapping through the API
// and returns the decoded response DTO.
func createMappingViaAPI(t *testing.T, deps *Dependencies, tenantID, userID string, body string) identityDepartmentMappingDTO {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/department-mappings", bytes.NewReader([]byte(body)))
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	CreateIdentityDepartmentMapping(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create mapping want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var dto identityDepartmentMappingDTO
	_ = json.Unmarshal(w.Body.Bytes(), &dto)
	return dto
}

// TestIdentityDepartmentMappingCreateValidatesRequiredFields exercises the
// customer-facing create endpoint and asserts that empty external_group,
// unknown source_type, or missing department_id are rejected with clear
// messages that never mention database internals.
func TestIdentityDepartmentMappingCreateValidatesRequiredFields(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)

	cases := []struct {
		name string
		body string
	}{
		{"empty external_group", `{"source_type":"oidc","source_id":"idp-a","external_group":"","department_id":"tmd_x"}`},
		{"unknown source_type", `{"source_type":"saml","source_id":"idp-a","external_group":"rd","department_id":"tmd_x"}`},
		{"empty department_id", `{"source_type":"oidc","source_id":"idp-a","external_group":"rd","department_id":""}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/department-mappings", bytes.NewReader([]byte(c.body)))
			req = withOrgUserCtx(req, tenantID, userID)
			w := httptest.NewRecorder()
			CreateIdentityDepartmentMapping(deps)(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "identity_department_mappings") {
				t.Fatalf("response leaks table name: %s", w.Body.String())
			}
		})
	}
}

// TestIdentityDepartmentMappingCreateRejectsCrossTenantTarget asserts that a
// mapping whose department_id belongs to a different tenant is rejected.
func TestIdentityDepartmentMappingCreateRejectsCrossTenantTarget(t *testing.T) {
	pool, tenantA, userA := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	ctx := context.Background()

	// Tenant B and a department owned by tenant B.
	tenantB := "txb_" + tenantA[len("toh_"):]
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active',TRUE)`, tenantB, tenantB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantB)
	})
	deptB := seedDepartmentForMapping(t, pool, tenantB, "B部门")

	body := `{"source_type":"oidc","source_id":"idp-a","external_group":"研发中心","department_id":"` + deptB + `"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/department-mappings", bytes.NewReader([]byte(body)))
	req = withOrgUserCtx(req, tenantA, userA)
	w := httptest.NewRecorder()
	CreateIdentityDepartmentMapping(deps)(w, req)

	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "不属于当前租户") {
		t.Fatalf("cross-tenant department must be rejected, got %d %s", w.Code, w.Body.String())
	}
}

// TestIdentityDepartmentMappingCreateRejectsDuplicate asserts that creating a
// rule with the same (source_type, source_id, external_group) as an existing
// rule is rejected with a conflict status rather than silently overwriting.
func TestIdentityDepartmentMappingCreateRejectsDuplicate(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	dept := seedDepartmentForMapping(t, pool, tenantID, "研发部")

	body := `{"source_type":"oidc","source_id":"idp-a","external_group":"研发中心","department_id":"` + dept + `"}`
	createMappingViaAPI(t, deps, tenantID, userID, body)

	// Same natural key -> must conflict.
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/department-mappings", bytes.NewReader([]byte(body)))
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	CreateIdentityDepartmentMapping(deps)(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate rule want 409, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestIdentityDepartmentMappingListReturnsDepartmentName asserts that the list
// response carries the human-readable department name and never the raw table
// name or Keycloak/LDAP internal identifiers.
func TestIdentityDepartmentMappingListReturnsDepartmentName(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	dept := seedDepartmentForMapping(t, pool, tenantID, "研发中心部门")

	dto := createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-a","external_group":"研发组","department_id":"`+dept+`","priority":50}`)
	if dto.DepartmentName != "研发中心部门" {
		t.Fatalf("expected department_name 研发中心部门, got %q", dto.DepartmentName)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/identity/department-mappings?source_type=oidc&source_id=idp-a", nil)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	ListIdentityDepartmentMappings(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data []identityDepartmentMappingDTO `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(resp.Data))
	}
	if resp.Data[0].DepartmentName != "研发中心部门" {
		t.Fatalf("list department_name mismatch: %q", resp.Data[0].DepartmentName)
	}
	if resp.Data[0].ExternalGroup != "研发组" {
		t.Fatalf("external_group mismatch: %q", resp.Data[0].ExternalGroup)
	}
	if strings.Contains(w.Body.String(), "target_department_id") {
		t.Fatalf("response leaks internal column name: %s", w.Body.String())
	}
}

// TestIdentityDepartmentMappingUpdateChangesPriority asserts PATCH updates the
// priority and preserves the natural key uniqueness invariant.
func TestIdentityDepartmentMappingUpdateChangesPriority(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	dept := seedDepartmentForMapping(t, pool, tenantID, "运维部")

	created := createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-a","external_group":"oncall","department_id":"`+dept+`","priority":100}`)

	body := `{"source_type":"oidc","source_id":"idp-a","external_group":"oncall","department_id":"` + dept + `","priority":10}`
	req := httptest.NewRequest(http.MethodPatch, "/admin/v1/identity/department-mappings/"+created.ID, bytes.NewReader([]byte(body)))
	req = withChiIDParam(withOrgUserCtx(req, tenantID, userID), "id", created.ID)
	w := httptest.NewRecorder()
	UpdateIdentityDepartmentMapping(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("update want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var dto identityDepartmentMappingDTO
	_ = json.Unmarshal(w.Body.Bytes(), &dto)
	if dto.Priority != 10 {
		t.Fatalf("expected priority 10, got %d", dto.Priority)
	}
}

// TestIdentityDepartmentMappingDeleteRemovesRule asserts DELETE removes the
// rule and that subsequent list does not return it.
func TestIdentityDepartmentMappingDeleteRemovesRule(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	dept := seedDepartmentForMapping(t, pool, tenantID, "财务部")

	created := createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-a","external_group":"finance","department_id":"`+dept+`"}`)

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/identity/department-mappings/"+created.ID, nil)
	req = withChiIDParam(withOrgUserCtx(req, tenantID, userID), "id", created.ID)
	w := httptest.NewRecorder()
	DeleteIdentityDepartmentMapping(deps)(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete want 204, got %d body=%s", w.Code, w.Body.String())
	}

	// Cross-tenant delete must not succeed: build a second tenant and attempt
	// to delete the same id from its context.
	tenantB := "tdb_" + tenantID[len("toh_"):]
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active',TRUE)`, tenantB, tenantB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantB) })
	dept2 := seedDepartmentForMapping(t, pool, tenantID, "法务部")
	created2 := createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-a","external_group":"legal","department_id":"`+dept2+`"}`)

	delReq := httptest.NewRequest(http.MethodDelete, "/admin/v1/identity/department-mappings/"+created2.ID, nil)
	tenantBUser := "uxb_" + tenantID[len("toh_"):]
	u := &repository.User{ID: tenantBUser, TenantID: tenantB, Role: "platform_admin", Status: "active"}
	delReq = withChiIDParam(delReq.WithContext(context.WithValue(delReq.Context(), auth.UserKey, u)), "id", created2.ID)
	delW := httptest.NewRecorder()
	DeleteIdentityDepartmentMapping(deps)(delW, delReq)
	if delW.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete want 404, got %d body=%s", delW.Code, delW.Body.String())
	}
}

// TestIdentityDepartmentMappingPreviewResolvesGroup asserts that preview returns
// the department that a given external_group would resolve to, without
// persisting any state.
func TestIdentityDepartmentMappingPreviewResolvesGroup(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	dept := seedDepartmentForMapping(t, pool, tenantID, "预览目标部门")

	createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-a","external_group":"engineers","department_id":"`+dept+`","priority":10}`)

	body := `{"source_type":"oidc","source_id":"idp-a","external_group":"engineers"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/department-mappings/preview", bytes.NewReader([]byte(body)))
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	PreviewIdentityDepartmentMappings(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		DepartmentID   string `json:"department_id"`
		DepartmentName string `json:"department_name"`
		Matched        bool   `json:"matched"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Matched || resp.DepartmentID != dept {
		t.Fatalf("preview expected match %s, got %+v", dept, resp)
	}
	if resp.DepartmentName != "预览目标部门" {
		t.Fatalf("preview department_name mismatch: %q", resp.DepartmentName)
	}
}

// TestIdentityDepartmentMappingPreviewReportsAmbiguity asserts that when a
// user carrying multiple external groups resolves to more than one distinct
// department, preview flags the ambiguity rather than silently picking one.
// The natural-key uniqueness constraint means a single group can only map to
// one department, so ambiguity arises from a user holding several groups.
func TestIdentityDepartmentMappingPreviewReportsAmbiguity(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	deptA := seedDepartmentForMapping(t, pool, tenantID, "歧义部门甲")
	deptB := seedDepartmentForMapping(t, pool, tenantID, "歧义部门乙")

	// Two distinct groups, each mapping to a different department at equal priority.
	createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-a","external_group":"group-a","department_id":"`+deptA+`","priority":10}`)
	createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-a","external_group":"group-b","department_id":"`+deptB+`","priority":10}`)

	// Preview a user that holds BOTH groups: the resolver cannot pick a single
	// winner deterministically, so the response must flag ambiguity.
	body := `{"source_type":"oidc","source_id":"idp-a","external_groups":["group-a","group-b"]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/department-mappings/preview", bytes.NewReader([]byte(body)))
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	PreviewIdentityDepartmentMappings(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Matched      bool     `json:"matched"`
		Ambiguous    bool     `json:"ambiguous"`
		CandidateIDs []string `json:"candidate_ids"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Matched || !resp.Ambiguous {
		t.Fatalf("expected ambiguous match, got %+v", resp)
	}
	if len(resp.CandidateIDs) != 2 {
		t.Fatalf("expected 2 candidates, got %d (%v)", len(resp.CandidateIDs), resp.CandidateIDs)
	}
}

// TestLegacyDeptMappingsEndpointReadsNewTable asserts the backwards-compatible
// /identity/dept-mappings GET reads from the new identity_department_mappings
// table and preserves the legacy response shape (mapped_team_id).
func TestLegacyDeptMappingsEndpointReadsNewTable(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	dept := seedDepartmentForMapping(t, pool, tenantID, "兼容读部门")

	// Seed via the legacy identity_source so the legacy endpoint can resolve
	// an active source id when no source_id query param is supplied.
	ctx := context.Background()
	sourceID := "ids_compat_" + tenantID[len("toh_"):]
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources (id, tenant_id, display_name, issuer_url, client_id, client_secret_enc, status, is_default)
		VALUES ($1,$2,'兼容 IdP','https://idp.example.com','c','enc:v1:x','active',TRUE)
	`, sourceID, tenantID); err != nil {
		t.Fatal(err)
	}

	// Write through the new endpoint into the new table.
	createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"`+sourceID+`","external_group":"legacy-group","department_id":"`+dept+`"}`)

	// Read through the legacy endpoint; it must reflect the new-table row and
	// populate mapped_team_id from target_department_id.
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/identity/dept-mappings?source_id="+sourceID, nil)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	ListIdentityDeptMappings(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("legacy list want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data []identityDeptMappingDTO `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Data) != 1 {
		t.Fatalf("legacy endpoint expected 1 row from new table, got %d", len(resp.Data))
	}
	if resp.Data[0].MappedTeamID != dept {
		t.Fatalf("legacy mapped_team_id should mirror target_department_id %s, got %q", dept, resp.Data[0].MappedTeamID)
	}
	if resp.Data[0].MatchValue != "legacy-group" {
		t.Fatalf("legacy match_value mismatch: %q", resp.Data[0].MatchValue)
	}
	// Deprecation marker is surfaced via a response header so clients can migrate.
	if w.Header().Get("Deprecation") == "" {
		t.Fatal("legacy endpoint should set a Deprecation header")
	}
}

// TestLegacyDeptMappingsCreateWritesNewTable asserts the legacy POST endpoint
// writes through to the new table and no longer dual-writes to the legacy
// identity_dept_mappings table.
func TestLegacyDeptMappingsCreateWritesNewTable(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	dept := seedDepartmentForMapping(t, pool, tenantID, "兼容写部门")
	ctx := context.Background()
	sourceID := "ids_compat_w_" + tenantID[len("toh_"):]
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources (id, tenant_id, display_name, issuer_url, client_id, client_secret_enc, status, is_default)
		VALUES ($1,$2,'兼容 IdP','https://idp.example.com','c','enc:v1:x','active',TRUE)
	`, sourceID, tenantID); err != nil {
		t.Fatal(err)
	}

	body := `{"match_value":"legacy-create","mapped_team_id":"` + dept + `"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/dept-mappings?source_id="+sourceID, bytes.NewReader([]byte(body)))
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	CreateIdentityDeptMapping(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("legacy create want 200, got %d body=%s", w.Code, w.Body.String())
	}

	// New table must contain the row.
	var newCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM identity_department_mappings WHERE tenant_id=$1 AND source_id=$2 AND match_value='legacy-create'`, tenantID, sourceID).Scan(&newCount); err != nil {
		t.Fatal(err)
	}
	if newCount != 1 {
		t.Fatalf("new table expected 1 row, got %d", newCount)
	}
	// Legacy table must NOT be written to anymore (no dual-write).
	var legacyCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM identity_dept_mappings WHERE tenant_id=$1 AND match_value='legacy-create'`, tenantID).Scan(&legacyCount); err != nil {
		t.Fatal(err)
	}
	if legacyCount != 0 {
		t.Fatalf("legacy table must not be written, got %d rows", legacyCount)
	}
}

type departmentMappingPreviewResultForTest struct {
	Matched        bool   `json:"matched"`
	Ambiguous      bool   `json:"ambiguous"`
	DepartmentID   string `json:"department_id"`
	DepartmentName string `json:"department_name"`
	Candidates     []struct {
		DepartmentID   string `json:"department_id"`
		DepartmentName string `json:"department_name"`
	} `json:"candidate_departments"`
}

func previewDepartmentMappingViaAPI(t *testing.T, deps *Dependencies, tenantID, userID, body string) departmentMappingPreviewResultForTest {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/department-mappings/preview", strings.NewReader(body))
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	PreviewIdentityDepartmentMappings(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var result departmentMappingPreviewResultForTest
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	return result
}

func TestIdentityDepartmentMappingPreviewResolvesTypedDepartmentValues(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	department := seedDepartmentForMapping(t, pool, tenantID, "编码匹配部门")
	groupDepartment := seedDepartmentForMapping(t, pool, tenantID, "群组匹配部门")
	createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-typed","external_group":"RD001","match_type":"department","department_id":"`+department+`","priority":10}`)
	createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-typed","external_group":"RD001","match_type":"groups","department_id":"`+groupDepartment+`","priority":10}`)

	t.Run("departments do not match groups", func(t *testing.T) {
		result := previewDepartmentMappingViaAPI(t, deps, tenantID, userID,
			`{"source_type":" OIDC ","source_id":" idp-typed ","external_departments":[" RD001 ","RD001"]}`)
		if !result.Matched || result.Ambiguous || result.DepartmentID != department || result.DepartmentName != "编码匹配部门" {
			t.Fatalf("department preview must match only department rules: %+v", result)
		}
	})
	t.Run("groups do not match departments", func(t *testing.T) {
		result := previewDepartmentMappingViaAPI(t, deps, tenantID, userID,
			`{"source_type":"oidc","source_id":"idp-typed","external_groups":[" RD001 ","RD001"]}`)
		if !result.Matched || result.Ambiguous || result.DepartmentID != groupDepartment {
			t.Fatalf("groups preview must match only groups rules: %+v", result)
		}
	})
}

func TestIdentityDepartmentMappingPreviewUsesLoginPriorityResolution(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	first := seedDepartmentForMapping(t, pool, tenantID, "优先匹配部门")
	second := seedDepartmentForMapping(t, pool, tenantID, "后备匹配部门")
	createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-priority","external_group":"first","department_id":"`+first+`","priority":10}`)
	createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-priority","external_group":"second","department_id":"`+second+`","priority":100}`)
	result := previewDepartmentMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-priority","external_groups":["first","second"]}`)
	if !result.Matched || result.Ambiguous || result.DepartmentID != first {
		t.Fatalf("preview must choose the lowest priority number as login does: %+v", result)
	}
}

func TestIdentityDepartmentMappingPreviewExplainsConflictsWithDepartmentNames(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	first := seedDepartmentForMapping(t, pool, tenantID, "冲突研发部")
	second := seedDepartmentForMapping(t, pool, tenantID, "冲突运维部")
	createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-conflict","external_group":"rd","department_id":"`+first+`","priority":10}`)
	createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-conflict","external_group":"ops","department_id":"`+second+`","priority":10}`)
	result := previewDepartmentMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"idp-conflict","external_groups":["rd","ops"]}`)
	if !result.Matched || !result.Ambiguous || len(result.Candidates) != 2 {
		t.Fatalf("conflict must include named departments: %+v", result)
	}
	names := map[string]bool{}
	for _, candidate := range result.Candidates {
		names[candidate.DepartmentName] = true
	}
	if !names["冲突研发部"] || !names["冲突运维部"] {
		t.Fatalf("missing customer-facing candidate names: %+v", result.Candidates)
	}
}

func TestIdentityDepartmentMappingPreviewRejectsOnlyBlankValues(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	body := `{"source_type":"oidc","source_id":"idp-a","external_groups":[" ","\t"],"external_departments":[""]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/department-mappings/preview", strings.NewReader(body))
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	PreviewIdentityDepartmentMappings(deps)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("blank values must be rejected before lookup, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestIdentityDepartmentMappingPreviewKeepsSourceVersionRulesIsolated(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDepartmentDeps(pool)
	active := seedDepartmentForMapping(t, pool, tenantID, "活动部门")
	pending := seedDepartmentForMapping(t, pool, tenantID, "草稿部门")
	createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"source-active","external_group":"staff","department_id":"`+active+`","priority":100}`)
	createMappingViaAPI(t, deps, tenantID, userID,
		`{"source_type":"oidc","source_id":"source-pending","external_group":"staff","department_id":"`+pending+`","priority":10}`)
	for _, c := range []struct{ sourceID, departmentID string }{
		{"source-active", active}, {"source-pending", pending},
	} {
		result := previewDepartmentMappingViaAPI(t, deps, tenantID, userID,
			`{"source_type":"oidc","source_id":"`+c.sourceID+`","external_group":"staff"}`)
		if !result.Matched || result.Ambiguous || result.DepartmentID != c.departmentID {
			t.Fatalf("source %s used another source version's rules: %+v", c.sourceID, result)
		}
	}
}
