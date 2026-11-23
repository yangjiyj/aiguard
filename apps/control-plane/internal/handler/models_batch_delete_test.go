package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type modelBatchDeleteAuditRepo struct {
	MockSystemRepo
	calls int
	op    *repository.AuditOperation
}

func (r *modelBatchDeleteAuditRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	r.calls++
	r.op = op
	return nil
}

type modelBatchDeletePermissionCall struct {
	userID    string
	tenantID  string
	scopeType string
	scopeID   string
	resource  string
	action    string
}

type modelBatchDeletePermissionAuthorizer struct {
	allowed bool
	err     error
	calls   []modelBatchDeletePermissionCall
}

func newModelBatchDeletePermissionAuthorizer() *modelBatchDeletePermissionAuthorizer {
	return &modelBatchDeletePermissionAuthorizer{allowed: true}
}

func (a *modelBatchDeletePermissionAuthorizer) HasPermission(
	_ context.Context,
	userID, tenantID, scopeType, scopeID, resource, action string,
) (bool, error) {
	a.calls = append(a.calls, modelBatchDeletePermissionCall{
		userID:    userID,
		tenantID:  tenantID,
		scopeType: scopeType,
		scopeID:   scopeID,
		resource:  resource,
		action:    action,
	})
	return a.allowed, a.err
}

func (a *modelBatchDeletePermissionAuthorizer) InvalidateUserCache(string) {}

func performModelBatchDelete(body, contentType string, user *repository.User, modelRepo *MockModelRepository, systemRepo SystemRepo) *httptest.ResponseRecorder {
	return performModelBatchDeleteWithPermission(
		body,
		contentType,
		user,
		modelRepo,
		newModelBatchDeletePermissionAuthorizer(),
		systemRepo,
	)
}

func performModelBatchDeleteWithPermission(
	body, contentType string,
	user *repository.User,
	modelRepo *MockModelRepository,
	permissionChecker PermissionAuthorizer,
	systemRepo SystemRepo,
) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/models/batch-delete", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if user != nil {
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
	}
	recorder := httptest.NewRecorder()
	BatchDeleteModels(&Dependencies{
		ModelRepo:         modelRepo,
		PermissionChecker: permissionChecker,
		SystemRepo:        systemRepo,
	}).ServeHTTP(recorder, req)
	return recorder
}

func decodeModelBatchDeleteError(t *testing.T, recorder *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	var response struct {
		Error struct {
			Code    string
			Message string
		}
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode error response: %v; body=%q", err, recorder.Body.String())
	}
	return response.Error.Code, response.Error.Message
}

func TestBatchDeleteModelsRejectsUnauthenticatedRequest(t *testing.T) {
	modelRepo := &MockModelRepository{}
	recorder := performModelBatchDelete("{\"model_ids\":[\"model-a\"]}", "application/json", nil, modelRepo, nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
	if modelRepo.DeleteBatchCalls != 0 {
		t.Fatalf("DeleteBatch calls = %d, want 0", modelRepo.DeleteBatchCalls)
	}
}

func TestBatchDeleteModelsRejectsInvalidRequestsBeforeRepository(t *testing.T) {
	manyIDs := make([]string, 101)
	for i := range manyIDs {
		manyIDs[i] = fmt.Sprintf("model-%03d", i)
	}
	manyIDsJSON, err := json.Marshal(map[string]interface{}{"model_ids": manyIDs})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, contentType, body string
	}{
		{"non json content type", "text/plain", "{\"model_ids\":[\"model-a\"]}"},
		{"empty body", "application/json", ""},
		{"empty array", "application/json", "{\"model_ids\":[]}"},
		{"more than one hundred ids", "application/json", string(manyIDsJSON)},
		{"blank id", "application/json", "{\"model_ids\":[\"model-a\",\" \\t \"]}"},
		{"duplicate id", "application/json", "{\"model_ids\":[\"model-a\",\"model-a\"]}"},
		{"unknown tenant field", "application/json", "{\"model_ids\":[\"model-a\"],\"tenant_id\":\"tenant-attacker\"}"},
		{"trailing second json value", "application/json", "{\"model_ids\":[\"model-a\"]} {\"model_ids\":[\"model-b\"]}"},
		{"body larger than sixteen kibibytes", "application/json", "{\"model_ids\":[\"" + strings.Repeat("a", (16<<10)+1) + "\"]}"},
	}
	user := &repository.User{ID: "user-1", TenantID: "tenant-auth"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			modelRepo := &MockModelRepository{}
			recorder := performModelBatchDelete(tc.body, tc.contentType, user, modelRepo, nil)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			if modelRepo.DeleteBatchCalls != 0 {
				t.Fatalf("DeleteBatch calls = %d, want 0", modelRepo.DeleteBatchCalls)
			}
		})
	}
}

func TestBatchDeleteModelsFailsClosedWithoutDeletePermission(t *testing.T) {
	denied := newModelBatchDeletePermissionAuthorizer()
	denied.allowed = false
	failed := newModelBatchDeletePermissionAuthorizer()
	failed.err = errors.New("permission database exposed internal detail")

	cases := []struct {
		name       string
		authorizer PermissionAuthorizer
		wantCode   string
		leakNeedle string
	}{
		{"checker missing", nil, "permission_check_failed", ""},
		{"delete permission denied", denied, "permission_denied", ""},
		{"permission check error", failed, "permission_check_failed", "permission database"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			modelRepo := &MockModelRepository{}
			recorder := performModelBatchDeleteWithPermission(
				"{\"model_ids\":[\"model-a\"]}",
				"application/json",
				&repository.User{ID: "user-no-delete", TenantID: "tenant-auth"},
				modelRepo,
				tc.authorizer,
				nil,
			)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
			}
			code, _ := decodeModelBatchDeleteError(t, recorder)
			if code != tc.wantCode {
				t.Fatalf("error code = %q, want %q", code, tc.wantCode)
			}
			if tc.leakNeedle != "" && strings.Contains(recorder.Body.String(), tc.leakNeedle) {
				t.Fatalf("response leaks permission checker error: %s", recorder.Body.String())
			}
			if modelRepo.DeleteBatchCalls != 0 {
				t.Fatalf("DeleteBatch calls = %d, want 0", modelRepo.DeleteBatchCalls)
			}
		})
	}
}

func TestBatchDeleteModelsReturnsUniformNotFoundForUnavailableModels(t *testing.T) {
	modelRepo := &MockModelRepository{DeleteBatchErr: fmt.Errorf("ownership validation failed: %w", repository.ErrModelsUnavailable)}
	recorder := performModelBatchDelete(
		"{\"model_ids\":[\"model-a\",\"model-other-tenant\"]}",
		"application/json",
		&repository.User{ID: "user-1", TenantID: "tenant-auth"},
		modelRepo,
		nil,
	)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
	code, message := decodeModelBatchDeleteError(t, recorder)
	if code != "not_found" || message != "model not found or not owned" {
		t.Fatalf("error = (%q, %q), want uniform not_found response", code, message)
	}
	if strings.Contains(recorder.Body.String(), "other-tenant") || strings.Contains(recorder.Body.String(), "ownership validation") {
		t.Fatalf("response leaks availability detail: %s", recorder.Body.String())
	}
}

func TestBatchDeleteModelsReturnsInternalErrorForUnexpectedRepositoryFailure(t *testing.T) {
	modelRepo := &MockModelRepository{DeleteBatchErr: errors.New("database connection included a secret")}
	recorder := performModelBatchDelete(
		"{\"model_ids\":[\"model-a\"]}",
		"application/json",
		&repository.User{ID: "user-1", TenantID: "tenant-auth"},
		modelRepo,
		nil,
	)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusInternalServerError, recorder.Body.String())
	}
	code, _ := decodeModelBatchDeleteError(t, recorder)
	if code != "internal_error" {
		t.Fatalf("error code = %q, want internal_error", code)
	}
	if strings.Contains(recorder.Body.String(), "database connection") || strings.Contains(recorder.Body.String(), "secret") {
		t.Fatalf("response leaks repository error: %s", recorder.Body.String())
	}
}

func TestBatchDeleteModelsUsesAuthenticatedTenantReturnsCountsAndAudits(t *testing.T) {
	modelIDs := []string{"model-b", "model-a"}
	modelRepo := &MockModelRepository{
		DeleteBatchResult: repository.ModelBatchDeleteResult{Requested: 2, Deleted: 1, Disabled: 1, Failed: 0},
	}
	auditRepo := &modelBatchDeleteAuditRepo{}
	permissionChecker := newModelBatchDeletePermissionAuthorizer()
	recorder := performModelBatchDeleteWithPermission(
		"{\"model_ids\":[\"model-b\",\"model-a\"]}",
		"application/json; charset=utf-8",
		&repository.User{ID: "user-1", TenantID: "tenant-from-auth"},
		modelRepo,
		permissionChecker,
		auditRepo,
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if got, want := recorder.Header().Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("Content-Type = %q, want %q", got, want)
	}
	if got, want := recorder.Body.String(), "{\"requested\":2,\"deleted\":1,\"disabled\":1,\"failed\":0}\n"; got != want {
		t.Fatalf("response body = %q, want %q", got, want)
	}
	if modelRepo.DeleteBatchCalls != 1 || modelRepo.DeleteBatchTenantID != "tenant-from-auth" {
		t.Fatalf("DeleteBatch call contract = (%d, %q), want (1, tenant-from-auth)", modelRepo.DeleteBatchCalls, modelRepo.DeleteBatchTenantID)
	}
	if !reflect.DeepEqual(modelRepo.DeleteBatchIDs, modelIDs) {
		t.Fatalf("DeleteBatch IDs = %#v, want %#v", modelRepo.DeleteBatchIDs, modelIDs)
	}
	wantPermissionCall := modelBatchDeletePermissionCall{
		userID:    "user-1",
		tenantID:  "tenant-from-auth",
		scopeType: "tenant",
		scopeID:   "tenant-from-auth",
		resource:  "models",
		action:    "delete",
	}
	if len(permissionChecker.calls) != 1 {
		t.Fatalf("permission calls = %d, want 1", len(permissionChecker.calls))
	}
	if got := permissionChecker.calls[0]; got != wantPermissionCall {
		t.Fatalf("permission call = %#v, want %#v", got, wantPermissionCall)
	}
	if auditRepo.calls != 1 || auditRepo.op == nil {
		t.Fatalf("audit calls = %d, operation = %#v; want one audit", auditRepo.calls, auditRepo.op)
	}
	if auditRepo.op.ActionType != "batch_delete_models" || auditRepo.op.TargetType != "model_batch" {
		t.Fatalf("audit action/target = (%q, %q)", auditRepo.op.ActionType, auditRepo.op.TargetType)
	}
	wantDetail := map[string]interface{}{
		"model_ids": modelIDs,
		"requested": 2,
		"deleted":   1,
		"disabled":  1,
		"failed":    0,
	}
	if !reflect.DeepEqual(auditRepo.op.ActionDetail, wantDetail) {
		t.Fatalf("audit detail = %#v, want %#v", auditRepo.op.ActionDetail, wantDetail)
	}
}
