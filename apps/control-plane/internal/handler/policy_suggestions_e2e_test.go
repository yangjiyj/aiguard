package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestPolicySuggestionsHTTPPostGetApproveReject(t *testing.T) {
	dsn := os.Getenv("POLICY_SUGGESTIONS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("POLICY_SUGGESTIONS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const tenantID = "tenant_default"
	if _, err := db.Exec(ctx, `DELETE FROM policy_suggestions WHERE tenant_id=$1 AND external_id LIKE 'e2e-%'`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM rules WHERE rule_set_id IN (SELECT id FROM rule_sets WHERE tenant_id=$1 AND name='LSE 策略建议')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM rule_sets WHERE tenant_id=$1 AND name='LSE 策略建议'`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES($1,'Default','enterprise','active') ON CONFLICT DO NOTHING`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role,status) VALUES('ps_e2e_admin',$1,'ps_e2e_admin','platform_admin','active') ON CONFLICT DO NOTHING`, tenantID); err != nil {
		t.Fatal(err)
	}
	deps := &Dependencies{DB: db, RuleSetRepo: repository.NewRuleSetRepository(db), RuleRepo: repository.NewRuleRepository(db), SystemRepo: repository.NewSystemRepository(db)}
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if strings.HasPrefix(req.URL.Path, "/admin/v1/policy-suggestions") {
				req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "ps_e2e_admin", TenantID: tenantID, Role: "platform_admin"}))
			}
			next.ServeHTTP(w, req)
		})
	})
	r.Post("/admin/v1/eval-integration/policy-suggestions", CreateEvalIntegrationPolicySuggestion(deps))
	r.Get("/admin/v1/eval-integration/policy-suggestions/{id}", GetEvalIntegrationPolicySuggestion(deps))
	r.Get("/admin/v1/policy-suggestions", ListPolicySuggestions(deps))
	r.Post("/admin/v1/policy-suggestions/{id}/approve", ReviewPolicySuggestion(deps, true))
	r.Post("/admin/v1/policy-suggestions/{id}/reject", ReviewPolicySuggestion(deps, false))
	srv := httptest.NewServer(r)
	defer srv.Close()
	client := srv.Client()
	call := func(method, path, body string, integration bool) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if integration {
			req.Header.Set(evalIntegrationTenantHeader, tenantID)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var result map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&result)
		return resp.StatusCode, result
	}
	post := `{"external_id":"e2e-approve","source":"lse","type":"sensitive_data","action":"block","payload":{"regex":"secret[0-9]+"}}`
	status, created := call(http.MethodPost, "/admin/v1/eval-integration/policy-suggestions", post, true)
	if status != http.StatusOK {
		t.Fatalf("post status=%d body=%v", status, created)
	}
	status, duplicate := call(http.MethodPost, "/admin/v1/eval-integration/policy-suggestions", post, true)
	if status != http.StatusOK || duplicate["id"] != created["id"] {
		t.Fatalf("idempotent post status=%d body=%v initial=%v", status, duplicate, created)
	}
	id := created["id"].(string)
	status, pending := call(http.MethodGet, "/admin/v1/eval-integration/policy-suggestions/"+id, "", true)
	if status != http.StatusOK || pending["status"] != "pending_approval" {
		t.Fatalf("pending get status=%d body=%v", status, pending)
	}
	status, list := call(http.MethodGet, "/admin/v1/policy-suggestions", "", false)
	if status != http.StatusOK || list["total"].(float64) < 1 {
		t.Fatalf("list status=%d body=%v", status, list)
	}
	status, approved := call(http.MethodPost, "/admin/v1/policy-suggestions/"+id+"/approve", `{}`, false)
	if status != http.StatusOK || approved["status"] != "published" || approved["rule_set_version"] == nil {
		t.Fatalf("approve status=%d body=%v", status, approved)
	}
	status, published := call(http.MethodGet, "/admin/v1/eval-integration/policy-suggestions/e2e-approve", "", true)
	if status != http.StatusOK || published["status"] != "published" || published["rule_set_version"] == nil {
		t.Fatalf("published get status=%d body=%v", status, published)
	}
	rejectBody := `{"external_id":"e2e-reject","source":"lse","type":"sensitive_data","action":"alert","payload":{"keywords":["credential"]}}`
	status, rejectedItem := call(http.MethodPost, "/admin/v1/eval-integration/policy-suggestions", rejectBody, true)
	if status != http.StatusOK {
		t.Fatalf("reject setup status=%d body=%v", status, rejectedItem)
	}
	rejectID := rejectedItem["id"].(string)
	status, rejected := call(http.MethodPost, "/admin/v1/policy-suggestions/"+rejectID+"/reject", `{"review_note":"reviewed and rejected"}`, false)
	if status != http.StatusOK || rejected["status"] != "rejected" {
		t.Fatalf("reject status=%d body=%v", status, rejected)
	}
	status, rejectedQuery := call(http.MethodGet, "/admin/v1/eval-integration/policy-suggestions/"+rejectID, "", true)
	if status != http.StatusOK || rejectedQuery["status"] != "rejected" {
		t.Fatalf("rejected get status=%d body=%v", status, rejectedQuery)
	}
	unsupportedBody := `{"external_id":"e2e-unsupported","source":"lse","type":"tool_call_limit","action":"block","payload":{"keywords":["delete_file"]}}`
	status, unsupportedItem := call(http.MethodPost, "/admin/v1/eval-integration/policy-suggestions", unsupportedBody, true)
	if status != http.StatusOK {
		t.Fatalf("unsupported setup status=%d body=%v", status, unsupportedItem)
	}
	status, unsupported := call(http.MethodPost, "/admin/v1/policy-suggestions/"+unsupportedItem["id"].(string)+"/approve", `{}`, false)
	errObj, _ := unsupported["error"].(map[string]any)
	if status != http.StatusUnprocessableEntity || errObj["code"] != "unsupported_suggestion_type" {
		t.Fatalf("unsupported approve status=%d body=%v", status, unsupported)
	}
}
