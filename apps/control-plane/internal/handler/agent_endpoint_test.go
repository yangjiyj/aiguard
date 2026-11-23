package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	entlicense "github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestResolveRejectsNonHexHashBeforeRepository(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/resolve", strings.NewReader(`{"token_hash":"`+strings.Repeat("z", 64)+`"}`))
	w := httptest.NewRecorder()
	(&AgentEndpointAPI{}).Resolve(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRegisterRequestUsesStrictTypedDTO(t *testing.T) {
	body := `{"machine_id":"m","hostname":"h","os":"linux","arch":"amd64","agent_product":"claude-code","extra":true}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer enrollment")
	w := httptest.NewRecorder()
	(&AgentEndpointAPI{}).Register(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestAgentInternalLicenseStatusUsesVerifiedFeature(t *testing.T) {
	token, keys := signedV2HandlerLicense(t, func(payload *entlicense.PayloadV2) {
		payload.Features = []string{"agent_security"}
	})
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", keys)
	settings := &licenseSystemRepo{settings: map[string]string{LicenseSettingKey: token}}
	api := &AgentEndpointAPI{Deps: &Dependencies{SystemRepo: settings}}
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/agent/license-status", nil)
	for _, tt := range []struct {
		name, raw string
		expected  bool
	}{
		{"valid agent feature", token, true},
		{"tampered signature", token + "!", false},
		{"missing license", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			settings.settings[LicenseSettingKey] = tt.raw
			w := httptest.NewRecorder()
			api.LicenseStatus(w, request)
			var result struct {
				Licensed bool `json:"licensed"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != http.StatusOK || result.Licensed != tt.expected {
				t.Fatalf("status=%d licensed=%v error=%v", w.Code, result.Licensed, err)
			}
		})
	}
}

func TestAgentEndpointAuthFailsClosedWithoutLicense(t *testing.T) {
	deps := &Dependencies{SystemRepo: &licenseSystemRepo{settings: map[string]string{}}}
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/agent/policy-bundle", nil)
	licensed, err := agentSecurityLicensed(request, deps)
	if err != nil || licensed {
		t.Fatalf("missing license licensed=%v error=%v", licensed, err)
	}
	_, err = agentSecurityLicensed(request, nil)
	if err == nil {
		t.Fatal("missing system repository must fail closed")
	}
}

func TestAgentRegistrationRejectsValidRequestWithoutLicense(t *testing.T) {
	api := &AgentEndpointAPI{Deps: &Dependencies{SystemRepo: &licenseSystemRepo{settings: map[string]string{}}}}
	r := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/endpoints/register", strings.NewReader(`{"machine_id":"m","hostname":"h","os":"linux","arch":"amd64","agent_product":"claude-code"}`))
	r.Header.Set("Authorization", "Bearer enrollment")
	w := httptest.NewRecorder()
	api.Register(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AGENT_UNLICENSED") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAgentEndpointRegisterAndHeartbeatReturnCurrentPolicy(t *testing.T) {
	dsn := os.Getenv("AGENT_ENDPOINT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENT_ENDPOINT_TEST_DATABASE_URL is not set")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ctx := context.Background()
	var database string
	if err := db.QueryRow(ctx, `SELECT current_database()`).Scan(&database); err != nil {
		t.Fatal(err)
	}
	if database != "jjdguard_dev" {
		t.Fatalf("refusing non-development database %q", database)
	}

	id := uuid.NewString()
	tenantID := "aeht-" + id
	enrollmentID := "agent-endpoint-handler-test-enrollment-" + id
	enrollmentToken := "agent-endpoint-handler-test-token-" + id
	_, err = db.Exec(ctx, `INSERT INTO agent_enrollment_tokens
		(id,tenant_id,name,token_hash,token_prefix,default_mode,allowed_products,max_endpoints)
		VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,1)`,
		enrollmentID, tenantID, "test", repository.HashAgentToken(enrollmentToken), "test", "monitor", `["claude-code"]`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM tool_risk_config WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM agent_endpoints WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM agent_policy_bundles WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM agent_enrollment_tokens WHERE id=$1`, enrollmentID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	license, keys := signedV2HandlerLicense(t, func(payload *entlicense.PayloadV2) {
		payload.Features = []string{"agent_security"}
	})
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", keys)
	api := &AgentEndpointAPI{Repo: repository.NewAgentEndpointRepository(db), Deps: &Dependencies{
		SystemRepo: &licenseSystemRepo{settings: map[string]string{LicenseSettingKey: license}},
	}}
	register := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/endpoints/register",
		strings.NewReader(`{"machine_id":"m","hostname":"h","os":"linux","arch":"amd64","agent_product":"claude-code"}`))
	register.Header.Set("Authorization", "Bearer "+enrollmentToken)
	registration := httptest.NewRecorder()
	api.Register(registration, register)
	if registration.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", registration.Code, registration.Body.String())
	}
	var registered struct {
		EndpointID    string `json:"endpoint_id"`
		EndpointToken string `json:"endpoint_token"`
		Policy        struct {
			Version  int64  `json:"version"`
			Checksum string `json:"checksum"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(registration.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}
	current, err := api.Repo.Policy(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if registered.Policy.Version < 1 || registered.Policy.Version != current["version"] || registered.Policy.Checksum != current["checksum"] || registered.Policy.Checksum == "sha256:"+strings.Repeat("0", 64) {
		t.Fatalf("register policy=%+v current version=%v checksum=%v", registered.Policy, current["version"], current["checksum"])
	}

	newHeartbeat := func() *http.Request {
		request := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/endpoints/heartbeat",
			strings.NewReader(`{"endpoint_id":"`+registered.EndpointID+`","policy_version":0,"config_version":1,"health":{}}`))
		return request.WithContext(contextWithEndpoint(request.Context(), &repository.AgentEndpointContext{
			TenantID: tenantID, EndpointID: registered.EndpointID, Mode: "monitor", CaptureLevel: "metadata", PolicyVersion: 0,
		}))
	}
	response := httptest.NewRecorder()
	api.Heartbeat(response, newHeartbeat())
	if response.Code != http.StatusOK {
		t.Fatalf("heartbeat status=%d body=%s", response.Code, response.Body.String())
	}
	var heartbeated struct {
		Policy struct {
			Version  int64  `json:"version"`
			Checksum string `json:"checksum"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &heartbeated); err != nil {
		t.Fatal(err)
	}
	if heartbeated.Policy.Version != registered.Policy.Version || heartbeated.Policy.Checksum != registered.Policy.Checksum {
		t.Fatalf("heartbeat policy=%+v register policy=%+v", heartbeated.Policy, registered.Policy)
	}

	if _, err := db.Exec(ctx, `INSERT INTO tenants (id,name,edition,status,is_test) VALUES ($1,$2,$3,$4,true)`, tenantID, tenantID, "enterprise", "active"); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `INSERT INTO tool_risk_config(id,tenant_id,tool_name,tool_type,risk_level,action)
		VALUES($1,$2,$3,$4,$5,$6)`, "tr_"+id[:20], tenantID, "invalid", "unsupported", "medium", "audit")
	if err != nil {
		t.Fatal(err)
	}
	retry := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/endpoints/register",
		strings.NewReader(`{"machine_id":"m","hostname":"h","os":"linux","arch":"amd64","agent_product":"claude-code"}`))
	retry.Header.Set("Authorization", "Bearer "+enrollmentToken)
	registrationError := httptest.NewRecorder()
	api.Register(registrationError, retry)
	if registrationError.Code != http.StatusOK {
		t.Fatalf("register policy error status=%d body=%s", registrationError.Code, registrationError.Body.String())
	}
	var rotated struct {
		EndpointID    string `json:"endpoint_id"`
		EndpointToken string `json:"endpoint_token"`
		Policy        struct {
			Version     int64  `json:"version"`
			Checksum    string `json:"checksum"`
			SyncPending bool   `json:"sync_pending"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(registrationError.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.EndpointID != registered.EndpointID || rotated.EndpointToken == "" || rotated.EndpointToken == registered.EndpointToken ||
		rotated.Policy.Version != 0 || rotated.Policy.Checksum != "sha256:"+strings.Repeat("0", 64) || !rotated.Policy.SyncPending {
		t.Fatalf("unsafe registration response: endpoint=%q token_present=%t rotated=%t policy=%+v", rotated.EndpointID,
			rotated.EndpointToken != "", rotated.EndpointToken != registered.EndpointToken, rotated.Policy)
	}
	resolved, err := api.Repo.Resolve(ctx, repository.HashAgentToken(rotated.EndpointToken))
	if err != nil || resolved == nil || resolved.EndpointID != rotated.EndpointID {
		t.Fatalf("returned token not usable: endpoint=%+v err=%v", resolved, err)
	}
	oldResolved, err := api.Repo.Resolve(ctx, repository.HashAgentToken(registered.EndpointToken))
	if err != nil || oldResolved != nil {
		t.Fatalf("old token unexpectedly active: endpoint=%+v err=%v", oldResolved, err)
	}
	heartbeatError := httptest.NewRecorder()
	api.Heartbeat(heartbeatError, newHeartbeat())
	if heartbeatError.Code != http.StatusInternalServerError {
		t.Fatalf("heartbeat policy error status=%d body=%s", heartbeatError.Code, heartbeatError.Body.String())
	}
	if _, err := db.Exec(ctx, `UPDATE tool_risk_config SET tool_type='system' WHERE tenant_id=$1 AND tool_name='invalid'`, tenantID); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	api.Heartbeat(response, newHeartbeat())
	if response.Code != http.StatusOK {
		t.Fatalf("heartbeat recovery status=%d body=%s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &heartbeated); err != nil {
		t.Fatal(err)
	}
	if heartbeated.Policy.Version <= registered.Policy.Version || heartbeated.Policy.Checksum == registered.Policy.Checksum {
		t.Fatalf("heartbeat did not publish recovered policy: %+v", heartbeated.Policy)
	}
}
