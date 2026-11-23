package handler

import (
	"context"
	"encoding/json"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"net/http"
	"net/http/httptest"
	"testing"
)

type credentialContractStore struct {
	IntegrationRepo
	key         ai.Credential
	tenant      string
	updateCalls int
}

func (s *credentialContractStore) IssueCredential(_ context.Context, tenant string, input ai.Credential, raw, replaced string) (*ai.Credential, error) {
	s.tenant = tenant
	if replaced == "" {
		s.key = input
		s.key.KeyID = "key1"
		s.key.Status = "active"
		if s.key.Enforcement == "" {
			s.key.Enforcement = "record"
		}
		if s.key.DLPEnforcement == "" {
			s.key.DLPEnforcement = "record"
		}
	}
	s.key.ResolveEnforcement()
	return &s.key, nil
}
func (s *credentialContractStore) GetCredential(_ context.Context, tenant, id string) (*ai.Credential, error) {
	s.tenant = tenant
	if id != s.key.KeyID {
		return nil, ai.ErrNotFound
	}
	s.key.ResolveEnforcement()
	return &s.key, nil
}
func (s *credentialContractStore) ListCredentials(_ context.Context, tenant, agent string) ([]ai.Credential, error) {
	s.tenant = tenant
	s.key.ResolveEnforcement()
	return []ai.Credential{s.key}, nil
}
func (s *credentialContractStore) RevokeCredential(ctx context.Context, tenant, id string) (*ai.Credential, error) {
	key, err := s.GetCredential(ctx, tenant, id)
	if err == nil {
		key.Status = "revoked"
	}
	return key, err
}
func (s *credentialContractStore) UpdateCredential(_ context.Context, tenant, id string, u ai.CredentialUpdate) (*ai.Credential, error) {
	s.tenant = tenant
	s.updateCalls++
	if u.Enforcement != nil {
		s.key.Enforcement = *u.Enforcement
	}
	if u.DLPEnforcement != nil {
		s.key.DLPEnforcement = *u.DLPEnforcement
	}
	if u.ModelAllowlist != nil {
		s.key.ModelAllowlist = *u.ModelAllowlist
	}
	s.key.ResolveEnforcement()
	return &s.key, nil
}

func TestCredentialHTTPContractAcrossLifecycle(t *testing.T) {
	t.Setenv("INTEGRATION_KEY_ENFORCEMENT", "record_only")
	store := &credentialContractStore{}
	deps := &Dependencies{IntegrationRepo: store}
	requests := []struct {
		method, path, body string
		handler            http.HandlerFunc
		status             int
		secret             bool
	}{
		{"POST", "/admin/v1/integration/agent-credentials", `{"agent_instance_id":"agent1","project_id":"proj","name":"测试凭据","scopes":["chat"],"model_restriction":"allowlist","model_allowlist":["模型甲"],"enforcement":"block","dlp_enforcement":"block"}`, IssueAgentCredential(deps), 201, true},
		{"GET", "/admin/v1/integration/agent-credentials?agent_instance_id=agent1", "", ListAgentCredentials(deps), 200, false},
		{"GET", "/admin/v1/integration/agent-credentials/key1", "", GetAgentCredential(deps), 200, false},
		{"PATCH", "/admin/v1/integration/agent-credentials/key1", `{"model_allowlist":["模型甲"],"enforcement":"block","dlp_enforcement":"block"}`, UpdateAgentCredential(deps), 200, false},
		{"POST", "/admin/v1/integration/agent-credentials/key1/rotate", `{}`, RotateAgentCredential(deps), 201, true},
		{"POST", "/admin/v1/integration/agent-credentials/key1/revoke", `{}`, RevokeAgentCredential(deps), 200, false},
	}
	for _, tc := range requests {
		w := httptest.NewRecorder()
		r := withPolicyID(policyHandlerRequest(tc.method, tc.path, tc.body, "platform_connector"), "key1")
		tc.handler(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
		var obj map[string]json.RawMessage
		json.Unmarshal(w.Body.Bytes(), &obj)
		_, secret := obj["full_key"]
		if secret != tc.secret {
			t.Fatal("一次性送达范围不正确")
		}
		if list, ok := obj["data"]; ok {
			var keys []map[string]json.RawMessage
			json.Unmarshal(list, &keys)
			obj = keys[0]
		}
		for _, name := range []string{"model_restriction", "model_allowlist", "enforcement", "effective_enforcement", "dlp_enforcement", "effective_dlp_enforcement", "enforcement_gate"} {
			if _, ok := obj[name]; !ok {
				t.Errorf("响应缺少 %s", name)
			}
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("凭据响应允许缓存")
		}
		if store.tenant != "tenant-a" {
			t.Fatal("未使用鉴权租户")
		}
	}
}

func TestCredentialPatchStrictFields(t *testing.T) {
	store := &credentialContractStore{}
	deps := &Dependencies{IntegrationRepo: store}
	for _, body := range []string{`{"model_restriction":"allowlist"}`, `{"tenant_id":"foreign"}`, `{"full_key":"fixture"}`, `{"model_allowlist":null}`, `{"enforcement":null}`, `{"dlp_enforcement":null}`, `{"enforcement":"record"} {}`} {
		w := httptest.NewRecorder()
		UpdateAgentCredential(deps)(w, withPolicyID(policyHandlerRequest("PATCH", "/", body, "platform_connector"), "key1"))
		if w.Code != 400 {
			t.Errorf("未拒绝非法字段 %s: %d", body, w.Code)
		}
	}
	if store.updateCalls != 0 {
		t.Fatal("非法请求到达存储层")
	}
	for _, role := range []string{"chat_user", "security_admin", "auditor"} {
		w := httptest.NewRecorder()
		GetAgentCredential(deps)(w, withPolicyID(policyHandlerRequest("GET", "/", "", role), "key1"))
		if w.Code != 403 {
			t.Fatalf("普通角色进入集成接口：%s %d", role, w.Code)
		}
	}
}
