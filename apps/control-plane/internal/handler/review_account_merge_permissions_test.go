package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReviewAccountMergeHandlerPermissions(t *testing.T) {
	db, tenant, admin := setupOrgHandlerPool(t)
	ctx := context.Background()
	actor, source, target := tenant+"_actor", tenant+"_source", tenant+"_target"
	for _, v := range []struct{ id, role string }{{actor, "tenant_admin"}, {source, "chat_user"}, {target, "chat_user"}} {
		if _, err := db.Exec(ctx, "INSERT INTO users(id,tenant_id,username,role,status,department_assignment_mode) VALUES($1,$2,$1,$3,'active','manual')", v.id, tenant, v.role); err != nil {
			t.Fatal(err)
		}
	}
	repo := repository.NewUserAccountMergeRepository(db)
	router := chi.NewRouter()
	router.Post("/users/{id}/identity-links/{link_id}/rebind", RebindUserIdentity(&Dependencies{UserAccountMergeRepo: repo}))
	router.Post("/users/{id}/merge-preview", AccountMerge(&Dependencies{UserAccountMergeRepo: repo}, true))
	call := func(actorID, role, sourceID, targetID string) int {
		payload, _ := json.Marshal(map[string]string{"source_user_id": sourceID})
		req := httptest.NewRequest(http.MethodPost, "/users/"+targetID+"/merge-preview", bytes.NewReader(payload))
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: actorID, TenantID: tenant, Role: role}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}
	t.Run("rebind_requires_preview", func(t *testing.T) {
		link := tenant + "_link"
		if _, err := db.Exec(ctx, "INSERT INTO user_identity_links(id,tenant_id,user_id,issuer,source_type,external_subject) VALUES($1,$2,$3,'https://idp.test','oidc','review-subject')", link, tenant, source); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Exec(ctx, "DELETE FROM user_identity_links WHERE tenant_id=$1", tenant) })
		payload, _ := json.Marshal(map[string]string{"target_user_id": target})
		req := httptest.NewRequest("POST", "/users/"+source+"/identity-links/"+link+"/rebind", bytes.NewReader(payload))
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: actor, TenantID: tenant, Role: "tenant_admin"}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != 409 {
			t.Fatalf("missing preview status=%d", w.Code)
		}
	})
	t.Run("non_admin_403", func(t *testing.T) {
		if code := call(source, "chat_user", source, target); code != 403 {
			t.Fatalf("status=%d", code)
		}
	})
	for _, role := range []string{"security_officer", "auditor", "tenant_admin", "dept_manager", "platform_admin", "admin"} {
		for _, id := range []string{source, target} {
			t.Run(role+"_"+id, func(t *testing.T) {
				if _, err := db.Exec(ctx, "UPDATE users SET role=$2 WHERE id=$1", id, role); err != nil {
					t.Fatal(err)
				}
				if code := call(actor, "tenant_admin", source, target); code != 403 {
					t.Errorf("privileged identity accepted: status=%d", code)
				}
				db.Exec(ctx, "UPDATE users SET role='chat_user' WHERE id=$1", id)
			})
		}
	}
	t.Run("self_target_403", func(t *testing.T) {
		if code := call(actor, "tenant_admin", source, actor); code != 403 {
			t.Fatalf("status=%d", code)
		}
	})
	t.Run("platform_self_403", func(t *testing.T) {
		if code := call(admin, "platform_admin", source, admin); code != 403 {
			t.Fatalf("status=%d", code)
		}
	})
}
