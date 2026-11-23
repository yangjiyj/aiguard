package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReviewMergeAndRebindInvalidateOIDCAndStalePreview(t *testing.T) {
	for _, operation := range []string{"merge", "rebind"} {
		t.Run(operation, func(t *testing.T) {
			db, tenant, actor := setupOrgHandlerPool(t)
			ctx := context.Background()
			dept := ensureDepartment(t, db, tenant, "Merge evidence")
			source, target, link := tenant+"_source", tenant+"_target", tenant+"_link"
			for _, id := range []string{source, target} {
				mustExec(t, db, "INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode) VALUES($1,$2,$1,'chat_user','active',$3,'manual')", id, tenant, dept)
			}
			mustExec(t, db, "INSERT INTO user_identity_links(id,tenant_id,user_id,issuer,source_type,external_subject) VALUES($1,$2,$3,'https://review-idp.test','oidc','review-subject')", link, tenant, source)
			t.Cleanup(func() {
				db.Exec(ctx, "DELETE FROM user_account_merges WHERE tenant_id=$1", tenant)
				db.Exec(ctx, "DELETE FROM user_identity_links WHERE tenant_id=$1", tenant)
			})
			repo := repository.NewUserAccountMergeRepository(db)
			deps := &Dependencies{UserRepo: repository.NewUserRepository(db), TeamModelRepo: repository.NewTeamModelRepository(db), UserIdentityLinkLookup: repository.NewUserIdentityLinkRepository(db), UserAccountMergeRepo: repo}
			deps.IdentityRuntimeConfig.IssuerURL = "https://review-idp.test"
			if w := boundPortalContext(deps, tenant, source, "review-subject"); w.Code != 200 {
				t.Fatalf("pre-operation OIDC status=%d", w.Code)
			}
			p, err := repo.Preview(ctx, tenant, source, target, actor)
			if err != nil {
				t.Fatal(err)
			}
			mustExec(t, db, "UPDATE users SET local_credential_version=local_credential_version+1 WHERE id=$1", source)
			stale := httptest.NewRecorder()
			payload, _ := json.Marshal(map[string]any{"source_user_id": source, "preview_version": p.Version})
			request := userModelRequest("POST", tenant, actor, "platform_admin", target, string(payload))
			AccountMerge(deps, false)(stale, request)
			if stale.Code != 409 {
				t.Fatalf("stale preview status=%d", stale.Code)
			}
			p, err = repo.Preview(ctx, tenant, source, target, actor)
			if err != nil {
				t.Fatal(err)
			}
			if operation == "merge" {
				if _, err := repo.Merge(ctx, tenant, source, target, actor, repository.AccountMergeInput{PreviewVersion: p.Version}); err != nil {
					t.Fatal(err)
				}
			} else {
				router := chi.NewRouter()
				router.Post("/users/{id}/identity-links/{link_id}/rebind", RebindUserIdentity(deps))
				body, _ := json.Marshal(map[string]string{"target_user_id": target, "preview_version": p.Version})
				req := httptest.NewRequest("POST", "/users/"+source+"/identity-links/"+link+"/rebind", strings.NewReader(string(body)))
				req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: actor, TenantID: tenant, Role: "platform_admin"}))
				req.RemoteAddr = "198.51.100.33:1234"
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if w.Code != 200 {
					t.Fatalf("rebind status=%d", w.Code)
				}
				var audits int
				if err := db.QueryRow(ctx, "SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND action_type='user.identity.rebound' AND user_id=$2 AND ip_address='198.51.100.33'", tenant, actor).Scan(&audits); err != nil || audits != 1 {
					t.Fatalf("rebind audits=%d err=%v", audits, err)
				}
			}
			if w := boundPortalContext(deps, tenant, source, "review-subject"); w.Code != 404 {
				t.Fatalf("old OIDC source survives %s: %d", operation, w.Code)
			}
			if w := boundPortalContext(deps, tenant, target, "review-subject"); w.Code != 200 {
				t.Fatalf("new OIDC owner missing %s: %d", operation, w.Code)
			}
			foreign := httptest.NewRecorder()
			AccountMerge(deps, true)(foreign, userModelRequest("POST", tenant, actor, "platform_admin", "foreign-target", "{\"source_user_id\":\"foreign-source\"}"))
			if foreign.Code != 404 {
				t.Fatalf("legal actor foreign identities=%d", foreign.Code)
			}
		})
	}
}
