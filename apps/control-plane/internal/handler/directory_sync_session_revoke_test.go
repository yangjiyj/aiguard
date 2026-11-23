package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryldap"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// recordingSessionStore records DeleteByUser calls (W2.5).
type recordingSessionStore struct {
	mu        sync.Mutex
	revoked   []string
	deleteErr error
}

func (*recordingSessionStore) Create(context.Context, *repository.Session) error { return nil }
func (*recordingSessionStore) Delete(context.Context, string) error              { return nil }
func (s *recordingSessionStore) DeleteByUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = append(s.revoked, userID)
	return s.deleteErr
}

func (s *recordingSessionStore) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.revoked...)
}

// W2.5: a full directory sync that deactivates a vanished account must revoke
// that account's console sessions, and must not touch accounts still present.
func TestDirectoryActivationRevokesSessionsOfDisabledUsers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		deleteErr error
	}{
		{name: "revoked"},
		{name: "revocation failure does not fail activation", deleteErr: errors.New("redis down")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, tenantID, sourceID, _ := setupDirectoryPreviewFixture(t)
			ctx := context.Background()

			goneUserID := "user_w25_gone_" + tenantID[len(tenantID)-6:]
			keptUserID := "user_w25_kept_" + tenantID[len(tenantID)-6:]
			for _, u := range []struct{ id, name, ext string }{
				{goneUserID, "w25gone", "w25-gone-ext"},
				{keptUserID, "w25kept", "w25-kept-ext"},
			} {
				if _, err := pool.Exec(ctx, `
					INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
					VALUES ($1, $2, $3::text, $3::text || '@x.test', 'x', 'developer', 'active')
				`, u.id, tenantID, u.name+tenantID[len(tenantID)-6:]); err != nil {
					t.Fatalf("insert user %s: %v", u.id, err)
				}
				if _, err := pool.Exec(ctx, `
					INSERT INTO directory_user_links (id, tenant_id, directory_source_id, external_object_id, source_dn, user_id)
					VALUES ($1, $2, $3, $4, $5, $6)
				`, "dul_"+u.id, tenantID, sourceID, u.ext, "cn="+u.name, u.id); err != nil {
					t.Fatalf("insert link %s: %v", u.id, err)
				}
			}

			lister := &fakeDirectoryLister{users: []directoryldap.DirectoryUser{
				{ObjectID: "w25-kept-ext", DN: "cn=w25kept", Username: "w25kept" + tenantID[len(tenantID)-6:], Email: "w25kept@x.test"},
			}}
			deps := directoryPreviewDeps(pool, lister)
			sessions := &recordingSessionStore{deleteErr: tc.deleteErr}
			deps.SessionRepo = sessions

			rr := httptest.NewRecorder()
			PreviewDirectorySource(deps).ServeHTTP(rr, newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/preview", tenantID, "u1", "{}"))
			if rr.Code != http.StatusOK {
				t.Fatalf("preview status=%d body=%s", rr.Code, rr.Body.String())
			}
			previewID, _ := parseJSONBody(t, rr)["data"].(map[string]any)["preview_id"].(string)

			req := newPreviewRequest(http.MethodPost, "/admin/v1/directory/sources/previews/"+previewID+"/activate", tenantID, "u1", "{\x22confirm\x22:true}")
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", previewID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			actRR := httptest.NewRecorder()
			ActivateDirectoryPreview(deps).ServeHTTP(actRR, req)
			if actRR.Code != http.StatusOK {
				t.Fatalf("activate status=%d body=%s", actRR.Code, actRR.Body.String())
			}

			var status string
			if err := pool.QueryRow(ctx, `SELECT status FROM users WHERE id=$1`, goneUserID).Scan(&status); err != nil || status != "disabled" {
				t.Fatalf("gone user status=%q err=%v, want disabled", status, err)
			}
			got := sessions.calls()
			if len(got) != 1 || got[0] != goneUserID {
				t.Fatalf("DeleteByUser calls=%v, want exactly [%s]", got, goneUserID)
			}
		})
	}
}

// W2.5: nothing to revoke when the sync disables nobody, and a missing
// session store is tolerated.
func TestRevokeDirectoryDisabledSessions(t *testing.T) {
	if failed := revokeDirectoryDisabledSessions(context.Background(), &Dependencies{}, []string{"u1"}); failed != nil {
		t.Fatalf("nil SessionRepo failed=%v", failed)
	}
	store := &recordingSessionStore{}
	if failed := revokeDirectoryDisabledSessions(context.Background(), &Dependencies{SessionRepo: store}, nil); failed != nil || len(store.calls()) != 0 {
		t.Fatalf("empty ids: failed=%v calls=%v", failed, store.calls())
	}
	store.deleteErr = errors.New("boom")
	failed := revokeDirectoryDisabledSessions(context.Background(), &Dependencies{SessionRepo: store}, []string{"a", "b"})
	if len(failed) != 2 || failed[0] != "a" || failed[1] != "b" {
		t.Fatalf("failed=%v want [a b]", failed)
	}
}
