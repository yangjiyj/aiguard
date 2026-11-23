package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReviewPortalUploadPagesThroughChi(t *testing.T) {
	db, tenant, user := setupOrgHandlerPool(t)
	ctx := context.Background()
	repo := repository.NewPortalUploadEventRepository(db)
	t.Cleanup(func() { _, _ = db.Exec(ctx, "DELETE FROM portal_upload_events WHERE tenant_id=$1", tenant) })
	for i := 0; i < 6; i++ {
		err := repo.Insert(ctx, repository.PortalUploadEvent{ID: fmt.Sprintf("%s-event-%d", user, i), TenantID: tenant, UserID: user, Filename: "same.txt", MimeType: "text/plain", Size: 1, SHA256: "same", CreatedAt: time.Now().Add(time.Duration(-i) * time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
	}
	router := chi.NewRouter()
	router.Get("/admin/v1/portal-integration/upload-events", ListPortalUploadEvents(&Dependencies{PortalUploadEventRepo: repo}))
	server := httptest.NewServer(router)
	defer server.Close()
	seen := map[string]bool{}
	for page := 0; page < 3; page++ {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/admin/v1/portal-integration/upload-events?user_id=%s&limit=2&cursor=%d", server.URL, user, page*2), nil)
		req.Header.Set("X-JJDGuard-Tenant-Id", tenant)
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Data  []struct{ ID string }
			Total int
		}
		err = json.NewDecoder(res.Body).Decode(&body)
		res.Body.Close()
		if err != nil || res.StatusCode != 200 || body.Total != 6 || len(body.Data) != 2 {
			t.Fatalf("page=%d status=%d total=%d rows=%d err=%v", page, res.StatusCode, body.Total, len(body.Data), err)
		}
		for _, row := range body.Data {
			if seen[row.ID] {
				t.Fatalf("page %d repeated %s", page, row.ID)
			}
			seen[row.ID] = true
		}
	}
}
