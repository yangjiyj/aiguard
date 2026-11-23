package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestPortalCreateRestrictedKeyRejectsUnauthorizedModels(t *testing.T) {
	deps, db, tenant, user, project := portalProjectFixture(t)
	ctx := context.Background()
	mustExec(t, db, "UPDATE teams SET model_access_mode='all_active',model_access_configured=true WHERE id=(SELECT department_id FROM users WHERE id=$1)", user)
	provider, _ := wtProviderModels(t, db, tenant, "model-approved")
	t.Cleanup(func() {
		db.Exec(ctx, "DELETE FROM models WHERE provider_id=$1", provider)
		db.Exec(ctx, "DELETE FROM providers WHERE id=$1", provider)
	})
	create := func(models []string) *httptest.ResponseRecorder {
		encoded, _ := json.Marshal(models)
		body := fmt.Sprintf(`{"project_id":%q,"user_id":%q,"name":"受限 Key","scopes":["chat","models"],"model_allowlist":%s}`, project, user, encoded)
		w := httptest.NewRecorder()
		CreatePortalKey(deps)(w, userSyncReq(http.MethodPost, "/x", tenant, body))
		return w
	}
	denied := create([]string{"model-outside"})
	if denied.Code != 403 || !strings.Contains(denied.Body.String(), "key_model_not_authorized") {
		t.Fatalf("unauthorized configuration status=%d", denied.Code)
	}
	allowed := create([]string{"model-approved"})
	if allowed.Code != 200 {
		t.Fatalf("create status=%d", allowed.Code)
	}
	var reply struct {
		ID             string   `json:"id"`
		ModelAllowlist []string `json:"model_allowlist"`
	}
	if err := json.Unmarshal(allowed.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	stored, err := deps.KeyRepo.GetByID(ctx, tenant, reply.ID)
	if err != nil || stored == nil || len(stored.ModelAllowlist) != 1 || stored.ModelAllowlist[0] != "model-approved" {
		t.Fatal("model limits not saved")
	}
}

func TestPortalConcurrentCreateCannotBypassActiveKeyLimit(t *testing.T) {
	deps, db, tenant, user, project := portalProjectFixture(t)
	const workers = 8
	start := make(chan struct{})
	results := make(chan int, workers)
	var wait sync.WaitGroup
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			w := httptest.NewRecorder()
			CreatePortalKey(deps)(w, userSyncReq(http.MethodPost, "/x", tenant, fmt.Sprintf(`{"user_id":%q,"project_id":%q,"name":"concurrent","scopes":["chat","models"]}`, user, project)))
			results <- w.Code
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	created := 0
	for status := range results {
		if status == 200 {
			created++
		} else if status != 409 {
			t.Fatalf("unexpected create status=%d", status)
		}
	}
	var active int
	if err := db.QueryRow(context.Background(), "SELECT count(*) FROM internal_keys WHERE tenant_id=$1 AND user_id=$2 AND status='active'", tenant, user).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 5 || created != 5 {
		t.Fatalf("concurrent create bypassed limit: created=%d active=%d", created, active)
	}
}
