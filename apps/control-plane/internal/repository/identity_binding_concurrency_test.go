package repository

import (
	"context"
	"sync"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
)

func TestIdentityBindingServiceConcurrentBindAndResolveHasOneCommittedWinner(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	service := identitybinding.NewService(NewUserIdentityLinkRepository(db))
	identity := identitybinding.ExternalIdentity{
		TenantID:        tenantID,
		Issuer:          "https://issuer.concurrent.example",
		SourceID:        "source-concurrent",
		SourceType:      "oidc",
		ExternalSubject: "subject-concurrent",
		Username:        "concurrent-user",
		Email:           "concurrent@example.local",
	}

	const workers = 8
	start := make(chan struct{})
	results := make(chan identitybinding.Resolution, workers)
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			resolution, err := service.BindAndResolve(ctx, identity)
			results <- resolution
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	winnerUserID := ""
	for result := range results {
		if winnerUserID == "" {
			winnerUserID = result.UserID
		}
		if result.UserID != winnerUserID {
			t.Fatalf("winner changed from %s to %s", winnerUserID, result.UserID)
		}
	}
	if winnerUserID == "" {
		t.Fatal("no committed winner")
	}

	for table, want := range map[string]int{
		"users":                              1,
		"user_identity_links":                1,
		"audit_operations":                   1,
		"identity_cache_invalidation_outbox": 1,
	} {
		var count int
		query := "SELECT COUNT(*) FROM " + table + " WHERE tenant_id=$1"
		if err := db.QueryRow(ctx, query, tenantID).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != want {
			t.Fatalf("%s count=%d, want %d", table, count, want)
		}
	}
}
