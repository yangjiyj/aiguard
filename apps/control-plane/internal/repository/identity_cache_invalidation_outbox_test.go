package repository

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestIdentityCacheInvalidationOutboxDeadLetterAndProcessedCleanup(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	var deadLetterReady bool
	if err := db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_constraint
			WHERE conrelid='identity_cache_invalidation_outbox'::regclass
			  AND pg_get_constraintdef(oid) LIKE '%dead_letter%'
		)
	`).Scan(&deadLetterReady); err != nil {
		t.Fatal(err)
	}
	if !deadLetterReady {
		t.Skip("test database applied an intermediate migration 137 and must be rebuilt")
	}

	suffix := identityFixtureSuffix(tenantID)
	userID := "outbox-policy-user-" + suffix
	var unassignedID string
	if err := db.QueryRow(ctx, `
		SELECT id FROM teams WHERE tenant_id=$1 AND system_key='unassigned'
	`, tenantID).Scan(&unassignedID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO users (
			id,tenant_id,username,role,status,department_id,
			department_assignment_mode,department_assignment_source
		) VALUES ($1,$2,$1,'developer','active',$3,'unassigned','oidc')
	`, userID, tenantID, unassignedID); err != nil {
		t.Fatal(err)
	}

	eventID := "outbox-dead-letter-" + suffix
	if _, err := db.Exec(ctx, `
		INSERT INTO identity_cache_invalidation_outbox (
			id,tenant_id,user_id,attempt_count,next_attempt_at
		) VALUES ($1,$2,$3,9,NOW()-INTERVAL '1 day')
	`, eventID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	repo := NewUserIdentityLinkRepository(db)
	event, err := repo.ClaimNextInvalidation(ctx, "dead-letter-worker")
	if err != nil || event == nil || event.AttemptCount != 10 {
		t.Fatalf("claim=%+v err=%v", event, err)
	}
	if err := repo.MarkInvalidationFailed(
		ctx, eventID, "dead-letter-worker", strings.Repeat("safe", 200), time.Now().Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	var status, lastError string
	if err := db.QueryRow(ctx, `
		SELECT status,last_error FROM identity_cache_invalidation_outbox WHERE id=$1
	`, eventID).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "dead_letter" || len([]rune(lastError)) != 512 {
		t.Fatalf("status=%s last_error_runes=%d", status, len([]rune(lastError)))
	}
	var claimable int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM identity_cache_invalidation_outbox
		WHERE id=$1 AND status IN ('pending','failed','processing')
	`, eventID).Scan(&claimable); err != nil {
		t.Fatal(err)
	}
	if claimable != 0 {
		t.Fatalf("dead letter remains claimable: %d", claimable)
	}

	oldID := "outbox-old-processed-" + suffix
	recentID := "outbox-recent-processed-" + suffix
	if _, err := db.Exec(ctx, `
		INSERT INTO identity_cache_invalidation_outbox (
			id,tenant_id,user_id,status,processed_at
		) VALUES
			($1,$3,$4,'processed',NOW()-INTERVAL '31 days'),
			($2,$3,$4,'processed',NOW()-INTERVAL '1 day')
	`, oldID, recentID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	deleted, err := repo.CleanupProcessedInvalidations(ctx, time.Now().Add(-30*24*time.Hour), 10)
	if err != nil || deleted != 1 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	var remaining int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM identity_cache_invalidation_outbox WHERE id=ANY($1)
	`, []string{oldID, recentID}).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("remaining processed events=%d, want recent event only", remaining)
	}
}
