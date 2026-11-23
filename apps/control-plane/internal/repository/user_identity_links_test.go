package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setupEnterpriseIdentityRepositoryDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	var migrationReady bool
	if err := db.QueryRow(ctx, `
		SELECT to_regclass('public.user_identity_links') IS NOT NULL
		   AND to_regclass('public.identity_department_mappings') IS NOT NULL
	`).Scan(&migrationReady); err != nil || !migrationReady {
		db.Close()
		t.Skip("enterprise identity migration 137 is not applied")
	}
	tenantID := fmt.Sprintf("tenant_identity_repo_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx, `
		INSERT INTO tenants (id,name,edition,status,is_test)
		VALUES ($1,$1,'enterprise','active',TRUE)
	`, tenantID); err != nil {
		db.Close()
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM identity_cache_invalidation_outbox WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(context.Background(), `DELETE FROM audit_operations WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(context.Background(), `DELETE FROM users WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenantID)
		db.Close()
	})
	return db, tenantID
}

func identityFixtureSuffix(tenantID string) string {
	if len(tenantID) <= 12 {
		return tenantID
	}
	return tenantID[len(tenantID)-12:]
}

func TestBoundedIdentityUsernamePreservesUTF8AndVarcharLimit(t *testing.T) {
	got := boundedIdentityUsername(strings.Repeat("中", 255), "user_1234567890abcdef")
	if !utf8.ValidString(got) {
		t.Fatalf("fallback username is invalid UTF-8: %q", got)
	}
	if utf8.RuneCountInString(got) > 255 {
		t.Fatalf("fallback username has %d characters", utf8.RuneCountInString(got))
	}
}

func TestUserIdentityLinkRepositoryStableKeyWinner(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	winnerUserID := "winner-user-" + suffix
	loserUserID := "loser-user-" + suffix
	var unassignedID string
	if err := db.QueryRow(ctx, `SELECT id FROM teams WHERE tenant_id=$1 AND system_key='unassigned'`, tenantID).Scan(&unassignedID); err != nil {
		t.Fatal(err)
	}
	for _, userID := range []string{winnerUserID, loserUserID} {
		if _, err := db.Exec(ctx, `
			INSERT INTO users (id,tenant_id,username,email,role,status,department_id,
				department_assignment_mode,department_assignment_source)
			VALUES ($1,$2,$3,$4,'developer','active',$5,'unassigned','oidc')
		`, userID, tenantID, userID, userID+"@example.local", unassignedID); err != nil {
			t.Fatal(err)
		}
	}
	repo := NewUserIdentityLinkRepository(db)
	base := identitybinding.UserIdentityLink{
		ID: "link-winner-" + suffix, TenantID: tenantID, UserID: winnerUserID,
		Issuer: "https://issuer.example", SourceID: "source-a", SourceType: "oidc", ExternalSubject: "subject-a",
	}
	first, created, err := repo.Bind(ctx, base)
	if err != nil || !created || first.UserID != winnerUserID {
		t.Fatalf("first=%+v created=%v err=%v", first, created, err)
	}
	base.ID = "link-loser-" + suffix
	base.UserID = loserUserID
	second, created, err := repo.Bind(ctx, base)
	if err != nil || created || second.UserID != winnerUserID {
		t.Fatalf("second=%+v created=%v err=%v", second, created, err)
	}
	got, err := repo.GetByStableKey(ctx, identitybinding.ExternalIdentity{
		TenantID: tenantID, Issuer: base.Issuer, SourceType: base.SourceType, ExternalSubject: base.ExternalSubject,
	})
	if err != nil || got == nil || got.UserID != winnerUserID {
		t.Fatalf("get=%+v err=%v", got, err)
	}
}

func TestUserIdentityLinkRepositoryDetectsExternalCredentialOwner(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	userID := "credential-owner-" + suffix
	var unassignedID string
	if err := db.QueryRow(ctx, `SELECT id FROM teams WHERE tenant_id=$1 AND system_key='unassigned'`, tenantID).Scan(&unassignedID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO users (id,tenant_id,username,role,status,department_id,department_assignment_mode,department_assignment_source)
		VALUES ($1,$2,$1,'developer','active',$3,'unassigned','migration')
	`, userID, tenantID, unassignedID); err != nil {
		t.Fatal(err)
	}
	repo := NewUserIdentityLinkRepository(db)
	managed, err := repo.HasExternalCredentialOwner(ctx, tenantID, userID)
	if err != nil || managed {
		t.Fatalf("plain synced account managed=%v err=%v", managed, err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO user_identity_links (id,tenant_id,user_id,issuer,source_type,source_id,external_subject)
		VALUES ($1,$2,$3,$4,'ldap',$4,$5)
	`, "credential-link-"+suffix, tenantID, userID, "ldap-source-"+suffix, "ldap-subject-"+suffix); err != nil {
		t.Fatal(err)
	}
	managed, err = repo.HasExternalCredentialOwner(ctx, tenantID, userID)
	if err != nil || !managed {
		t.Fatalf("LDAP credential owner managed=%v err=%v", managed, err)
	}
}

func TestUserIdentityLinkRepositoryRuntimeIssuerChangeReusesSourceScopedBinding(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	userID := "issuer-move-user-" + suffix
	var unassignedID string
	if err := db.QueryRow(ctx, `SELECT id FROM teams WHERE tenant_id=$1 AND system_key='unassigned'`, tenantID).Scan(&unassignedID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO users (id,tenant_id,username,role,status,department_id,
			department_assignment_mode,department_assignment_source)
		VALUES ($1,$2,$1,'developer','active',$3,'unassigned','oidc')
	`, userID, tenantID, unassignedID); err != nil {
		t.Fatal(err)
	}

	repo := NewUserIdentityLinkRepository(db)
	oldLink := identitybinding.UserIdentityLink{
		ID: "issuer-move-link-" + suffix, TenantID: tenantID, UserID: userID,
		Issuer: "http://gateway.internal:8180/sso/realms/jjdguard", SourceID: "source-a",
		SourceType: "oidc", ExternalSubject: "issuer-move-subject",
	}
	if _, created, err := repo.Bind(ctx, oldLink); err != nil || !created {
		t.Fatalf("create old issuer link: created=%v err=%v", created, err)
	}

	currentIdentity := identitybinding.ExternalIdentity{
		TenantID: tenantID, Issuer: "https://gateway.example/sso/realms/jjdguard",
		SourceID: "source-a", SourceType: "oidc", ExternalSubject: oldLink.ExternalSubject,
	}
	got, err := repo.GetByStableKey(ctx, currentIdentity)
	if err != nil || got == nil || got.UserID != userID {
		t.Fatalf("source-scoped lookup after issuer move: got=%+v err=%v", got, err)
	}

	alias := oldLink
	alias.ID = "issuer-move-alias-" + suffix
	alias.Issuer = currentIdentity.Issuer
	winner, created, err := repo.Bind(ctx, alias)
	if err != nil || created || winner.UserID != userID || winner.ID != oldLink.ID {
		t.Fatalf("issuer alias must reuse existing binding: winner=%+v created=%v err=%v", winner, created, err)
	}

	withoutSourceID := currentIdentity
	withoutSourceID.SourceID = ""
	if got, err := repo.GetByStableKey(ctx, withoutSourceID); err != nil || got != nil {
		t.Fatalf("issuer fallback without source id must fail closed: got=%+v err=%v", got, err)
	}
	differentSource := currentIdentity
	differentSource.SourceID = "source-b"
	if got, err := repo.GetByStableKey(ctx, differentSource); err != nil || got != nil {
		t.Fatalf("different identity source must remain isolated: got=%+v err=%v", got, err)
	}
}

func TestIdentityDepartmentMappingRepositoryExactThenFallbackAndTenantIsolation(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	exactDepartment := "dept-exact-" + tenantID
	fallbackDepartment := "dept-fallback-" + tenantID
	for _, departmentID := range []string{exactDepartment, fallbackDepartment} {
		if _, err := db.Exec(ctx, `
			INSERT INTO teams (id,tenant_id,name,path) VALUES ($1,$2,$3,$4)
		`, departmentID, tenantID, departmentID, "/"+departmentID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO identity_department_mappings
			(id,tenant_id,source_kind,source_id,match_type,match_value,target_department_id,priority,enabled)
		VALUES
			($1,$4,'oidc','source-a','groups','group-a',$5,100,TRUE),
			($2,$4,'oidc','','groups','group-a',$6,1,TRUE),
			($3,$4,'oidc','','groups','group-b',$6,1,TRUE),
			('mapping-wrong-type-' || $4,$4,'oidc','source-a','department','group-a',$6,1,TRUE)
	`, "mapping-exact-"+tenantID, "mapping-fallback-"+tenantID,
		"mapping-fallback-b-"+tenantID, tenantID, exactDepartment, fallbackDepartment); err != nil {
		t.Fatal(err)
	}
	repo := NewIdentityDepartmentMappingRepository(db)
	exact, err := repo.FindMatches(ctx, identitybinding.ExternalIdentity{
		TenantID: tenantID, SourceType: "oidc", SourceID: "source-a", Groups: []string{"group-a"},
	})
	if err != nil || len(exact) != 1 || exact[0].DepartmentID != exactDepartment {
		t.Fatalf("exact=%+v err=%v", exact, err)
	}
	fallback, err := repo.FindMatches(ctx, identitybinding.ExternalIdentity{
		TenantID: tenantID, SourceType: "oidc", SourceID: "other-source", Groups: []string{"group-b"},
	})
	if err != nil || len(fallback) != 1 || fallback[0].DepartmentID != fallbackDepartment {
		t.Fatalf("fallback=%+v err=%v", fallback, err)
	}
	isolated, err := repo.FindMatches(ctx, identitybinding.ExternalIdentity{
		TenantID: "another-tenant", SourceType: "oidc", SourceID: "source-a", Groups: []string{"group-a"},
	})
	if err != nil || len(isolated) != 0 {
		t.Fatalf("cross-tenant mappings=%+v err=%v", isolated, err)
	}
	if exact[0].ID != "mapping-exact-"+tenantID {
		t.Fatalf("same match_value in another match_type must not match Groups claim: %+v", exact)
	}
}

func TestIdentityDepartmentMappingRepositoryMatchesTypedValuesWithoutCrossTypeMatches(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	departments := map[string]string{
		"department": "dept-typed-department-" + tenantID,
		"member_of":  "dept-typed-member-of-" + tenantID,
		"groups":     "dept-typed-groups-" + tenantID,
		"wrong":      "dept-typed-wrong-" + tenantID,
	}
	for _, departmentID := range departments {
		if _, err := db.Exec(ctx, `
			INSERT INTO teams (id,tenant_id,name,path) VALUES ($1,$2,$3,$4)
		`, departmentID, tenantID, departmentID, "/"+departmentID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO identity_department_mappings
			(id,tenant_id,source_kind,source_id,match_type,match_value,target_department_id,priority,enabled)
		VALUES
			('typed-department-' || $1,$1,'oidc','source-a','department','shared-value',$2,10,TRUE),
			('typed-member-of-' || $1,$1,'oidc','source-a','member_of','shared-value',$3,10,TRUE),
			('typed-groups-' || $1,$1,'oidc','source-a','groups','shared-value',$4,10,TRUE),
			('wrong-department-' || $1,$1,'oidc','source-a','department','groups-only',$5,10,TRUE),
			('typed-groups-only-' || $1,$1,'oidc','source-a','groups','groups-only',$4,10,TRUE)
	`, tenantID, departments["department"], departments["member_of"], departments["groups"], departments["wrong"]); err != nil {
		t.Fatal(err)
	}

	matches, err := NewIdentityDepartmentMappingRepository(db).FindMatches(ctx, identitybinding.ExternalIdentity{
		TenantID: tenantID, SourceType: "oidc", SourceID: "source-a",
		Departments: []string{"shared-value"},
		MemberOf:    []string{"shared-value"},
		Groups:      []string{"shared-value", "groups-only"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]string, len(matches))
	for _, match := range matches {
		got[match.MatchType] = match.DepartmentID
	}
	for matchType, departmentID := range map[string]string{
		"department": departments["department"],
		"member_of":  departments["member_of"],
		"groups":     departments["groups"],
	} {
		if got[matchType] != departmentID {
			t.Fatalf("%s match department=%q, want %q; all matches=%+v", matchType, got[matchType], departmentID, matches)
		}
	}
	if len(matches) != 4 {
		t.Fatalf("typed matches=%+v, want four matching rules without cross-type match", matches)
	}
	for _, match := range matches {
		if match.DepartmentID == departments["wrong"] {
			t.Fatalf("groups-only value crossed into department mapping: %+v", match)
		}
	}
}

func TestUserIdentityLinkRepositoryConcurrentBindHasOneWinner(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	var unassignedID string
	if err := db.QueryRow(ctx, `SELECT id FROM teams WHERE tenant_id=$1 AND system_key='unassigned'`, tenantID).Scan(&unassignedID); err != nil {
		t.Fatal(err)
	}
	const workers = 8
	for index := 0; index < workers; index++ {
		userID := fmt.Sprintf("concurrent-user-%s-%d", suffix, index)
		if _, err := db.Exec(ctx, `
			INSERT INTO users (id,tenant_id,username,role,status,department_id,
				department_assignment_mode,department_assignment_source)
			VALUES ($1,$2,$1,'developer','active',$3,'unassigned','oidc')
		`, userID, tenantID, unassignedID); err != nil {
			t.Fatal(err)
		}
	}
	repo := NewUserIdentityLinkRepository(db)
	start := make(chan struct{})
	winners := make(chan string, workers)
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			link, _, err := repo.Bind(ctx, identitybinding.UserIdentityLink{
				ID: fmt.Sprintf("concurrent-link-%s-%d", suffix, index), TenantID: tenantID,
				UserID: fmt.Sprintf("concurrent-user-%s-%d", suffix, index),
				Issuer: "https://issuer.example", SourceID: "source-a",
				SourceType: "oidc", ExternalSubject: "concurrent-subject",
			})
			errs <- err
			winners <- link.UserID
		}(index)
	}
	close(start)
	wait.Wait()
	close(errs)
	close(winners)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	winner := ""
	for userID := range winners {
		if winner == "" {
			winner = userID
		}
		if userID != winner {
			t.Fatalf("winner changed from %s to %s", winner, userID)
		}
	}
}

type repositoryTestInvalidator struct {
	users      []string
	modelUsers []string
}

func (i *repositoryTestInvalidator) InvalidateUserCache(_ context.Context, userID string) error {
	i.users = append(i.users, userID)
	return nil
}

func (i *repositoryTestInvalidator) InvalidateUserModelAuthorizationCache(_ context.Context, userID string) error {
	i.modelUsers = append(i.modelUsers, userID)
	return nil
}

func TestIdentityBindingServiceTransactionProjectsDepartmentAndAudit(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	departmentA := "dept-service-a-" + suffix
	departmentB := "dept-service-b-" + suffix
	for _, departmentID := range []string{departmentA, departmentB} {
		if _, err := db.Exec(ctx, `
			INSERT INTO teams (id,tenant_id,name,path) VALUES ($1,$2,$3,$4)
		`, departmentID, tenantID, departmentID, "/"+departmentID); err != nil {
			t.Fatal(err)
		}
	}
	mappingID := "mapping-service-" + suffix
	if _, err := db.Exec(ctx, `
		INSERT INTO identity_department_mappings (
			id,tenant_id,source_kind,source_id,match_type,match_value,
			target_department_id,priority,enabled
		) VALUES
			($1,$2,'oidc','source-a','groups','group-a',$3,10,TRUE),
			($4,$2,'oidc','source-a','groups','group-b',$5,20,TRUE)
	`, mappingID, tenantID, departmentA, "mapping-service-low-"+suffix, departmentB); err != nil {
		t.Fatal(err)
	}
	invalidator := &repositoryTestInvalidator{}
	repo := NewUserIdentityLinkRepository(db)
	service := identitybinding.NewService(repo)
	identity := identitybinding.ExternalIdentity{
		TenantID: tenantID, Issuer: "https://issuer.example", SourceID: "source-a",
		SourceType: "oidc", ExternalSubject: "service-subject", Username: "service-user",
		Email: "service@example.local", Groups: []string{"group-a", "group-b"},
	}
	first, err := service.BindAndResolve(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	if first.DepartmentID != departmentA || !first.Changed {
		t.Fatalf("first=%+v", first)
	}
	if _, err := db.Exec(ctx, `
		UPDATE team_members SET role='owner' WHERE user_id=$1 AND team_id=$2
	`, first.UserID, departmentA); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		UPDATE identity_department_mappings
		SET target_department_id=$2, updated_at=NOW()
		WHERE tenant_id=$1 AND id=$3
	`, tenantID, departmentB, mappingID); err != nil {
		t.Fatal(err)
	}
	second, err := service.BindAndResolve(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	if second.UserID != first.UserID || second.DepartmentID != departmentB || !second.Changed {
		t.Fatalf("second=%+v first=%+v", second, first)
	}

	var userDepartment, assignmentMode, memberDepartment, memberRole string
	if err := db.QueryRow(ctx, `
		SELECT department_id, department_assignment_mode
		FROM users WHERE tenant_id=$1 AND id=$2
	`, tenantID, first.UserID).Scan(&userDepartment, &assignmentMode); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `
		SELECT team_id, role FROM team_members WHERE user_id=$1
	`, first.UserID).Scan(&memberDepartment, &memberRole); err != nil {
		t.Fatal(err)
	}
	if userDepartment != departmentB || memberDepartment != departmentB ||
		assignmentMode != identitybinding.ModeAutomatic || memberRole != "member" {
		t.Fatalf("user=%s/%s projection=%s/%s", userDepartment, assignmentMode, memberDepartment, memberRole)
	}
	reconciler := identitybinding.NewReconciler(repo, invalidator, invalidator)
	// The production worker is global: unrelated fixture tenants may have pending
	// events. Drain it and assert this identity's events, rather than assume two
	// global calls exhaust the queue.
	for index := 0; index < 10000; index++ {
		processed, err := reconciler.ProcessOne(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !processed {
			break
		}
		if index == 9999 {
			t.Fatal("outbox did not drain")
		}
	}
	if processed, err := reconciler.ProcessOne(ctx); err != nil || processed {
		t.Fatalf("empty reconcile processed=%v err=%v", processed, err)
	}
	var auditCount, processedOutboxCount int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_operations
		WHERE tenant_id=$1
		  AND action_type='identity.department.changed'
		  AND target_id=$2
		  AND action_detail ?& ARRAY[
		    'user_id','old_department_id','new_department_id',
		    'source_id','rule_id','actor_id'
		  ]
		  AND NOT action_detail ?| ARRAY[
		    'tenant_id','token','email','groups','source'
		  ]
		  AND (SELECT COUNT(*) FROM jsonb_object_keys(action_detail))=6
		  AND action_detail->>'user_id'=$2
		  AND action_detail->>'source_id'='source-a'
	`, tenantID, first.UserID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM identity_cache_invalidation_outbox
		WHERE tenant_id=$1
		  AND status='processed'
	`, tenantID).Scan(&processedOutboxCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 2 || processedOutboxCount != 2 ||
		countIdentityInvalidations(invalidator.users, first.UserID) != 2 || countIdentityInvalidations(invalidator.modelUsers, first.UserID) != 2 {
		t.Fatalf("audit=%d outbox=%d invalidations=%v model_invalidations=%v",
			auditCount, processedOutboxCount, invalidator.users, invalidator.modelUsers)
	}
}

func TestIdentityCacheInvalidationOutboxClaimRetryLeaseAndConcurrency(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	userID := "outbox-user-" + suffix
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
	eventID := "outbox-event-" + suffix
	if _, err := db.Exec(ctx, `
		INSERT INTO identity_cache_invalidation_outbox (
			id,tenant_id,user_id,old_department_id,new_department_id
		) VALUES ($1,$2,$3,$4,$5)
	`, eventID, tenantID, userID, "dept-old", "dept-new"); err != nil {
		t.Fatal(err)
	}

	repo := NewUserIdentityLinkRepository(db)
	const workers = 8
	start := make(chan struct{})
	claimed := make(chan *identitybinding.CacheInvalidationEvent, workers)
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			event, err := repo.ClaimNextInvalidation(ctx, fmt.Sprintf("worker-%d", index))
			claimed <- event
			errs <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(claimed)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var winner *identitybinding.CacheInvalidationEvent
	for event := range claimed {
		if event == nil {
			continue
		}
		if winner != nil {
			t.Fatalf("event claimed twice: first=%+v second=%+v", winner, event)
		}
		winner = event
	}
	if winner == nil || winner.AttemptCount != 1 {
		t.Fatalf("first claim=%+v", winner)
	}
	var owner string
	if err := db.QueryRow(ctx, `
		SELECT locked_by FROM identity_cache_invalidation_outbox WHERE id=$1
	`, eventID).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkInvalidationFailed(
		ctx, eventID, owner, "permission cache invalidation failed", time.Now().Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	if event, err := repo.ClaimNextInvalidation(ctx, "too-early"); err != nil || event != nil {
		t.Fatalf("future retry claimed=%+v err=%v", event, err)
	}

	if _, err := db.Exec(ctx, `
		UPDATE identity_cache_invalidation_outbox
		SET next_attempt_at=NOW()-INTERVAL '1 second'
		WHERE id=$1
	`, eventID); err != nil {
		t.Fatal(err)
	}
	retry, err := repo.ClaimNextInvalidation(ctx, "retry-worker")
	if err != nil || retry == nil || retry.AttemptCount != 2 {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}

	if _, err := db.Exec(ctx, `
		UPDATE identity_cache_invalidation_outbox
		SET status='processing',locked_by='crashed-worker',
		    locked_at=NOW()-INTERVAL '10 minutes'
		WHERE id=$1
	`, eventID); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := repo.ClaimNextInvalidation(ctx, "lease-recovery-worker")
	if err != nil || reclaimed == nil || reclaimed.AttemptCount != 3 {
		t.Fatalf("lease reclaimed=%+v err=%v", reclaimed, err)
	}
	if err := repo.MarkInvalidationProcessed(ctx, eventID, "lease-recovery-worker"); err != nil {
		t.Fatal(err)
	}
	var status, lastError string
	if err := db.QueryRow(ctx, `
		SELECT status,last_error FROM identity_cache_invalidation_outbox WHERE id=$1
	`, eventID).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "processed" || lastError != "" {
		t.Fatalf("status=%s last_error=%q", status, lastError)
	}
}

func countIdentityInvalidations(users []string, id string) int {
	count := 0
	for _, user := range users {
		if user == id {
			count++
		}
	}
	return count
}
