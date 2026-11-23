package repository

import (
	"context"
	"testing"
)

func TestTeamMemberBatchAddUsesSingleDepartmentAuthorityAtomically(t *testing.T) {
	pool, tenantID, firstUserID, teamID := setupTeamMembersTestDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	secondUserID := "batch-user-" + suffix
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id,tenant_id,username,role,status)
		VALUES ($1,$2,$1,'developer','active')
	`, secondUserID, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE tenant_id=$1 AND id=$2`, tenantID, secondUserID)
	})

	repo := NewTeamMemberRepository(pool)
	if err := repo.BatchAdd(ctx, teamID, []string{firstUserID, secondUserID}, "owner"); err != nil {
		t.Fatal(err)
	}
	var authoritativeUsers, projectedUsers int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users
		WHERE tenant_id=$1
		  AND id=ANY($2::text[])
		  AND department_id=$3
		  AND department_assignment_mode='manual'
		  AND department_assignment_source='admin'
	`, tenantID, []string{firstUserID, secondUserID}, teamID).Scan(&authoritativeUsers); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM team_members
		WHERE team_id=$1
		  AND user_id=ANY($2::text[])
		  AND role='owner'
	`, teamID, []string{firstUserID, secondUserID}).Scan(&projectedUsers); err != nil {
		t.Fatal(err)
	}
	if authoritativeUsers != 2 || projectedUsers != 2 {
		t.Fatalf("authoritative=%d projected=%d", authoritativeUsers, projectedUsers)
	}

	if err := repo.BatchAdd(ctx, teamID, []string{firstUserID, "missing-" + suffix}, "viewer"); err == nil {
		t.Fatal("batch with a missing user must fail")
	}
	var role string
	if err := pool.QueryRow(ctx, `
		SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2
	`, teamID, firstUserID).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "owner" {
		t.Fatalf("failed batch partially committed role=%s", role)
	}
}
