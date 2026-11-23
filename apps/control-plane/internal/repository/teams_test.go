package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupTeamsTestDB opens a connection to the test database and registers a
// cleanup that removes the tenant (and cascades) created during the test.
// It follows the same pattern as content_logs_test.go and
// audit_stats_regression_test.go.
func setupTeamsTestDB(t *testing.T) (*pgxpool.Pool, string) {
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

	// Use a unique tenant per test run to avoid inter-test pollution.
	tenantID := fmt.Sprintf("tenant_teams_%d", time.Now().UnixNano())

	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	t.Cleanup(func() {
		// CASCADE on teams FK covers team_members too.
		_, _ = db.Exec(ctx, `DELETE FROM teams WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})

	return db, tenantID
}

func TestTeamCreateGetList(t *testing.T) {
	pool, tenantID := setupTeamsTestDB(t)
	repo := NewTeamRepository(pool)
	ctx := context.Background()

	team := &Team{ID: "team_t1_" + fmt.Sprint(time.Now().UnixNano()), TenantID: tenantID, Name: "研发部"}
	if err := repo.Create(ctx, team, ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if team.Path == "" {
		t.Fatal("Create should set team.Path")
	}

	got, err := repo.GetByID(ctx, team.ID)
	if err != nil {
		t.Fatalf("get err: %v", err)
	}
	if got == nil || got.Name != "研发部" {
		t.Fatalf("get: got=%+v", got)
	}

	list, err := repo.ListByTenant(ctx, tenantID)
	if err != nil || len(list) == 0 {
		t.Fatalf("list: got=%v err=%v", list, err)
	}
}

func TestTeamCustomerListsHideSystemDepartments(t *testing.T) {
	pool, tenantID := setupTeamsTestDB(t)
	repo := NewTeamRepository(pool)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	businessID := "team_business_" + suffix
	if _, err := pool.Exec(ctx, `
		INSERT INTO teams (id,tenant_id,name,path,is_system,monthly_budget_cny,daily_budget_cny)
		VALUES ($1,$2,'业务部门',$3,FALSE,100,10)
	`, businessID, tenantID, "/"+businessID); err != nil {
		t.Fatal(err)
	}
	var systemCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM teams WHERE tenant_id=$1 AND is_system=TRUE
	`, tenantID).Scan(&systemCount); err != nil {
		t.Fatal(err)
	}
	if systemCount != 1 {
		t.Fatalf("system department fixtures=%d, want 1", systemCount)
	}
	var systemID string
	if err := pool.QueryRow(ctx, `
		SELECT id FROM teams WHERE tenant_id=$1 AND is_system=TRUE
	`, tenantID).Scan(&systemID); err != nil {
		t.Fatal(err)
	}
	hidden, err := repo.GetByID(ctx, systemID)
	if err != nil {
		t.Fatal(err)
	}
	if hidden != nil {
		t.Fatalf("GetByID exposed system department: %+v", hidden)
	}

	list, err := repo.ListByTenant(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != businessID {
		t.Fatalf("customer team list=%+v", list)
	}

	budgetList, err := repo.ListByTenantWithBudget(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(budgetList) != 1 || budgetList[0].ID != businessID {
		t.Fatalf("customer budget team list=%+v", budgetList)
	}

	otherTenantID := "tenant_teams_other_" + suffix
	crossTenantTeamID := "team_cross_tenant_" + suffix
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id,name,edition,status,is_test)
		VALUES ($1,$1,'enterprise','active',TRUE)
	`, otherTenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO teams (id,tenant_id,name,path,monthly_budget_cny,daily_budget_cny)
		VALUES ($1::varchar,$2::varchar,$1::varchar,'/' || $1::text,200,20)
	`, crossTenantTeamID, otherTenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, otherTenantID)
	})

	for _, test := range []struct {
		name   string
		teamID string
	}{
		{name: "system", teamID: systemID},
		{name: "missing", teamID: "team_missing_" + suffix},
		{name: "cross tenant", teamID: crossTenantTeamID},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := repo.GetWithBudget(ctx, tenantID, test.teamID)
			if err != nil {
				t.Fatal(err)
			}
			if got != nil {
				t.Fatalf("GetWithBudget exposed unavailable department: %+v", got)
			}
		})
	}

	business, err := repo.GetWithBudget(ctx, tenantID, businessID)
	if err != nil {
		t.Fatal(err)
	}
	if business == nil || business.ID != businessID ||
		business.MonthlyBudgetCNY != 100 || business.DailyBudgetCNY != 10 {
		t.Fatalf("business team budget=%+v", business)
	}
}

func TestTeamPathWithParent(t *testing.T) {
	pool, tenantID := setupTeamsTestDB(t)
	repo := NewTeamRepository(pool)
	ctx := context.Background()

	suffix := fmt.Sprint(time.Now().UnixNano())
	parentID := "team_root_" + suffix
	childID := "team_child_" + suffix

	parent := &Team{ID: parentID, TenantID: tenantID, Name: "根部"}
	if err := repo.Create(ctx, parent, ""); err != nil {
		t.Fatalf("create parent: %v", err)
	}

	child := &Team{ID: childID, TenantID: tenantID, Name: "子部门", ParentTeamID: parentID}
	if err := repo.Create(ctx, child, parent.Path); err != nil {
		t.Fatalf("create child: %v", err)
	}

	got, err := repo.GetByID(ctx, childID)
	if err != nil {
		t.Fatalf("get child err: %v", err)
	}
	wantPath := "/" + parentID + "/" + childID
	if got.Path != wantPath {
		t.Errorf("path: want %s, got %s", wantPath, got.Path)
	}
	if got.ParentTeamID != parentID {
		t.Errorf("parent_team_id: want %s, got %s", parentID, got.ParentTeamID)
	}
}

func TestTeamUpdateName(t *testing.T) {
	pool, tenantID := setupTeamsTestDB(t)
	repo := NewTeamRepository(pool)
	ctx := context.Background()

	id := "team_upd_" + fmt.Sprint(time.Now().UnixNano())
	team := &Team{ID: id, TenantID: tenantID, Name: "旧名"}
	if err := repo.Create(ctx, team, ""); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := repo.UpdateName(ctx, id, "新名"); err != nil {
		t.Fatalf("update name: %v", err)
	}
	got, _ := repo.GetByID(ctx, id)
	if got.Name != "新名" {
		t.Errorf("want 新名, got %s", got.Name)
	}
}

func TestTeamListSubtree(t *testing.T) {
	pool, tenantID := setupTeamsTestDB(t)
	repo := NewTeamRepository(pool)
	ctx := context.Background()

	suffix := fmt.Sprint(time.Now().UnixNano())
	rootID := "team_sr_" + suffix
	child1ID := "team_sc1_" + suffix
	child2ID := "team_sc2_" + suffix

	root := &Team{ID: rootID, TenantID: tenantID, Name: "根"}
	_ = repo.Create(ctx, root, "")

	c1 := &Team{ID: child1ID, TenantID: tenantID, Name: "子1", ParentTeamID: rootID}
	_ = repo.Create(ctx, c1, root.Path)

	c2 := &Team{ID: child2ID, TenantID: tenantID, Name: "子2", ParentTeamID: rootID}
	_ = repo.Create(ctx, c2, root.Path)

	subtree, err := repo.ListSubtree(ctx, root.Path)
	if err != nil {
		t.Fatalf("list subtree: %v", err)
	}
	if len(subtree) != 2 {
		t.Errorf("want 2 children, got %d", len(subtree))
	}
}

func TestTeamDelete(t *testing.T) {
	pool, tenantID := setupTeamsTestDB(t)
	repo := NewTeamRepository(pool)
	ctx := context.Background()

	id := "team_del_" + fmt.Sprint(time.Now().UnixNano())
	team := &Team{ID: id, TenantID: tenantID, Name: "待删"}
	_ = repo.Create(ctx, team, "")

	if err := repo.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, _ := repo.GetByID(ctx, id)
	if got != nil {
		t.Errorf("expected nil after delete, got %+v", got)
	}
}
