package billing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestAnalyticsModelDisplayMetadataPreservesFactsAndTenantScope(t *testing.T) {
	store, db, tenantID, _ := setupBillingStoreTest(t)
	_, _, otherTenant, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	commonName := "wallet-qa-history-" + tenantID
	exactID, fallbackID, foreignID := "z-"+tenantID, "a-"+tenantID, "foreign-"+otherTenant
	for _, item := range []struct{ id, tenant, name, label, status string }{
		{exactID, tenantID, commonName, "Exact disabled label", "disabled"},
		{fallbackID, tenantID, commonName, "Same tenant fallback", "active"},
		{foreignID, otherTenant, commonName, "Foreign label must stay private", "active"},
		{foreignID + "-only", otherTenant, "foreign-only-" + tenantID, "Foreign only label", "active"},
	} {
		providerID := item.id + "-provider"
		if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type,base_url,status)
            VALUES ($1,$2,$1,'openai','https://metadata.test.invalid','active')`, providerID, item.tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name,model_label,status)
            VALUES ($1,$2,$3,$4,$5)`, item.id, providerID, item.name, item.label, item.status); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	for _, item := range []struct{ id, name string }{
		{exactID, commonName}, {"missing-" + tenantID, commonName},
		{foreignID, commonName}, {foreignID + "-only", "foreign-only-" + tenantID},
	} {
		if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,model_id,model_name,
            prompt_tokens,output_tokens,currency,status,billable_amount_micros,occurred_at)
            VALUES ($1,$2,$1,'metering',$3,$4,1,1,'CNY','settled',390,$5)`,
			"fact-"+item.id, tenantID, item.id, item.name, now); err != nil {
			t.Fatal(err)
		}
	}
	filter := AnalyticsFilter{TenantID: tenantID, Start: now.Add(-time.Hour), End: now.Add(time.Hour), FullTenant: true}
	rows, err := store.GetAnalyticsBreakdown(ctx, filter, "model", 100)
	if err != nil || len(rows) != 4 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	want := map[string]string{exactID: "Exact disabled label", "missing-" + tenantID: "Same tenant fallback",
		foreignID: "Same tenant fallback", foreignID + "-only": ""}
	var total Micros
	for _, row := range rows {
		if row.ModelLabel != want[row.ID] || row.ModelName != row.Name || row.Requests != 1 || row.BillableMicros != 390 {
			t.Fatalf("metadata changed or leaked facts: %+v", row)
		}
		total += row.BillableMicros
	}
	if total != 1560 {
		t.Fatalf("duplicated financial sum: %d", total)
	}
	filter.FilterModelIDs = []string{exactID}
	scoped, err := store.GetAnalyticsBreakdown(ctx, filter, "model", 100)
	if err != nil || len(scoped) != 1 || scoped[0].BillableMicros != 390 || scoped[0].ModelLabel != "Exact disabled label" {
		t.Fatalf("scoped=%+v err=%v", scoped, err)
	}
}

func TestLedgerDepartmentMetadataBothReadPathsPreserveEntries(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	departmentID := tenantID + "-department"
	if _, err := db.Exec(ctx, `INSERT INTO teams(id,tenant_id,name,path) VALUES ($1,$2,'Existing department',$1)`, departmentID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE users SET department_id=$1 WHERE id=$2`, departmentID, userID); err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Credit(ctx, tenantID, wallet.ID, "display-credit", 390, "tester", "display metadata"); err != nil {
		t.Fatal(err)
	}
	legacy, err := store.ListLedgerEntries(ctx, tenantID, "", 100)
	if err != nil || len(legacy) != 1 {
		t.Fatalf("legacy=%+v err=%v", legacy, err)
	}
	page, next, err := store.ListLedgerEntriesPage(ctx, tenantID, "", 1, "")
	if err != nil || len(page) != 1 || next != "" {
		t.Fatalf("page=%+v next=%q err=%v", page, next, err)
	}
	for _, item := range []LedgerEntry{legacy[0], page[0]} {
		if item.Username != userID || item.UserID != userID || item.DepartmentID != departmentID || item.DepartmentName != "Existing department" ||
			item.Currency != "CNY" || item.BalanceDeltaMicros != 390 || item.BalanceAfterMicros != 390 || item.Reason != "display metadata" {
			t.Fatalf("display metadata changed financial trail: %+v", item)
		}
	}
	_, _, otherTenant, _ := setupBillingStoreTest(t)
	foreignDepartment := otherTenant + "-department"
	if _, err := db.Exec(ctx, `INSERT INTO teams(id,tenant_id,name,path) VALUES ($1,$2,'Foreign department must stay private',$1)`, foreignDepartment, otherTenant); err != nil {
		t.Fatal(err)
	}
	// The current schema prevents a cross-tenant department assignment.
	// Assert that database boundary instead of creating an impossible fixture.
	_, err = db.Exec(ctx, `UPDATE users SET department_id=$1 WHERE id=$2`, foreignDepartment, userID)
	var constraintError *pgconn.PgError
	if !errors.As(err, &constraintError) || constraintError.Code != "23503" || constraintError.ConstraintName != "fk_users_department_tenant" {
		t.Fatalf("cross-tenant assignment must be rejected by its foreign key: %v", err)
	}
	guarded, err := store.ListLedgerEntries(ctx, tenantID, "", 100)
	if err != nil || len(guarded) != 1 || guarded[0].DepartmentID != departmentID || guarded[0].DepartmentName != "Existing department" || guarded[0].BalanceDeltaMicros != 390 {
		t.Fatalf("rejected assignment changed the ledger projection: %+v err=%v", guarded, err)
	}
	guardedPage, _, err := store.ListLedgerEntriesPage(ctx, tenantID, "", 1, "")
	if err != nil || len(guardedPage) != 1 || guardedPage[0].DepartmentID != departmentID || guardedPage[0].DepartmentName != "Existing department" || guardedPage[0].BalanceDeltaMicros != 390 {
		t.Fatalf("rejected assignment changed the paginated ledger projection: %+v err=%v", guardedPage, err)
	}
}
