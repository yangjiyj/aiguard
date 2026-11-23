package repository

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
)

func TestCatalogSnapshotLifecyclePreservesManualChoicesAndHistory(t *testing.T) {
	db := catalogSnapshotTestDB(t)
	ctx := context.Background()
	var err error
	seedStatus(t, db, "ta", "p1", "manual", "manual", "active", "active", "active")
	repo := NewModelRepository(db)
	provider := &Provider{ID: "p1", TenantID: "ta", ProviderType: "openai", Status: "active"}
	apply := func(admit bool, ids ...string) CatalogSnapshotResult {
		token, err := repo.BeginCatalogSync(ctx, "ta", "p1")
		if err != nil {
			t.Fatal(err)
		}
		input := CatalogSnapshotInput{TenantID: "ta", Provider: provider, CredentialID: "c-p1", LeaseToken: token}
		for _, id := range ids {
			item := CatalogSnapshotModel{ID: id, Name: id}
			if admit {
				item.Approved = true
				item.Probe = catalogAdmissionProbe()
			}
			input.Models = append(input.Models, item)
		}
		result, err := repo.ApplyCatalogSnapshot(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	r := apply(true, "a", "b", "manual")
	if r.Created != 2 {
		t.Fatalf("created=%+v", r)
	}
	var a, b string
	if err = db.QueryRow(ctx, `SELECT model_id FROM model_catalog_entries WHERE provider_id='p1' AND upstream_model_id='a'`).Scan(&a); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT model_id FROM model_catalog_entries WHERE provider_id='p1' AND upstream_model_id='b'`).Scan(&b); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `UPDATE models SET status=CASE WHEN id=$1 THEN 'active' ELSE 'disabled' END WHERE id IN ($1,$2)`, a, b)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,provider_id,model_id,request_status) VALUES('history','history','ta','p1',$1,'success')`, a)
	if err != nil {
		t.Fatal(err)
	}
	r = apply(false)
	if r.Deactivated != 2 {
		t.Fatalf("removed=%+v", r)
	}
	var status string
	db.QueryRow(ctx, `SELECT status FROM models WHERE id=$1`, a).Scan(&status)
	if status != "upstream_removed" {
		t.Fatal(status)
	}
	db.QueryRow(ctx, `SELECT status FROM models WHERE id='manual'`).Scan(&status)
	if status != "active" {
		t.Fatal("manual changed", status)
	}
	r = apply(false, "a", "b")
	if r.Reappeared != 2 {
		t.Fatalf("reappeared=%+v", r)
	}
	db.QueryRow(ctx, `SELECT status FROM models WHERE id=$1`, a).Scan(&status)
	if status != "active" {
		t.Fatal(status)
	}
	db.QueryRow(ctx, `SELECT status FROM models WHERE id=$1`, b).Scan(&status)
	if status != "disabled" {
		t.Fatal("manual disable lost", status)
	}
	r = apply(false, "a", "b")
	if r.Created != 0 || r.Deactivated != 0 || r.Reappeared != 0 {
		t.Fatal("not idempotent", r)
	}
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM request_logs WHERE id='history'`).Scan(&n)
	if n != 1 {
		t.Fatal("history lost")
	}
	db.QueryRow(ctx, `SELECT count(*) FROM model_catalog_sync_runs`).Scan(&n)
	if n != 4 {
		t.Fatal("audit lost", n)
	}
	token, err := repo.BeginCatalogSync(ctx, "ta", "p1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.BeginCatalogSync(ctx, "ta", "p1"); err == nil {
		t.Fatal("concurrent lease accepted")
	}
	if err = repo.FailCatalogSync(ctx, "ta", "p1", token, "http_401"); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(ctx, `SELECT status FROM models WHERE id=$1`, a).Scan(&status)
	if status != "active" {
		t.Fatal("failure cleared models")
	}
	if _, err = repo.ApplyCatalogSnapshot(ctx, CatalogSnapshotInput{TenantID: "ta", Provider: provider, CredentialID: "c-p1", LeaseToken: token}); err == nil {
		t.Fatal("expired task applied")
	}
}

func catalogSnapshotTestDB(t *testing.T) *pgxpool.Pool {
	db := statusTestDB(t)
	ctx := context.Background()
	_, err := db.Exec(ctx, `ALTER TABLE models ADD COLUMN model_label text, ADD COLUMN upstream_model_id text, ADD COLUMN pricing_json jsonb DEFAULT '{}', ADD COLUMN context_window int DEFAULT 0; INSERT INTO tenants VALUES('ta'); CREATE TABLE audit_operations(id text PRIMARY KEY,action_type text,action_detail jsonb,target_id text,created_at timestamptz);`)
	if err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../../../deploy/migrations/946_model_catalog_snapshots.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	return db
}
func TestCatalogSnapshotScopeAliasesAdmissionAndAtomicFailure(t *testing.T) {
	db := catalogSnapshotTestDB(t)
	ctx := context.Background()
	repo := NewModelRepository(db)
	seedStatus(t, db, "ta", "p1", "manual-one", "manual", "active", "disabled", "active")
	seedStatus(t, db, "ta", "p2", "manual-two", "same", "active", "active", "active")
	p := &Provider{ID: "p1", TenantID: "ta", ProviderType: "openai", Status: "active"}
	apply := func(items []CatalogSnapshotModel) (CatalogSnapshotResult, error) {
		token, err := repo.BeginCatalogSync(ctx, "ta", "p1")
		if err != nil {
			return CatalogSnapshotResult{}, err
		}
		return repo.ApplyCatalogSnapshot(ctx, CatalogSnapshotInput{TenantID: "ta", Provider: p, CredentialID: "c-p1", LeaseToken: token, Models: items})
	}
	first, err := apply([]CatalogSnapshotModel{{ID: "real-one", Name: "same", Approved: true}, {ID: "manual", Name: "manual", Approved: true}})
	if err != nil || first.Created != 0 || first.Skipped != 1 || first.VerificationFailed != 1 {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	var id, status string
	db.QueryRow(ctx, `SELECT COALESCE(model_id,'') FROM model_catalog_entries WHERE provider_id='p1' AND upstream_model_id='real-one'`).Scan(&id)
	if id != "" {
		t.Fatal("unverified catalog entry entered managed inventory", id)
	}
	verified, err := apply([]CatalogSnapshotModel{{ID: "real-one", Name: "same", Approved: true, Probe: catalogAdmissionProbe()}})
	if err != nil || verified.Created != 1 || verified.Verified != 1 || verified.Updated != 0 {
		t.Fatalf("verified admission=%+v err=%v", verified, err)
	}
	db.QueryRow(ctx, `SELECT model_id FROM model_catalog_entries WHERE provider_id='p1' AND upstream_model_id='real-one'`).Scan(&id)
	_, err = db.Exec(ctx, `UPDATE models SET model_name='public-alias',status='active' WHERE id=$1`, id)
	if err != nil {
		t.Fatal(err)
	}
	_, err = apply([]CatalogSnapshotModel{{ID: "real-one", Name: "changed label"}})
	if err != nil {
		t.Fatal(err)
	}
	var name, label string
	db.QueryRow(ctx, `SELECT model_name,model_label FROM models WHERE id=$1`, id).Scan(&name, &label)
	if name != "public-alias" || label != "changed label" {
		t.Fatal("alias changed", name, label)
	}
	if _, err = db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name,upstream_model_id,status) VALUES('manual-alias','p1','extra-public-alias','real-one','active')`); err != nil {
		t.Fatal(err)
	}
	removed, err := apply([]CatalogSnapshotModel{})
	if err != nil || removed.Deactivated != 2 {
		t.Fatal(removed, err)
	}
	db.QueryRow(ctx, `SELECT status FROM models WHERE id='manual-two'`).Scan(&status)
	if status != "active" {
		t.Fatal("other upstream changed")
	}
	db.QueryRow(ctx, `SELECT status FROM models WHERE id='manual-one'`).Scan(&status)
	if status != "disabled" {
		t.Fatal("manual disabled changed")
	}
	db.QueryRow(ctx, `SELECT status FROM models WHERE id='manual-alias'`).Scan(&status)
	if status != "upstream_removed" {
		t.Fatal("alias retained removed upstream route", status)
	}
	if present, err := repo.CatalogModelPresent(ctx, id); err != nil || present {
		t.Fatal("removed enable guard failed")
	}
	_, err = apply([]CatalogSnapshotModel{{ID: "would-create", Name: "would-create"}, {ID: "would-create", Name: "duplicate"}})
	if err == nil {
		t.Fatal("invalid snapshot committed")
	}
	var count int
	db.QueryRow(ctx, `SELECT count(*) FROM models WHERE model_name='would-create'`).Scan(&count)
	if count != 0 {
		t.Fatal("partial transaction committed")
	}
	var token string
	db.QueryRow(ctx, `SELECT lease_token FROM model_catalog_sync_state WHERE provider_id='p1'`).Scan(&token)
	repo.FailCatalogSync(ctx, "ta", "p1", token, "fixture_conflict")
	token, err = repo.BeginCatalogSync(ctx, "ta", "p1")
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(ctx, `UPDATE provider_credentials SET status='inactive' WHERE provider_id='p1'`)
	if _, err = repo.ApplyCatalogSnapshot(ctx, CatalogSnapshotInput{TenantID: "ta", Provider: p, CredentialID: "c-p1", LeaseToken: token}); err == nil {
		t.Fatal("rotated credential snapshot accepted")
	}
}

func TestCatalogMigrationOnlyAdoptsCompleteNonManualAuditBatches(t *testing.T) {
	db := catalogSnapshotTestDB(t)
	ctx := context.Background()
	for _, p := range []string{"owned", "manual", "incomplete"} {
		seedStatus(t, db, "ta", p, "legacy-"+p, p, "active", "active", "active")
	}
	_, err := db.Exec(ctx, `UPDATE providers SET created_at='2026-01-01';UPDATE models SET created_at='2026-01-02';
 INSERT INTO audit_operations(id,action_type,action_detail,target_id,created_at) VALUES
 ('owned-sync','sync_models','{"provider_id":"owned","created":1}','owned','2026-01-03'),
 ('manual-sync','sync_models','{"provider_id":"manual","created":1}','manual','2026-01-03'),
 ('incomplete-sync','sync_models','{"provider_id":"incomplete","created":2}','incomplete','2026-01-03'),
 ('manual-create','create_model','{}','legacy-manual','2026-01-02');`)
	if err != nil {
		t.Fatal(err)
	}
	sql, err := os.ReadFile("../../../../deploy/migrations/946_model_catalog_snapshots.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = db.Exec(ctx, string(sql)); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM model_catalog_entries`).Scan(&count); err != nil || count != 1 {
		t.Fatal("ambiguous or manual rows adopted", count, err)
	}
	var model string
	db.QueryRow(ctx, `SELECT model_id FROM model_catalog_entries`).Scan(&model)
	if model != "legacy-owned" {
		t.Fatal(model)
	}
}
