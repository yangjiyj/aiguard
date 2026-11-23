package repository

import (
	"context"
	"errors"
	"testing"
)

func TestModelRepositoryDeleteBatchDeletesUnreferencedAndDisablesReferenced(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	seedStatus(t, db, "tenant-batch", "provider-batch", "model-a-delete", "delete", "active", "active", "active")
	seedStatus(t, db, "tenant-batch", "provider-batch", "model-b-disable", "disable", "active", "active", "active")
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs(id, request_id, tenant_id, provider_id, model_id, request_status)
		VALUES ('log-batch', 'request-batch', 'tenant-batch', 'provider-batch', 'model-b-disable', 'completed')
	`); err != nil {
		t.Fatal(err)
	}

	result, err := NewModelRepository(db).DeleteBatch(
		ctx,
		"tenant-batch",
		[]string{"model-b-disable", "model-a-delete"},
	)
	if err != nil {
		t.Fatalf("DeleteBatch: %v", err)
	}
	want := ModelBatchDeleteResult{Requested: 2, Deleted: 1, Disabled: 1, Failed: 0}
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}

	var deletedCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM models WHERE id = 'model-a-delete'`).Scan(&deletedCount); err != nil {
		t.Fatal(err)
	}
	if deletedCount != 0 {
		t.Fatalf("unreferenced model count = %d, want 0", deletedCount)
	}

	var disabledStatus string
	if err := db.QueryRow(ctx, `SELECT status FROM models WHERE id = 'model-b-disable'`).Scan(&disabledStatus); err != nil {
		t.Fatal(err)
	}
	if disabledStatus != "disabled" {
		t.Fatalf("referenced model status = %q, want disabled", disabledStatus)
	}

	var historyCount int
	if err := db.QueryRow(ctx, `
		SELECT count(*) FROM request_logs
		WHERE id = 'log-batch' AND model_id = 'model-b-disable'
	`).Scan(&historyCount); err != nil {
		t.Fatal(err)
	}
	if historyCount != 1 {
		t.Fatalf("historical request log count = %d, want 1", historyCount)
	}
}

func TestModelRepositoryDeleteBatchRejectsUnknownIDAtomically(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	seedStatus(t, db, "tenant-known", "provider-known", "model-a-known", "known", "active", "active", "active")

	_, err := NewModelRepository(db).DeleteBatch(
		ctx,
		"tenant-known",
		[]string{"model-a-known", "model-z-missing"},
	)
	if !errors.Is(err, ErrModelsUnavailable) {
		t.Fatalf("error = %v, want ErrModelsUnavailable", err)
	}

	var status string
	if err := db.QueryRow(ctx, `SELECT status FROM models WHERE id = 'model-a-known'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("known model status = %q, want active", status)
	}
}

func TestModelRepositoryDeleteBatchRejectsCrossTenantIDAtomically(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	seedStatus(t, db, "tenant-owner", "provider-owner", "model-a-owner", "owner", "active", "active", "active")
	seedStatus(t, db, "tenant-other", "provider-other", "model-z-other", "other", "active", "active", "active")

	_, err := NewModelRepository(db).DeleteBatch(
		ctx,
		"tenant-owner",
		[]string{"model-a-owner", "model-z-other"},
	)
	if !errors.Is(err, ErrModelsUnavailable) {
		t.Fatalf("error = %v, want ErrModelsUnavailable", err)
	}

	for _, id := range []string{"model-a-owner", "model-z-other"} {
		var status string
		if err := db.QueryRow(ctx, `SELECT status FROM models WHERE id = $1`, id).Scan(&status); err != nil {
			t.Fatalf("query %s: %v", id, err)
		}
		if status != "active" {
			t.Fatalf("model %s status = %q, want active", id, status)
		}
	}
}

func TestModelRepositoryDeleteBatchRollsBackOnUnexpectedDeleteError(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	seedStatus(t, db, "tenant-rollback", "provider-rollback", "model-a-safe", "safe", "active", "active", "active")
	seedStatus(t, db, "tenant-rollback", "provider-rollback", "model-b-fail", "fail", "active", "active", "active")
	if _, err := db.Exec(ctx, `
		CREATE FUNCTION fail_second_model_delete() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			IF OLD.id = 'model-b-fail'
				AND NOT EXISTS (SELECT 1 FROM models WHERE id = 'model-a-safe')
			THEN
				RAISE EXCEPTION 'forced model delete failure' USING ERRCODE = 'P0001';
			END IF;
			RETURN OLD;
		END
		$$;
		CREATE TRIGGER fail_second_model_delete
		BEFORE DELETE ON models
		FOR EACH ROW EXECUTE FUNCTION fail_second_model_delete();
	`); err != nil {
		t.Fatal(err)
	}

	_, err := NewModelRepository(db).DeleteBatch(
		ctx,
		"tenant-rollback",
		[]string{"model-b-fail", "model-a-safe"},
	)
	if err == nil {
		t.Fatal("DeleteBatch error = nil, want forced delete error")
	}
	if errors.Is(err, ErrModelsUnavailable) {
		t.Fatalf("error = %v, want unexpected delete error", err)
	}

	for _, id := range []string{"model-a-safe", "model-b-fail"} {
		var status string
		if err := db.QueryRow(ctx, `SELECT status FROM models WHERE id = $1`, id).Scan(&status); err != nil {
			t.Fatalf("query %s after rollback: %v", id, err)
		}
		if status != "active" {
			t.Fatalf("model %s status = %q after rollback, want active", id, status)
		}
	}
}
