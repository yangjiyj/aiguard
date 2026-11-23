package backfill

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresCustomerProjectionScale(t *testing.T) {
	url := os.Getenv("JJD_BACKFILL_SCALE_DATABASE_URL")
	if url == "" {
		t.Skip("JJD_BACKFILL_SCALE_DATABASE_URL is not set")
	}
	rows, err := strconv.Atoi(os.Getenv("JJD_BACKFILL_SCALE_ROWS"))
	if err != nil || rows < 1 || rows > 10_000_000 {
		t.Fatal("JJD_BACKFILL_SCALE_ROWS must be between 1 and 10000000")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Hour)
	defer cancel()
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(ctx, `
CREATE FUNCTION jjdguard_customer_content_text(value text)
RETURNS boolean LANGUAGE sql IMMUTABLE
AS $$ SELECT COALESCE(BTRIM(value), '') <> '' AND value NOT LIKE '<system>%' $$;
CREATE TABLE request_logs (
 id varchar(64) PRIMARY KEY,request_id varchar(64) NOT NULL UNIQUE,
 tenant_id varchar(64) NOT NULL,proxy_mode varchar(32),
 has_customer_content boolean,has_customer_request_body boolean,
 has_customer_response_body boolean,customer_content_rule_version smallint NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL
);
CREATE TABLE content_logs (
 id varchar(64) PRIMARY KEY,request_id varchar(64) NOT NULL REFERENCES request_logs(id) ON DELETE CASCADE,
 tenant_id varchar(64) NOT NULL,role varchar(32) NOT NULL,content text NOT NULL
);
CREATE TABLE access_content_logs (
 id varchar(64) PRIMARY KEY,request_id varchar(64) NOT NULL REFERENCES request_logs(request_id) ON DELETE CASCADE,
 tenant_id varchar(64) NOT NULL,request_content_redacted text,response_content_redacted text,
 file_metadata_json jsonb NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX content_lookup ON content_logs(tenant_id,request_id,role);
CREATE INDEX access_lookup ON access_content_logs(tenant_id,request_id);
CREATE INDEX request_backfill_cursor ON request_logs(created_at,id);
`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `
INSERT INTO request_logs(id,request_id,tenant_id,proxy_mode,has_customer_content,
 has_customer_request_body,has_customer_response_body,created_at)
SELECT 'log-'||lpad(gs::text,12,'0'),'req-'||lpad(gs::text,12,'0'),
       'tenant-'||lpad((gs%100)::text,3,'0'),'api',false,false,false,
       '2026-01-01'::timestamptz + gs*interval '1 microsecond'
FROM generate_series(1,$1) gs;
`, rows)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `
INSERT INTO content_logs(id,request_id,tenant_id,role,content)
SELECT 'content-'||lpad(gs::text,12,'0'),'log-'||lpad(gs::text,12,'0'),
       'tenant-'||lpad((gs%100)::text,3,'0'),
       CASE WHEN gs%20=0 THEN 'assistant' ELSE 'user' END,'synthetic scale content'
FROM generate_series(10,$1,10) gs`, rows)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `ANALYZE request_logs; ANALYZE content_logs;`)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"../../../../deploy/migrations/820_customer_content_projection_triggers.sql",
		"../../../../deploy/migrations/821_serialize_customer_content_projection.sql",
		"../../../../deploy/migrations/832_migration_backfill_framework.sql",
		"../../../../deploy/migrations/834_customer_content_projection_backfill.sql",
	} {
		body, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, err = db.Exec(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
	_, err = db.Exec(ctx, `UPDATE migration_backfill_tasks SET batch_size=5000,
 rate_limit_rows_per_second=100000,statement_timeout_ms=120000
WHERE task_name='customer_content_projection_v1'`)
	if err != nil {
		t.Fatal(err)
	}

	var beforeLSN string
	var beforeBytes int64
	if err = db.QueryRow(ctx, "SELECT pg_current_wal_lsn()::text,pg_database_size(current_database())").Scan(&beforeLSN, &beforeBytes); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	store := NewPostgresStore(db)
	owner := "scale-a"
	batches := 0
	var scanned, updated, skipped int64
	writerDone := make(chan error, 1)
	writerLatencies := make(chan time.Duration, 200)
	writerStarted := false
	for {
		task, claimErr := store.Claim(ctx, owner, 15*time.Second)
		if claimErr != nil || task == nil {
			t.Fatalf("claim batch %d: task=%v err=%v", batches, task, claimErr)
		}
		if !writerStarted {
			writerStarted = true
			go func() {
				for i := 0; i < 200; i++ {
					startedWrite := time.Now()
					id := fmt.Sprintf("live-%012d", i)
					requestID := fmt.Sprintf("live-req-%012d", i)
					if _, writeErr := db.Exec(ctx, `INSERT INTO request_logs(
 id,request_id,tenant_id,proxy_mode,has_customer_content,
 has_customer_request_body,has_customer_response_body,created_at
) VALUES($1,$2,'tenant-live','api',false,false,false,NOW())`, id, requestID); writeErr != nil {
						writerDone <- writeErr
						return
					}
					if _, writeErr := db.Exec(ctx, `INSERT INTO content_logs(
 id,request_id,tenant_id,role,content
) VALUES($1,$2,'tenant-live','user','synthetic concurrent content')`,
						fmt.Sprintf("live-content-%012d", i), id); writeErr != nil {
						writerDone <- writeErr
						return
					}
					writerLatencies <- time.Since(startedWrite)
					time.Sleep(5 * time.Millisecond)
				}
				writerDone <- nil
			}()
		}
		result, batchErr := store.RunBatch(ctx, task, owner, 15*time.Second)
		if batchErr != nil {
			t.Fatalf("batch %d: %v", batches, batchErr)
		}
		batches++
		scanned += result.Scanned
		updated += result.Updated
		skipped += result.Skipped
		if batches%100 == 0 {
			fmt.Printf("SCALE_PROGRESS rows=%d batches=%d scanned=%d elapsed=%s\n",
				rows, batches, scanned, time.Since(started).Round(time.Second))
		}
		if batches == 3 {
			_, err = db.Exec(ctx, `UPDATE migration_backfill_tasks
SET lease_expires_at=NOW()-interval '1 second' WHERE task_name=$1`, task.Name)
			if err != nil {
				t.Fatal(err)
			}
			owner = "scale-resumed"
		}
		if result.Done {
			if err = store.Complete(ctx, task, owner, result); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if writerErr := <-writerDone; writerErr != nil {
		t.Fatal(writerErr)
	}
	close(writerLatencies)
	latencies := make([]float64, 0, 200)
	for latency := range writerLatencies {
		latencies = append(latencies, float64(latency.Microseconds())/1000)
	}
	sort.Float64s(latencies)
	percentile := func(value float64) float64 {
		index := int(float64(len(latencies)-1) * value)
		return latencies[index]
	}
	duration := time.Since(started)
	var walBytes, afterBytes, incorrect int64
	err = db.QueryRow(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_lsn(),$1::pg_lsn)::bigint,
pg_database_size(current_database()),
(SELECT COUNT(*) FROM request_logs WHERE customer_content_rule_version<>1
 OR has_customer_content IS NULL OR has_customer_request_body IS NULL OR has_customer_response_body IS NULL)`,
		beforeLSN).Scan(&walBytes, &afterBytes, &incorrect)
	if err != nil {
		t.Fatal(err)
	}
	if incorrect != 0 || scanned != int64(rows) || updated != int64(rows) {
		t.Fatalf("incomplete scale backfill rows=%d scanned=%d updated=%d incorrect=%d", rows, scanned, updated, incorrect)
	}
	metrics := map[string]any{
		"rows": rows, "batches": batches, "duration_seconds": duration.Seconds(),
		"rows_per_second": float64(rows) / duration.Seconds(), "wal_bytes": walBytes,
		"database_bytes_before": beforeBytes, "database_bytes_after": afterBytes,
		"scanned": scanned, "updated": updated, "skipped": skipped,
		"crash_resume_after_batches": 3, "consistent": true,
		"concurrent_writes": len(latencies), "write_p95_ms": percentile(0.95),
		"write_p99_ms": percentile(0.99),
	}
	encoded, _ := json.Marshal(metrics)
	fmt.Printf("BACKFILL_METRICS=%s\n", encoded)
}
