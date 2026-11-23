package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/corpusscan"
)

// 语料扫描仓储的 PostgreSQL 测试：CORPUS_SCAN_TEST_DATABASE_URL 指向可丢弃测试库，未设置则跳过。
// 每个测试新建独立 schema 并执行迁移 990。
func corpusScanPG(t *testing.T) *PostgresCorpusScanStore {
	t.Helper()
	dsn := os.Getenv("CORPUS_SCAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CORPUS_SCAN_TEST_DATABASE_URL must point to a disposable database")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "corpus_scan_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migration, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "migrations", "990_corpus_scan_jobs.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	return NewPostgresCorpusScanStore(pool)
}

func corpusDigest(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func newCorpusJob(t *testing.T, store *PostgresCorpusScanStore, tenant, content string) CorpusScanJob {
	t.Helper()
	job, err := store.Create(context.Background(), CorpusScanCreate{
		TenantID: tenant, CreatedBy: "u1", FileName: "a.jsonl", Format: corpusscan.FormatJSONL,
		SizeBytes: int64(len(content)), SHA256: corpusDigest(content),
	})
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func uploadAll(t *testing.T, store *PostgresCorpusScanStore, job CorpusScanJob, parts ...string) CorpusScanJob {
	t.Helper()
	var err error
	for index, part := range parts {
		job, err = store.AppendChunk(context.Background(), job.TenantID, job.ID, CorpusScanChunk{Index: index, Size: int64(len(part)), Key: job.ID + "/" + string(rune('a'+index)), Data: []byte(part)})
		if err != nil {
			t.Fatalf("chunk %d: %v", index, err)
		}
	}
	return job
}

func TestCorpusScanStoreTenantIsolation(t *testing.T) {
	store := corpusScanPG(t)
	ctx := context.Background()
	job := newCorpusJob(t, store, "tenant-a", "0123456789")
	if _, err := store.Get(ctx, "tenant-b", job.ID); !errors.Is(err, ErrCorpusScanNotFound) {
		t.Fatalf("cross-tenant get err = %v", err)
	}
	if _, err := store.AppendChunk(ctx, "tenant-b", job.ID, CorpusScanChunk{Index: 0, Size: 1, Key: "k", Data: []byte("0")}); !errors.Is(err, ErrCorpusScanNotFound) {
		t.Fatalf("cross-tenant chunk err = %v", err)
	}
	if _, err := store.Queue(ctx, "tenant-b", job.ID); !errors.Is(err, ErrCorpusScanNotFound) {
		t.Fatalf("cross-tenant queue err = %v", err)
	}
	if _, err := store.Cancel(ctx, "tenant-b", job.ID); !errors.Is(err, ErrCorpusScanNotFound) {
		t.Fatalf("cross-tenant cancel err = %v", err)
	}
	if _, err := store.Delete(ctx, "tenant-b", job.ID); !errors.Is(err, ErrCorpusScanNotFound) {
		t.Fatalf("cross-tenant delete err = %v", err)
	}
	if items, err := store.List(ctx, "tenant-b", 50); err != nil || len(items) != 0 {
		t.Fatalf("tenant-b list = %+v err=%v", items, err)
	}
	if items, err := store.List(ctx, "tenant-a", 50); err != nil || len(items) != 1 || items[0].ID != job.ID {
		t.Fatalf("tenant-a list = %+v err=%v", items, err)
	}
}

func TestCorpusScanStoreChunksAreSequentialAndHashed(t *testing.T) {
	store := corpusScanPG(t)
	ctx := context.Background()
	job := newCorpusJob(t, store, "tenant-a", "0123456789")
	if _, err := store.AppendChunk(ctx, "tenant-a", job.ID, CorpusScanChunk{Index: 1, Size: 4, Key: "k1", Data: []byte("4567")}); !errors.Is(err, ErrCorpusScanChunkOrder) {
		t.Fatalf("out of order chunk err = %v", err)
	}
	updated, err := store.AppendChunk(ctx, "tenant-a", job.ID, CorpusScanChunk{Index: 0, Size: 4, Key: "k0", Data: []byte("0123")})
	if err != nil || updated.NextChunk != 1 || updated.UploadedBytes != 4 || len(updated.SourceKeys) != 1 {
		t.Fatalf("chunk 0 = %+v err=%v", updated, err)
	}
	if _, err := store.Queue(ctx, "tenant-a", job.ID); !errors.Is(err, ErrCorpusScanIncomplete) {
		t.Fatalf("queue before upload complete err = %v", err)
	}
	if _, err := store.AppendChunk(ctx, "tenant-a", job.ID, CorpusScanChunk{Index: 1, Size: 7, Key: "k1", Data: []byte("4567890")}); !errors.Is(err, ErrCorpusScanTooLarge) {
		t.Fatalf("oversized total err = %v", err)
	}
	updated, err = store.AppendChunk(ctx, "tenant-a", job.ID, CorpusScanChunk{Index: 1, Size: 6, Key: "k1", Data: []byte("456789")})
	if err != nil || updated.UploadedBytes != 10 || strings.Join(updated.SourceKeys, ",") != "k0,k1" {
		t.Fatalf("chunk 1 = %+v err=%v", updated, err)
	}
	queued, err := store.Queue(ctx, "tenant-a", job.ID)
	if err != nil || queued.Status != "queued" {
		t.Fatalf("queue = %+v err=%v", queued, err)
	}
}

func TestCorpusScanStoreRejectsDigestMismatch(t *testing.T) {
	store := corpusScanPG(t)
	ctx := context.Background()
	job := newCorpusJob(t, store, "tenant-a", "0123456789")
	uploadAll(t, store, job, "01234", "XXXXX")
	if _, err := store.Queue(ctx, "tenant-a", job.ID); !errors.Is(err, ErrCorpusScanDigest) {
		t.Fatalf("digest mismatch err = %v", err)
	}
}

func TestCorpusScanStoreRunsOneJobAtATimeInOrder(t *testing.T) {
	store := corpusScanPG(t)
	ctx := context.Background()
	first := uploadAll(t, store, newCorpusJob(t, store, "tenant-a", "aaaa"), "aaaa")
	second := uploadAll(t, store, newCorpusJob(t, store, "tenant-b", "bbbb"), "bbbb")
	if _, err := store.Queue(ctx, "tenant-a", first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Queue(ctx, "tenant-b", second.ID); err != nil {
		t.Fatalf("second job must be able to queue: %v", err)
	}
	running, ok, err := store.ClaimNext(ctx, "owner-1")
	if err != nil || !ok || running.ID != first.ID || running.Status != "running" {
		t.Fatalf("claim = %+v ok=%v err=%v", running, ok, err)
	}
	if _, ok, err := store.ClaimNext(ctx, "owner-2"); err != nil || ok {
		t.Fatalf("second claim while running: ok=%v err=%v", ok, err)
	}
	if err := store.Heartbeat(ctx, running, corpusscan.Progress{ProcessedBytes: 2, TotalRecords: 1}); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.Get(ctx, "tenant-a", first.ID); got.ProcessedBytes != 2 || got.TotalRecords != 1 {
		t.Fatalf("progress = %+v", got)
	}
	stolen := running
	stolen.ownerToken = "someone-else"
	if err := store.Heartbeat(ctx, stolen, corpusscan.Progress{}); !errors.Is(err, ErrCorpusScanLeaseLost) {
		t.Fatalf("foreign heartbeat err = %v", err)
	}
	// 租约过期后标为 interrupted，排在后面的任务接着运行。
	if _, err := store.pool.Exec(ctx, `UPDATE corpus_scan_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	next, ok, err := store.ClaimNext(ctx, "owner-2")
	if err != nil || !ok || next.ID != second.ID {
		t.Fatalf("claim after interruption = %+v ok=%v err=%v", next, ok, err)
	}
	got, _ := store.Get(ctx, "tenant-a", first.ID)
	if got.Status != "interrupted" || got.ErrorCode != "worker_interrupted" {
		t.Fatalf("expired job = %+v", got)
	}
	if err := store.Heartbeat(ctx, running, corpusscan.Progress{}); !errors.Is(err, ErrCorpusScanLeaseLost) {
		t.Fatalf("heartbeat after interruption err = %v", err)
	}
	if pending, err := store.PendingSourceCleanup(ctx, 10); err != nil || len(pending) != 1 || pending[0].ID != first.ID {
		t.Fatalf("pending cleanup = %+v err=%v", pending, err)
	}
}

func TestCorpusScanStoreCancelAndFinish(t *testing.T) {
	store := corpusScanPG(t)
	ctx := context.Background()
	uploading := newCorpusJob(t, store, "tenant-a", "aaaa")
	canceled, err := store.Cancel(ctx, "tenant-a", uploading.ID)
	if err != nil || canceled.Status != "canceled" || !canceled.CancelRequested {
		t.Fatalf("cancel uploading = %+v err=%v", canceled, err)
	}
	if _, err := store.AppendChunk(ctx, "tenant-a", uploading.ID, CorpusScanChunk{Index: 0, Size: 4, Key: "k", Data: []byte("aaaa")}); !errors.Is(err, ErrCorpusScanState) {
		t.Fatalf("chunk after cancel err = %v", err)
	}

	job := uploadAll(t, store, newCorpusJob(t, store, "tenant-a", "bbbb"), "bbbb")
	if _, err := store.Queue(ctx, "tenant-a", job.ID); err != nil {
		t.Fatal(err)
	}
	running, ok, err := store.ClaimNext(ctx, "owner")
	if err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	if got, _ := store.Cancel(ctx, "tenant-a", job.ID); got.Status != "running" || !got.CancelRequested {
		t.Fatalf("cancel running = %+v", got)
	}
	if err := store.Heartbeat(ctx, running, corpusscan.Progress{}); !errors.Is(err, ErrCorpusScanCanceled) {
		t.Fatalf("heartbeat after cancel request err = %v", err)
	}
	if err := store.Finish(ctx, running, CorpusScanOutcome{Status: "succeeded", ReportKey: "r", MaskedKey: "m", MaskedFormat: "jsonl"}); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(ctx, "tenant-a", job.ID)
	if got.Status != "canceled" || got.HasReport || got.HasMasked || got.CompletedAt == nil {
		t.Fatalf("finish after cancel request = %+v", got)
	}

	queuedJob := uploadAll(t, store, newCorpusJob(t, store, "tenant-a", "cccc"), "cccc")
	if _, err := store.Queue(ctx, "tenant-a", queuedJob.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.Cancel(ctx, "tenant-a", queuedJob.ID); got.Status != "canceled" {
		t.Fatalf("cancel queued = %+v", got)
	}
	if _, ok, _ := store.ClaimNext(ctx, "owner"); ok {
		t.Fatal("canceled queued job must not be claimed")
	}
}

func TestCorpusScanStoreSucceededJobKeepsReportAndExpires(t *testing.T) {
	store := corpusScanPG(t)
	ctx := context.Background()
	job := uploadAll(t, store, newCorpusJob(t, store, "tenant-a", "dddd"), "dddd")
	if _, err := store.Queue(ctx, "tenant-a", job.ID); err != nil {
		t.Fatal(err)
	}
	running, _, err := store.ClaimNext(ctx, "owner")
	if err != nil {
		t.Fatal(err)
	}
	report := corpusscan.Report{
		Progress:        corpusscan.Progress{TotalRecords: 2, ScannedRecords: 1, HitRecords: 1, UnscannedRecords: 1},
		Stats:           []corpusscan.TypeStat{{Type: "phone_cn", Label: "手机号", Hits: 2, Records: 1}},
		Samples:         []corpusscan.Sample{{Line: 1, Field: "text", Type: "phone_cn", Label: "手机号", Start: 0, End: 11, Preview: "1****8"}},
		Unscanned:       []corpusscan.UnscannedLine{{Line: 2, Reason: "unparsable"}},
		RulePackVersion: "rp-9",
	}
	if err := store.Finish(ctx, running, CorpusScanOutcome{Status: "succeeded", Report: report, Notes: []string{"n"}, ReportKey: "rk", MaskedKey: "mk", MaskedFormat: "jsonl"}); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(ctx, "tenant-a", job.ID)
	if got.Status != "succeeded" || got.HitRecords != 1 || got.RulePackVersion != "rp-9" || len(got.Samples) != 1 ||
		len(got.Stats) != 1 || len(got.Unscanned) != 1 || len(got.Notes) != 1 || !got.HasReport || !got.HasMasked {
		t.Fatalf("succeeded job = %+v", got)
	}
	if got.ExpiresAt.Before(time.Now().Add(6 * 24 * time.Hour)) {
		t.Fatalf("expires_at = %v, want about 7 days", got.ExpiresAt)
	}
	if err := store.ClearSourceKeys(ctx, got); err != nil {
		t.Fatal(err)
	}
	if pending, _ := store.PendingSourceCleanup(ctx, 10); len(pending) != 0 {
		t.Fatalf("source keys not cleared: %+v", pending)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE corpus_scan_jobs SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	expired, err := store.Expired(ctx, 10)
	if err != nil || len(expired) != 1 || expired[0].ID != job.ID || expired[0].ReportKey != "rk" {
		t.Fatalf("expired = %+v err=%v", expired, err)
	}
	if err := store.Purge(ctx, expired[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "tenant-a", job.ID); !errors.Is(err, ErrCorpusScanNotFound) {
		t.Fatalf("purged job still visible: %v", err)
	}
}

func TestCorpusScanStoreRefusesToDeleteRunningJobs(t *testing.T) {
	store := corpusScanPG(t)
	ctx := context.Background()
	job := uploadAll(t, store, newCorpusJob(t, store, "tenant-a", "eeee"), "eeee")
	if _, err := store.Queue(ctx, "tenant-a", job.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ClaimNext(ctx, "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Delete(ctx, "tenant-a", job.ID); !errors.Is(err, ErrCorpusScanState) {
		t.Fatalf("delete running job err = %v", err)
	}
	deleted := newCorpusJob(t, store, "tenant-a", "ffff")
	removed, err := store.Delete(ctx, "tenant-a", deleted.ID)
	if err != nil || removed.ID != deleted.ID {
		t.Fatalf("delete uploading job = %+v err=%v", removed, err)
	}
}
