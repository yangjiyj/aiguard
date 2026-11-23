package compliance_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/compliance"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestExportZip_RoundTrip(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	defer pool.Close()

	// Use a fixed test key
	key := []byte("test-hmac-key-32-bytes-padding!!")
	repo := repository.NewAuditChainRepository(pool, key)

	// Get current max seq before appending
	statsBefore, err := repo.Stats(ctx)
	if err != nil {
		t.Fatalf("stats before: %v", err)
	}
	fromSeq := statsBefore.MaxSeq + 1

	// Append 3 test records
	const nRecords = 3
	for i := 0; i < nRecords; i++ {
		if err := repo.Append(ctx, "test-tenant", "compliance_test", "evt-export-"+string(rune('A'+i)), map[string]any{
			"index": i,
			"label": "export_test",
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// Get the new max seq
	statsAfter, err := repo.Stats(ctx)
	if err != nil {
		t.Fatalf("stats after: %v", err)
	}
	toSeq := statsAfter.MaxSeq

	if toSeq-fromSeq+1 < nRecords {
		t.Fatalf("expected at least %d new records, got from=%d to=%d", nRecords, fromSeq, toSeq)
	}

	// Export the range
	exporter := compliance.NewExporter(repo)
	var buf bytes.Buffer
	if err := exporter.ExportZip(ctx, fromSeq, toSeq, "2026-05-30T00:00:00Z", &buf); err != nil {
		t.Fatalf("ExportZip: %v", err)
	}

	// Read back the ZIP
	zipData := buf.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}

	// Expect exactly 2 files
	if len(zr.File) != 2 {
		t.Fatalf("expected 2 zip entries, got %d", len(zr.File))
	}

	fileByName := make(map[string]*zip.File)
	for _, f := range zr.File {
		fileByName[f.Name] = f
	}

	// --- audit_chain.jsonl ---
	jf, ok := fileByName["audit_chain.jsonl"]
	if !ok {
		t.Fatal("audit_chain.jsonl not found in zip")
	}
	jrc, err := jf.Open()
	if err != nil {
		t.Fatalf("open jsonl: %v", err)
	}
	defer jrc.Close()

	var jsonlBuf bytes.Buffer
	if _, err := jsonlBuf.ReadFrom(jrc); err != nil {
		t.Fatalf("read jsonl: %v", err)
	}

	// Count lines
	lines := bytes.Split(bytes.TrimRight(jsonlBuf.Bytes(), "\n"), []byte("\n"))
	// Filter empty lines
	var nonEmpty [][]byte
	for _, l := range lines {
		if len(bytes.TrimSpace(l)) > 0 {
			nonEmpty = append(nonEmpty, l)
		}
	}
	if len(nonEmpty) != nRecords {
		t.Errorf("expected %d jsonl lines, got %d", nRecords, len(nonEmpty))
	}

	// Validate each line parses as JSON with expected fields
	for i, line := range nonEmpty {
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Errorf("line %d invalid JSON: %v", i, err)
			continue
		}
		for _, field := range []string{"seq", "tenant_id", "event_type", "event_id", "chain_hash", "created_at"} {
			if _, exists := rec[field]; !exists {
				t.Errorf("line %d missing field %q", i, field)
			}
		}
	}

	// --- certificate.json ---
	cf, ok := fileByName["certificate.json"]
	if !ok {
		t.Fatal("certificate.json not found in zip")
	}
	crc, err := cf.Open()
	if err != nil {
		t.Fatalf("open certificate: %v", err)
	}
	defer crc.Close()

	var certBuf bytes.Buffer
	if _, err := certBuf.ReadFrom(crc); err != nil {
		t.Fatalf("read certificate: %v", err)
	}

	var cert map[string]any
	if err := json.Unmarshal(certBuf.Bytes(), &cert); err != nil {
		t.Fatalf("parse certificate.json: %v", err)
	}

	// verify_ok must be true
	verifyOK, _ := cert["verify_ok"].(bool)
	if !verifyOK {
		t.Errorf("certificate verify_ok=false, cert: %s", certBuf.String())
	}

	// record_count must match nRecords
	recordCount, _ := cert["record_count"].(float64)
	if int(recordCount) != nRecords {
		t.Errorf("certificate record_count=%v, expected %d", recordCount, nRecords)
	}

	// exported_at must match what we passed
	exportedAt, _ := cert["exported_at"].(string)
	if exportedAt != "2026-05-30T00:00:00Z" {
		t.Errorf("certificate exported_at=%q, unexpected", exportedAt)
	}

	t.Logf("ExportZip OK: %d bytes ZIP, %d records, verify_ok=%v", len(zipData), nRecords, verifyOK)
}
