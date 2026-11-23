package compliance_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/compliance"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
)

func decodeExportJSONExact(t *testing.T, data []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal("invalid evidence JSON")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("evidence JSON has trailing content")
	}
	return decoded
}

func TestExportZipPreservesExactStoredPayloadAndEvidence(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("connect test database")
	}
	defer pool.Close()
	repo := repository.NewAuditChainRepository(pool, []byte("synthetic-audit-export-test-key"))
	eventID := "export-precision-" + time.Now().UTC().Format("20060102T150405.000000000")
	payload := map[string]any{
		"amount_micros": json.Number("9007199254740993"),
		"debit_micros":  json.Number("-9007199254740993"),
		"unsigned_id":   json.Number("18446744073709551615"),
		"fraction":      json.Number("0.000001"),
		"opaque_text":   "a<b&c>\u2028",
		"nested":        []any{map[string]any{"counter": json.Number("9007199254740992")}, nil, []any{}, true},
	}
	if err := repo.Append(ctx, "audit-export-test", "precision_test", eventID, payload); err != nil {
		t.Fatal("append precision fixture")
	}
	var seq int64
	var storedJSON []byte
	var storedPayloadHash, storedChainHash, storedSignature string
	if err := pool.QueryRow(ctx, `SELECT seq,payload_json,payload_hash,chain_hash,signature FROM audit_chain WHERE event_id=$1`, eventID).Scan(&seq, &storedJSON, &storedPayloadHash, &storedChainHash, &storedSignature); err != nil {
		t.Fatal("read immutable fixture")
	}
	before := decodeExportJSONExact(t, storedJSON)
	var archive bytes.Buffer
	if err := compliance.NewExporter(repo).ExportZip(ctx, seq, seq, "2026-10-12T00:00:00Z", &archive); err != nil {
		t.Fatal("export precision fixture")
	}
	zr, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal("open evidence ZIP")
	}
	files := map[string][]byte{}
	for _, file := range zr.File {
		reader, err := file.Open()
		if err != nil {
			t.Fatal("open evidence entry")
		}
		data, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			t.Fatal("read evidence entry")
		}
		files[file.Name] = data
	}
	lines := bytes.Split(bytes.TrimSpace(files["audit_chain.jsonl"]), []byte("\n"))
	if len(lines) != 1 {
		t.Fatal("evidence record count differs")
	}
	record := decodeExportJSONExact(t, lines[0])
	if !reflect.DeepEqual(record["payload_json"], before) {
		t.Fatal("export changed exact stored payload values or structure")
	}
	if record["payload_hash"] != storedPayloadHash || record["chain_hash"] != storedChainHash || record["signature"] != storedSignature {
		t.Fatal("export changed original evidence hashes or signature")
	}
	certificate := decodeExportJSONExact(t, files["certificate.json"])
	if certificate["verify_ok"] != true {
		t.Fatal("lossless exported evidence failed integrity verification")
	}
	var afterJSON []byte
	var afterPayloadHash, afterChainHash, afterSignature string
	if err := pool.QueryRow(ctx, `SELECT payload_json,payload_hash,chain_hash,signature FROM audit_chain WHERE event_id=$1`, eventID).Scan(&afterJSON, &afterPayloadHash, &afterChainHash, &afterSignature); err != nil {
		t.Fatal("reread immutable fixture")
	}
	if !bytes.Equal(storedJSON, afterJSON) || storedPayloadHash != afterPayloadHash || storedChainHash != afterChainHash || storedSignature != afterSignature {
		t.Fatal("export modified immutable database evidence")
	}
}
