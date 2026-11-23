package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMITMBypassEnvironmentEmitsStartupLog(t *testing.T) {
	t.Setenv("PROXY_MITM_BYPASS_SUFFIXES", " .PRIVATE-CDN.invalid,downloads.private.invalid,.private-cdn.invalid ")
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	NewProxyHandler(nil, nil, nil, nil, nil)
	for _, want := range []string{"PROXY_MITM_BYPASS_SUFFIXES", ".private-cdn.invalid", "downloads.private.invalid", "coverage_gap=true"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("startup bypass log missing %q: %s", want, output.String())
		}
	}
}

func TestFBypassDatabasePersistsStartupAudit(t *testing.T) {
	dsn := os.Getenv("C_WHITELIST_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("C_WHITELIST_TEST_DATABASE_URL is required: disposable migrated PostgreSQL")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	t.Setenv("PROXY_MITM_BYPASS_SUFFIXES", ".F-AUDIT-CDN.invalid, files.f-audit.invalid,.f-audit-cdn.invalid")
	checker := &WhitelistChecker{tenantID: "tenant_default"}
	NewProxyHandler(checker, nil, nil, NewAuditWriter(db), nil)
	var detail []byte
	if err := db.QueryRow(ctx, `SELECT action_detail FROM audit_operations WHERE action_type='proxy_mitm_bypass.env' AND target_type='forward_proxy' AND target_id='tenant_default' ORDER BY created_at DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("startup bypass audit unavailable: %v", err)
	}
	var record struct {
		Source      string   `json:"source"`
		TenantID    string   `json:"tenant_id"`
		CoverageGap bool     `json:"coverage_gap"`
		Suffixes    []string `json:"suffixes"`
	}
	if err := json.Unmarshal(detail, &record); err != nil {
		t.Fatal(err)
	}
	if record.Source != "PROXY_MITM_BYPASS_SUFFIXES" || record.TenantID != "tenant_default" || !record.CoverageGap || strings.Join(record.Suffixes, ",") != ".f-audit-cdn.invalid,files.f-audit.invalid" {
		t.Fatalf("incorrect bypass audit: %s", detail)
	}
}

func TestRawDumpDirectoryCannotEnablePlaintextCapture(t *testing.T) {
	t.Setenv("PROXY_RAW_DUMP_DIR", "")
	dir := "/tmp/proxy-raw-dump"
	_, err := os.Stat(dir)
	created := os.IsNotExist(err)
	if err != nil && !created {
		t.Fatal(err)
	}
	if created {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Remove(dir); err != nil {
				t.Error(err)
			}
		})
	}
	if got := rawDumpDir(); got != "" {
		t.Fatalf("directory presence enabled plaintext capture: %q", got)
	}
	if files, err := filepath.Glob(filepath.Join(dir, "*")); err != nil || created && len(files) != 0 {
		t.Fatalf("unexpected plaintext files: %v err=%v", files, err)
	}
	t.Setenv("PROXY_RAW_DUMP_DIR", t.TempDir())
	if got := rawDumpDir(); got == "" {
		t.Fatal("explicit diagnostic environment must enable capture")
	}
}
