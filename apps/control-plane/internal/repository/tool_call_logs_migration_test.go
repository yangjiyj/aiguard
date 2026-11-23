package repository

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToolCallLogIDMigrationUsesNinetySixBits(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "deploy", "migrations", "123_tool_call_log_id_entropy.sql")
	migration, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tool call log ID migration: %v", err)
	}
	normalized := strings.Join(strings.Fields(string(migration)), " ")
	if !strings.Contains(normalized, "ALTER TABLE IF EXISTS tool_call_logs ALTER COLUMN id SET DEFAULT") {
		t.Fatalf("migration must update the tool_call_logs ID default: %s", normalized)
	}
	if !strings.Contains(normalized, "substr(replace(gen_random_uuid()::text, '-', ''), 1, 24)") {
		t.Fatalf("migration must use 24 UUID hex characters: %s", normalized)
	}
}

func TestToolCallLogBootstrapSchemaUsesNinetySixBits(t *testing.T) {
	path := filepath.Join("..", "..", "sql", "tool_call_audit.sql")
	schema, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tool call log bootstrap schema: %v", err)
	}
	normalized := strings.Join(strings.Fields(string(schema)), " ")
	expected := "id VARCHAR(64) PRIMARY KEY DEFAULT 'tc_' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 24)"
	if !strings.Contains(normalized, expected) {
		t.Fatalf("bootstrap schema must use the canonical 96-bit ID default: %s", normalized)
	}
}
