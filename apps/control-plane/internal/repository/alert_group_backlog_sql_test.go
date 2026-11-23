package repository

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 只读统计 SQL（deploy/sql/readonly/alert_group_backlog_stats.sql）必须与 AutoCloseStale 的
// 护栏条件保持一致，且不得含任何写语句。仓储层改了条件而忘了同步统计 SQL 时，这里会失败。
func TestAlertGroupBacklogStatsSQLMatchesAutoCloseGuards(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "sql", "readonly", "alert_group_backlog_stats.sql"))
	if err != nil {
		t.Fatalf("read stats sql: %v", err)
	}
	var code []string
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		code = append(code, line)
	}
	body := strings.Join(code, "\n")
	norm := func(s string) string {
		return strings.Join(strings.Fields(strings.ReplaceAll(s, "ag.", "")), " ")
	}
	nb := norm(body)

	if !strings.Contains(nb, "BEGIN TRANSACTION READ ONLY;") || !strings.Contains(nb, "ROLLBACK;") {
		t.Fatal("stats sql must run inside a read-only transaction")
	}
	if m := regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|ALTER|DROP|TRUNCATE|CREATE|GRANT|REVOKE|COPY|COMMIT)\b`).FindString(body); m != "" {
		t.Fatalf("stats sql must be SELECT-only, found %q", m)
	}
	guard := norm(redlineFindingGuardSQL)
	if strings.Count(nb, guard) < 2 {
		t.Fatalf("stats sql must reuse the exact redline guard for both AutoCloseStale branches:\n%s", guard)
	}
	for _, clause := range []string{
		"WHERE status IN ('open', 'acknowledged')",
		"last_seen_at < p.cutoff AND stage = 'input' AND NOT is_canary AND",
		"alert_type = 'runtime_fault' AND last_seen_at < p.fault_cutoff AND NOT is_canary AND",
		"now() - interval '6 hours' AS fault_cutoff",
	} {
		if !strings.Contains(nb, clause) {
			t.Fatalf("stats sql missing AutoCloseStale clause %q", clause)
		}
	}
	if FaultQuietTTL.Hours() != 6 {
		t.Fatalf("FaultQuietTTL changed to %v; update the 6 hours window in the stats sql", FaultQuietTTL)
	}
}
