package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func rawEvidenceTestSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// 告警命中原文入库（2.9.22）后案件归并与“有无新证据”判定不变。需要 ALERT_RAW_EVIDENCE_TEST_DATABASE_URL
// 指向按正式流程（initdb 快照 + migration-runner）迁移到最新的库，读取走迁移 850/851/1010 的生成列。
//
// 同一凭据命中：升级前事件按 2.9.21 落库（打码前后文、只存原文哈希），升级后事件带原文和按旧口径算好的
// 证据身份。两者必须落在同一个案件里；案件处置为已解决后，升级后同一证据的事件不能让案件因“新证据”重开，
// 真正不同的证据仍要重开。
func TestRawEvidenceEventsKeepCaseAndEvidenceNoveltyOnPostgres(t *testing.T) {
	dsn := os.Getenv("ALERT_RAW_EVIDENCE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ALERT_RAW_EVIDENCE_TEST_DATABASE_URL not set; skipping migrated-database alert case test")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ns := fmt.Sprintf("rawev_%d", time.Now().UnixNano())
	tenantID, projectID := "tenant_"+ns, "proj_"+ns
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%v: %s", err, query)
		}
	}
	exec(`INSERT INTO tenants (id, name, is_test) VALUES ($1, $1, TRUE)`, tenantID)
	exec(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $1)`, projectID, tenantID)
	t.Cleanup(func() {
		c := context.Background()
		db.Exec(c, `DELETE FROM security_events WHERE tenant_id = $1`, tenantID)
		db.Exec(c, `DELETE FROM audit_dispositions WHERE tenant_id = $1`, tenantID)
		db.Exec(c, `DELETE FROM request_logs WHERE tenant_id = $1`, tenantID)
		db.Exec(c, `DELETE FROM projects WHERE id = $1`, projectID)
		db.Exec(c, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	finding := func(extra map[string]any) map[string]any {
		f := map[string]any{
			"type": "secret", "category": "generic_api_key", "severity": "critical", "confidence": 1,
			"matched_location": "content[8:44]", "content_source": "user", "evidence_kind": "literal",
			"matched_text_preview": "ey****J9（36 位）", "redacted_evidence": "API_KEY: *****（5 位）",
		}
		for key, value := range extra {
			f[key] = value
		}
		return f
	}
	legacyContext := "export API_KEY=<已隐藏 30 字> # deploy"
	before := finding(map[string]any{
		"raw_evidence_sha256": rawEvidenceTestSHA256("API_KEY=eyJhbGciOiJIUzI1NiJ9xxxxxxxxJ9"),
		"evidence_context":    legacyContext,
	})
	after := finding(map[string]any{
		"raw_evidence_sha256":      rawEvidenceTestSHA256("API_KEY=eyJhbGciOiJIUzI1NiJ9xxxxxxxxJ9"),
		"raw_evidence":             "API_KEY=eyJhbGciOiJIUzI1NiJ9xxxxxxxxJ9",
		"evidence_context":         "export API_KEY=eyJhbGciOiJIUzI1NiJ9xxxxxxxxJ9 # deploy",
		"evidence_identity_sha256": rawEvidenceTestSHA256(legacyContext),
	})
	different := finding(map[string]any{
		"raw_evidence_sha256":      rawEvidenceTestSHA256("API_KEY=eyJhbGciOiJIUzI1NiJ9yyyyyyyyyyJ9"),
		"raw_evidence":             "API_KEY=eyJhbGciOiJIUzI1NiJ9yyyyyyyyyyJ9",
		"evidence_context":         "export API_KEY=eyJhbGciOiJIUzI1NiJ9yyyyyyyyyyJ9 # other",
		"evidence_identity_sha256": rawEvidenceTestSHA256("export API_KEY=<已隐藏 32 字> # other"),
	})
	insertEvent := func(id string, at time.Time, f map[string]any) {
		t.Helper()
		requestID := id + "_" + ns
		exec(`INSERT INTO request_logs (id, request_id, tenant_id, project_id, client_id, created_at) VALUES ($1, $1, $2, $3, 'key_rawev', $4)`,
			requestID, tenantID, projectID, at)
		summary, _ := json.Marshal(map[string]any{
			"source": "gateway", "stage": "input", "action_taken": "audit", "category": "generic_api_key",
			"findings": []any{f}, "primary_finding": f, "findings_count": 1,
		})
		exec(`INSERT INTO security_events (id, request_id, tenant_id, project_id, event_type, severity, action_taken, matched_summary, conversation_key, created_at)
			VALUES ($1, $2, $3, $4, 'security_check', 'critical', 'audit', $5::jsonb, 'conv_rawev', $6)`,
			id+"_"+ns, requestID, tenantID, projectID, string(summary), at)
	}
	repo := NewAlertOccurrenceRepository(db)
	onlyCase := func(wantHits int, wantStatus string) string {
		t.Helper()
		page, err := repo.List(ctx, AlertOccurrenceFilter{TenantID: tenantID, Grouping: "cases", IncludeSuppressed: true, CanReadEvidence: true, Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 1 {
			t.Fatalf("同一凭据命中应只有一个案件，实际 %d 个: %+v", len(page.Items), page.Items)
		}
		item := page.Items[0]
		if item.HitCount != wantHits || item.DispositionStatus != wantStatus {
			t.Fatalf("案件 hit_count=%d 状态=%s，期望 %d / %s", item.HitCount, item.DispositionStatus, wantHits, wantStatus)
		}
		return item.CaseID
	}

	insertEvent("e_before", time.Now().Add(-3*time.Hour), before)
	caseID := onlyCase(1, "open")
	exec(`INSERT INTO audit_dispositions (tenant_id, subject_type, subject_id, status, case_seen_through, updated_at) VALUES ($1, 'alert_case', $2, 'resolved', $3, $3)`,
		tenantID, caseID, time.Now().Add(-2*time.Hour))
	onlyCase(1, "resolved")

	insertEvent("e_after", time.Now(), after)
	if got := onlyCase(2, "resolved"); got != caseID {
		t.Fatalf("升级后同一命中进了别的案件: %s vs %s", got, caseID)
	}
	var identities int
	if err := db.QueryRow(ctx, `SELECT COUNT(DISTINCT alert_read_metadata_v1#>>'{findings,0,_jjd_evidence_identity}') FROM security_events WHERE tenant_id=$1`, tenantID).Scan(&identities); err != nil || identities != 1 {
		t.Fatalf("升级前后同一命中的证据身份应相同: %d %v", identities, err)
	}

	insertEvent("e_different", time.Now(), different)
	if got := onlyCase(3, "open"); got != caseID {
		t.Fatalf("不同证据仍归同一案件: %s vs %s", got, caseID)
	}
}
