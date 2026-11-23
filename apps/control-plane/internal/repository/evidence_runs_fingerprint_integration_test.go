package repository

import (
	"context"
	"testing"
	"time"
)

func TestEvidenceRunsNativeSessionBeatsSyntheticFingerprint(t *testing.T) {
	db := evidenceRunsContractDB(t)
	tenant := newEvidenceRunsContractTenant(t, db)
	base := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	fixtures := []evidenceRunFixture{
		{id: "same-a", agentType: "openai-codex", sessionID: "native-a", conversationID: "ck_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", requestText: "same task"},
		{id: "same-b", agentType: "openai-codex", sessionID: "native-a", conversationID: "ck_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", requestText: "same task", riskState: "blocked"},
		{id: "independent", agentType: "openai-codex", sessionID: "native-b", conversationID: "ck_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", requestText: "same task"},
		{id: "legacy", agentType: "openai-codex", conversationID: "ck_cccccccccccccccccccccccccccccccc", requestText: "same task"},
	}
	for i, f := range fixtures {
		insertEvidenceRunFixture(t, db, tenant, f, base.Add(time.Duration(i)*time.Minute))
	}
	repo := NewRequestLogRepository(db)
	for _, build := range []evidenceRunsQueryBuilder{buildEvidenceRunsQueryWithTotal, buildIndexedEvidenceRunsQueryWithTotal} {
		rows, total := runEvidenceRunsWithBuilder(t, context.Background(), repo, tenant, ForwardProxyAccessFilter{EnvironmentScope: "customer", StartTime: base.Add(-time.Minute), EndTime: base.Add(time.Hour), Limit: 20}, build)
		if len(rows) != 3 || total != 3 {
			t.Fatalf("groups=%d total=%d want 3", len(rows), total)
		}
		exact, inferred, merged := 0, 0, 0
		for _, r := range rows {
			if r.CorrelationConfidence == "exact" {
				exact++
			}
			if r.CorrelationConfidence == "inferred" && r.CorrelationSource == "content_fingerprint" {
				inferred++
			}
			if r.RequestCount == 2 {
				merged++
				if r.RiskState != "blocked" {
					t.Fatal("merged group lost blocked evidence")
				}
			}
		}
		if exact != 2 || inferred != 1 || merged != 1 {
			t.Fatalf("exact=%d inferred=%d merged=%d", exact, inferred, merged)
		}
	}
}
