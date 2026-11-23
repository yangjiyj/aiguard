package repository

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func evidenceDigest(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }
func TestRecoveryRejectsPlaceholderEvidence(t *testing.T) {
	item := AlertOccurrence{EvidenceContext: "<deterministic-catalog-match>", MatchedTextPreview: "<deterministic-catalog-match>", RawEvidenceStatus: "available", EvidenceStatus: "available"}
	normalizeOccurrenceEvidence(&item, true)
	if item.EvidenceContext != "" || item.RawEvidenceStatus != "missing" || item.EvidenceStatus != "missing" {
		t.Fatalf("placeholder presented as evidence: %+v", item)
	}
}

// 整页命中一次批量回捞：每条命中仍按自己的请求、项目、位置和两个哈希独立核验，
// 一条核验不过不影响同页其他命中，也不会把别的请求的正文安到它头上。
func TestRecoverOccurrenceEvidenceRequiresBothHashesAndRequestScope(t *testing.T) {
	db := verifiedModelsTestDB(t)
	ctx := context.Background()
	_, err := db.Exec(ctx, `ALTER TABLE request_logs ADD COLUMN project_id text;
 CREATE TABLE content_logs(id text,request_id text,tenant_id text,role text,content text,message_index int,created_at timestamptz DEFAULT now(),environment_scope text);
 INSERT INTO tenants(id,name) VALUES('t1','T1'),('t2','T2');
 INSERT INTO request_logs(id,request_id,tenant_id,project_id) VALUES('log1','req1','t1','p1'),('log2','req2','t2','p1'),('log3','req3','t1','p1');`)
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("a", 700) + "buy guns" + strings.Repeat("z", 700)
	other := strings.Repeat("b", 30) + "sell cars" + strings.Repeat("y", 30)
	_, err = db.Exec(ctx, `INSERT INTO content_logs(id,request_id,tenant_id,role,content,message_index,environment_scope) VALUES
 ('c1','log1','t1','tool',$1,5,'legacy'),('c2','log2','t2','tool',$1,5,'legacy'),('c3','req3','t1','user',$2,0,'legacy')`, content, other)
	if err != nil {
		t.Fatal(err)
	}
	// Original detector index is deliberately different from the retention index;
	// cryptographic evidence anchors, not a guessed positional join, identify it.
	makeItem := func() AlertOccurrence {
		return AlertOccurrence{RequestID: "req1", ProjectID: "p1", MessageRole: "tool", ContentSource: "tool_result", MatchedLocation: "content[700:708]", RawEvidenceSHA256: evidenceDigest("buy guns"), EvidenceContextSHA256: evidenceDigest("…" + content[200:1208] + "…"), RawEvidenceStatus: "missing"}
	}
	cases := []struct {
		name   string
		mutate func(*AlertOccurrence)
		want   string
	}{
		{"valid", func(*AlertOccurrence) {}, "buy guns"},
		{"wrong tenant", func(i *AlertOccurrence) { i.RequestID = "req2" }, ""},
		{"wrong project", func(i *AlertOccurrence) { i.ProjectID = "p2" }, ""},
		{"wrong context", func(i *AlertOccurrence) { i.EvidenceContextSHA256 = strings.Repeat("0", 64) }, ""},
		{"wrong evidence", func(i *AlertOccurrence) { i.RawEvidenceSHA256 = strings.Repeat("0", 64) }, ""},
		{"wrong role", func(i *AlertOccurrence) { i.MessageRole = "assistant" }, ""},
		// 正文按外部请求编号存放的历史数据也能回捞；没有上下文哈希时只核验命中本身。
		{"external request id", func(i *AlertOccurrence) {
			*i = AlertOccurrence{RequestID: "req3", ProjectID: "p1", ContentSource: "user", MatchedLocation: "content[30:39]", RawEvidenceSHA256: evidenceDigest("sell cars"), RawEvidenceStatus: "missing"}
		}, "sell cars"},
		{"already has raw", func(i *AlertOccurrence) { i.RawEvidence = "stored original" }, "stored original"},
	}
	items := make([]AlertOccurrence, len(cases))
	for index, tc := range cases {
		items[index] = makeItem()
		tc.mutate(&items[index])
	}
	repo := NewAlertOccurrenceRepository(db)
	if err := repo.recoverOccurrenceEvidenceBatch(ctx, AlertOccurrenceFilter{TenantID: "t1", CanReadEvidence: true, IncludeRaw: true}, items); err != nil {
		t.Fatal(err)
	}
	for index, tc := range cases {
		got := items[index]
		if got.RawEvidence != tc.want {
			t.Fatalf("%s: raw=%q want %q", tc.name, got.RawEvidence, tc.want)
		}
		recovered := tc.want != "" && tc.name != "already has raw"
		if got.EvidenceRecovered != recovered {
			t.Fatalf("%s: recovered=%v want %v", tc.name, got.EvidenceRecovered, recovered)
		}
		if recovered && got.RawEvidenceStatus != "available" {
			t.Fatalf("%s: status=%q", tc.name, got.RawEvidenceStatus)
		}
	}
	if items[0].EvidenceContext != "…"+content[200:1208]+"…" {
		t.Fatalf("context not recovered with the evidence: %q", items[0].EvidenceContext)
	}
	for _, f := range []AlertOccurrenceFilter{
		{TenantID: "t1", CanReadEvidence: false, IncludeRaw: true},
		{TenantID: "t1", CanReadEvidence: true, IncludeRaw: false},
	} {
		page := []AlertOccurrence{makeItem()}
		if err := repo.recoverOccurrenceEvidenceBatch(ctx, f, page); err != nil {
			t.Fatal(err)
		}
		if page[0].RawEvidence != "" || page[0].EvidenceRecovered {
			t.Fatalf("unauthorized/unrequested raw content leaked: %+v", page[0])
		}
	}
}
