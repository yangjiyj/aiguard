package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
)

func currentMaxSeq(t *testing.T, repo *AuditChainRepository) int64 {
	t.Helper()
	stats, err := repo.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return stats.MaxSeq
}

// A chain that switches SHA-256 -> SM3 -> SHA-256 must verify end to end
// under the recorded algorithm; the legacy verifier must flag the SM3 rows.
func TestAuditChainMixedSHA256AndSM3Verify(t *testing.T) {
	_, repo := setupAuditChainTestDB(t)
	ctx := context.Background()
	tag := fmt.Sprintf("ws10-%d", time.Now().UnixNano())

	if err := repo.Append(ctx, "tenant_ws10", "ws10_test", tag+"-a", map[string]any{"step": "sha"}); err != nil {
		t.Fatal(err)
	}
	from := currentMaxSeq(t, repo)
	writer := NewSM3ChainWriter(repo)
	for i := 0; i < 3; i++ {
		if err := writer.Append(ctx, "tenant_ws10", "ws10_test", fmt.Sprintf("%s-sm3-%d", tag, i), map[string]any{"step": "sm3", "i": i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.Append(ctx, "tenant_ws10", "ws10_test", tag+"-z", map[string]any{"step": "sha-again"}); err != nil {
		t.Fatal(err)
	}
	to := currentMaxSeq(t, repo)

	res, err := repo.VerifyByRecordedAlgorithm(ctx, from, to)
	if err != nil || !res.OK {
		t.Fatalf("mixed chain must verify: %+v %v", res, err)
	}
	legacy, err := repo.Verify(ctx, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.OK || legacy.Detail != "payload_hash mismatch" || legacy.FirstBreakAtSeq != from+1 {
		t.Fatalf("legacy verifier must stop at the first SM3 row, got %+v", legacy)
	}

	var alg string
	if err := repo.db.QueryRow(ctx, `SELECT hash_alg FROM audit_chain WHERE seq=$1`, from+1).Scan(&alg); err != nil || alg != audit_chain.AlgSM3 {
		t.Fatalf("hash_alg recorded=%q err=%v", alg, err)
	}
	if err := repo.db.QueryRow(ctx, `SELECT hash_alg FROM audit_chain WHERE seq=$1`, from).Scan(&alg); err != nil || alg != audit_chain.AlgSHA256 {
		t.Fatalf("legacy Append must default to sha256-hmac, got %q err=%v", alg, err)
	}
}

func TestAuditChainSM3RejectsWrongKeyAndUnknownAlgorithm(t *testing.T) {
	db, repo := setupAuditChainTestDB(t)
	ctx := context.Background()
	if err := repo.AppendWithAlgorithm(ctx, "md5", "tenant_ws10", "ws10_test", "x", map[string]any{}); err != ErrUnknownChainAlgorithm {
		t.Fatalf("unknown algorithm err=%v", err)
	}
	if err := NewSM3ChainWriter(repo).Append(ctx, "tenant_ws10", "ws10_test", fmt.Sprintf("k-%d", time.Now().UnixNano()), map[string]any{"k": 1}); err != nil {
		t.Fatal(err)
	}
	seq := currentMaxSeq(t, repo)
	other := NewAuditChainRepository(db, []byte("some-other-key"))
	res, err := other.VerifyByRecordedAlgorithm(ctx, seq, seq)
	if err != nil || res.OK || res.Detail != "signature invalid" {
		t.Fatalf("wrong key must fail signature, got %+v %v", res, err)
	}
	// The DB constraint refuses algorithms the verifier does not know.
	_, err = db.Exec(ctx, `INSERT INTO audit_chain (tenant_id,event_type,event_id,payload_json,payload_hash,chain_hash,signature,hash_alg)
		VALUES ('tenant_ws10','ws10_test','bad-alg','{}',repeat('0',64),repeat('0',64),'s','md5')`)
	if err == nil {
		t.Fatal("audit_chain accepted unknown hash_alg")
	}
}
