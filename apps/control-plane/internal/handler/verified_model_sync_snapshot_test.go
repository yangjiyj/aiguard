package handler

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestVerifyModelSyncCandidatesBindsOneFreshSnapshotBatch(t *testing.T) {
	deps, _, _, _ := verifiedDeps()
	req := ModelSyncVerifyRequest{ProviderID: "provider-a", Items: []ModelSyncVerifyItem{
		{CatalogModelID: "gpt-5.5", DeploymentName: "deploy-55"},
		{CatalogModelID: "gpt-5.6", DeploymentName: "deploy-56"},
	}}
	firstRec := verifiedRequest(t, VerifyModelSyncCandidates(deps), req, "")
	if firstRec.Code != http.StatusOK {
		t.Fatalf("first verify status=%d body=%s", firstRec.Code, firstRec.Body.String())
	}
	first := verifiedDecode[ModelSyncVerifyResponse](t, firstRec)
	if len(first.Results) != 2 {
		t.Fatalf("first results=%#v", first.Results)
	}
	claims := make([]modelSyncClaim, len(first.Results))
	for i, result := range first.Results {
		claim, err := openModelSyncClaim(modelSyncTokenTestSecret, result.ProofToken, time.Now())
		if err != nil {
			t.Fatalf("open proof %d: %v", i, err)
		}
		claims[i] = claim
	}
	wantConfig := repository.VerifiedModelSyncProviderConfigDigest("azure", "https://azure.example.test", "api-key")
	activeModels, err := deps.ModelRepo.List(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	wantActive := repository.VerifiedModelSyncActiveSetDigest(activeModels, "provider-a")
	if claims[0].Version != 2 || claims[0].VerificationBatchID == "" || claims[0].ProviderConfigDigest != wantConfig || claims[0].ActiveSetDigest != wantActive {
		t.Fatalf("first claim bindings=%#v", claims[0])
	}
	if claims[1].VerificationBatchID != claims[0].VerificationBatchID || claims[1].ProviderConfigDigest != claims[0].ProviderConfigDigest || claims[1].ActiveSetDigest != claims[0].ActiveSetDigest {
		t.Fatalf("proofs were not bound to one batch: %#v %#v", claims[0], claims[1])
	}

	secondRec := verifiedRequest(t, VerifyModelSyncCandidates(deps), req, "")
	if secondRec.Code != http.StatusOK {
		t.Fatalf("second verify status=%d body=%s", secondRec.Code, secondRec.Body.String())
	}
	second := verifiedDecode[ModelSyncVerifyResponse](t, secondRec)
	secondClaim, err := openModelSyncClaim(modelSyncTokenTestSecret, second.Results[0].ProofToken, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if secondClaim.VerificationBatchID == claims[0].VerificationBatchID {
		t.Fatalf("two verify calls reused batch id %q", secondClaim.VerificationBatchID)
	}
}

func TestVerifyModelSyncCandidatesFailsBeforeProbeWhenActiveSnapshotUnavailable(t *testing.T) {
	deps, _, models, _ := verifiedDeps()
	models.listErr = errors.New("database detail must not leak")
	prober := &verifiedProber{}
	deps.ModelProber = prober
	rec := verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{
		ProviderID: "provider-a",
		Items:      []ModelSyncVerifyItem{{CatalogModelID: "gpt-5.5", DeploymentName: "deploy-55"}},
	}, "")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "verification_unavailable") || strings.Contains(rec.Body.String(), "database detail") || len(prober.snapshot()) != 0 {
		t.Fatalf("status=%d probes=%d body=%s", rec.Code, len(prober.snapshot()), rec.Body.String())
	}
}

func TestCommitVerifiedModelSyncRejectsMixedSnapshotBindingsBeforeRepository(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*modelSyncClaim)
	}{
		{name: "provider config", mutate: func(c *modelSyncClaim) { c.ProviderConfigDigest = strings.Repeat("c", 64) }},
		{name: "credential", mutate: func(c *modelSyncClaim) { c.CredentialID = "credential-b" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _, models, _ := verifiedDeps()
			first := verifiedModelSyncTestClaim("one", "deploy-one", "credential-a", time.Now().Add(time.Minute).Unix())
			second := verifiedModelSyncTestClaim("two", "deploy-two", "credential-a", time.Now().Add(time.Minute).Unix())
			tt.mutate(&second)
			firstToken, err := sealModelSyncClaim(modelSyncTokenTestSecret, first)
			if err != nil {
				t.Fatal(err)
			}
			secondToken, err := sealModelSyncClaim(modelSyncTokenTestSecret, second)
			if err != nil {
				t.Fatal(err)
			}
			rec := verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{firstToken, secondToken}}, "")
			if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "sync_conflict") || models.replaceCalls.Load() != 0 {
				t.Fatalf("status=%d replace=%d body=%s", rec.Code, models.replaceCalls.Load(), rec.Body.String())
			}
		})
	}
}

func TestCommitVerifiedModelSyncRejectsStaleProviderConfigBeforeRepository(t *testing.T) {
	deps, providers, models, _ := verifiedDeps()
	claim := verifiedModelSyncTestClaim("gpt-5.5", "deploy-55", "credential-a", time.Now().Add(time.Minute).Unix())
	token, err := sealModelSyncClaim(modelSyncTokenTestSecret, claim)
	if err != nil {
		t.Fatal(err)
	}
	providers.Providers["provider-a"].BaseURL = "https://changed.example.test"
	providers.Providers["provider-a"].AuthMode = "bearer"
	rec := verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{token}}, "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "sync_conflict") || models.replaceCalls.Load() != 0 {
		t.Fatalf("status=%d replace=%d body=%s", rec.Code, models.replaceCalls.Load(), rec.Body.String())
	}
}

// 分批验证（多次 verify，批次号和当时的启用集合各不相同）的结果可以一起提交：
// 提交是追加/更新语义，不再依赖验证时刻的启用集合快照。
func TestCommitVerifiedModelSyncAcceptsProofsFromSeparateVerifyRounds(t *testing.T) {
	deps, _, models, _ := verifiedDeps()
	first := verifiedModelSyncTestClaim("one", "deploy-one", "credential-a", time.Now().Add(time.Minute).Unix())
	second := verifiedModelSyncTestClaim("two", "deploy-two", "credential-a", time.Now().Add(time.Minute).Unix())
	second.VerificationBatchID = "batch-b"
	second.ActiveSetDigest = strings.Repeat("d", 64)
	firstToken, err := sealModelSyncClaim(modelSyncTokenTestSecret, first)
	if err != nil {
		t.Fatal(err)
	}
	secondToken, err := sealModelSyncClaim(modelSyncTokenTestSecret, second)
	if err != nil {
		t.Fatal(err)
	}
	rec := verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{firstToken, secondToken}}, "")
	if rec.Code != http.StatusOK || models.replaceCalls.Load() != 1 || len(models.ReplaceCalls) != 1 || len(models.ReplaceCalls[0].Desired) != 2 {
		t.Fatalf("status=%d merge=%d body=%s", rec.Code, models.replaceCalls.Load(), rec.Body.String())
	}
}
