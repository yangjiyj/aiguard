package handler

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// slowConcurrencyProber 每次探测睡 delay，并记录同时在跑的探测数峰值。
type slowConcurrencyProber struct {
	delay   time.Duration
	active  atomic.Int32
	peak    atomic.Int32
	calls   atomic.Int32
	failFor map[string]bool
}

func (p *slowConcurrencyProber) Probe(ctx context.Context, r catalog.ModelProbeRequest) catalog.ModelProbeResult {
	n := p.active.Add(1)
	defer p.active.Add(-1)
	for {
		old := p.peak.Load()
		if n <= old || p.peak.CompareAndSwap(old, n) {
			break
		}
	}
	p.calls.Add(1)
	select {
	case <-time.After(p.delay):
	case <-ctx.Done():
		return catalog.ModelProbeResult{ErrorKind: catalog.ModelProbeErrorCancelled}
	}
	if p.failFor[r.DeploymentName] {
		return catalog.ModelProbeResult{ErrorKind: catalog.ModelProbeErrorUpstream, HTTPStatus: 500}
	}
	return catalog.ModelProbeResult{OK: true, PayloadValidated: true, HTTPStatus: 200}
}

// recordingSnapshotStore 只记录 ApplyCatalogSnapshot 收到的输入，不碰数据库。
type recordingSnapshotStore struct {
	mu    sync.Mutex
	input repository.CatalogSnapshotInput
}

func (s *recordingSnapshotStore) BeginCatalogSync(context.Context, string, string) (string, error) {
	return "lease", nil
}
func (s *recordingSnapshotStore) FailCatalogSync(context.Context, string, string, string, string) error {
	return nil
}
func (s *recordingSnapshotStore) ApplyCatalogSnapshot(_ context.Context, in repository.CatalogSnapshotInput) (repository.CatalogSnapshotResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.input = in
	return repository.CatalogSnapshotResult{TotalSeen: len(in.Models)}, nil
}
func (s *recordingSnapshotStore) CatalogSyncState(context.Context, string, string) (repository.CatalogSyncState, error) {
	return repository.CatalogSyncState{}, nil
}
func (s *recordingSnapshotStore) SetCatalogSyncInterval(context.Context, string, string, int) error {
	return nil
}

// 勾选的模型要并发探测（上限 catalogProbeConcurrency），而不是一个做完再做下一个；
// 探测结果必须按目录原顺序、逐个对应地交给快照提交，失败原因不能串到别的模型上。
func TestRunCatalogSnapshotProbesSelectedModelsConcurrently(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "fixture-catalog-encryption-key-not-production")
	encrypted, _, err := secrets.EncryptProviderSecret("fixture-upstream-secret")
	if err != nil {
		t.Fatal(err)
	}
	const total = 8
	models := make([]types.ProviderCatalogModel, 0, total+1)
	selected := make([]string, 0, total)
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("model-%02d", i)
		models = append(models, types.ProviderCatalogModel{ID: id})
		selected = append(selected, id)
	}
	models = append(models, types.ProviderCatalogModel{ID: "not-selected"})
	provider := &repository.Provider{ID: "p1", TenantID: "t1", ProviderType: "openai", BaseURL: "https://upstream.example.test", AuthMode: "api_key", Status: "active"}
	prober := &slowConcurrencyProber{delay: 150 * time.Millisecond, failFor: map[string]bool{"model-03": true}}
	store := &recordingSnapshotStore{}
	deps := &Dependencies{
		ProviderRepo: &MockProviderRepository{
			Providers:   map[string]*repository.Provider{"p1": provider},
			Credentials: map[string]*repository.ProviderCredential{"p1": {ID: "c1", ProviderID: "p1", SecretCiphertext: encrypted, Status: "active"}},
		},
		CatalogFactory: &MockCatalogFactory{Client: &MockCatalogClient{Models: models}},
		ModelProber:    prober,
	}

	started := time.Now()
	if _, err := runCatalogSnapshot(context.Background(), deps, store, "t1", provider, selected, "manual"); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)

	// 每个文本模型探 chat + responses 两次，串行要 8×2×150ms=2.4s。
	if got := prober.calls.Load(); got != total*2 {
		t.Fatalf("探测次数=%d, want %d", got, total*2)
	}
	if peak := prober.peak.Load(); peak < 2 || peak > catalogProbeConcurrency {
		t.Errorf("同时探测峰值=%d, want 2..%d", peak, catalogProbeConcurrency)
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("8 个模型耗时 %v，仍像串行", elapsed)
	}
	got := store.input.Models
	if len(got) != total+1 {
		t.Fatalf("快照模型数=%d, want %d", len(got), total+1)
	}
	for i, item := range got {
		if item.ID != models[i].ID {
			t.Fatalf("快照顺序被打乱: 第 %d 个是 %s, want %s", i, item.ID, models[i].ID)
		}
		switch {
		case item.ID == "not-selected":
			if item.Approved || item.Probe != nil || item.ProbeFailure != "" {
				t.Errorf("未勾选的模型不应探测: %+v", item)
			}
		case item.ID == "model-03":
			if item.Probe != nil || item.ProbeFailure != catalog.ModelProbeErrorUpstream {
				t.Errorf("model-03 应记 upstream_error 失败: probe=%v failure=%q", item.Probe, item.ProbeFailure)
			}
		default:
			if item.Probe == nil || item.ProbeFailure != "" || item.HealthObservedAt.IsZero() {
				t.Errorf("%s 应有探测记录: probe=%v failure=%q", item.ID, item.Probe, item.ProbeFailure)
			}
		}
	}
}
