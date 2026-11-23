package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/corpusscan"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

// corpusFakeEngine 模拟引擎：手机号替换成 [手机号]，按字符下标返回命中。
type corpusFakeEngine struct {
	mu       sync.Mutex
	calls    int
	block    chan struct{}
	fail     error
	extract  string
	rejected bool
}

var corpusFakePhone = regexp.MustCompile(`1[3-9]\d{9}`)

func (e *corpusFakeEngine) Scan(ctx context.Context, items []corpusscan.EngineItem) (corpusscan.EngineBatch, error) {
	e.mu.Lock()
	e.calls++
	block, fail := e.block, e.fail
	e.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return corpusscan.EngineBatch{}, ctx.Err()
		}
	}
	if fail != nil {
		return corpusscan.EngineBatch{}, fail
	}
	batch := corpusscan.EngineBatch{RulePackVersion: "rp-test"}
	for _, item := range items {
		result := corpusscan.EngineResult{ID: item.ID, Findings: []corpusscan.EngineFinding{}}
		var replacements []corpusscan.Replacement
		for _, loc := range corpusFakePhone.FindAllStringIndex(item.Text, -1) {
			start := utf8.RuneCountInString(item.Text[:loc[0]])
			end := start + utf8.RuneCountInString(item.Text[loc[0]:loc[1]])
			result.Findings = append(result.Findings, corpusscan.EngineFinding{Type: "phone_cn", Label: "手机号", Start: start, End: end, Severity: "medium"})
			replacements = append(replacements, corpusscan.Replacement{Start: start, End: end, Text: "[手机号]"})
		}
		result.MaskedText = corpusscan.ApplyReplacements(item.Text, replacements)
		batch.Items = append(batch.Items, result)
	}
	return batch, nil
}

func (e *corpusFakeEngine) Extract(_ context.Context, _, _, _, _ string, _ []byte) (corpusExtractResult, error) {
	if e.rejected {
		return corpusExtractResult{}, errCorpusExtractRejected
	}
	return corpusExtractResult{Text: e.extract, Complete: true}, nil
}

// corpusMemoryStore 是 CorpusScanStore 的内存实现，用于不依赖数据库的流程测试。
type corpusMemoryStore struct {
	mu    sync.Mutex
	jobs  map[string]*CorpusScanJob
	order []string
	hash  map[string][]byte
	data  map[string][]byte
}

func newCorpusMemoryStore() *corpusMemoryStore {
	return &corpusMemoryStore{jobs: map[string]*CorpusScanJob{}, hash: map[string][]byte{}, data: map[string][]byte{}}
}

func (m *corpusMemoryStore) get(tenant, id string) (*CorpusScanJob, error) {
	job := m.jobs[id]
	if job == nil || job.TenantID != tenant {
		return nil, ErrCorpusScanNotFound
	}
	return job, nil
}

func (m *corpusMemoryStore) Create(_ context.Context, in CorpusScanCreate) (CorpusScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	job := &CorpusScanJob{ID: "corpus_" + strings.Repeat("0", 8) + "-0000-0000-0000-" + strings.Repeat("0", 11) + string(rune('a'+len(m.order))),
		TenantID: in.TenantID, CreatedBy: in.CreatedBy, FileName: in.FileName, Format: in.Format, SizeBytes: in.SizeBytes, SHA256: in.SHA256,
		Status: "uploading", Stats: []corpusscan.TypeStat{}, Samples: []corpusscan.Sample{}, Unscanned: []corpusscan.UnscannedLine{}, Notes: []string{},
		SourceKeys: []string{}, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(corpusScanUploadingTimeout)}
	m.jobs[job.ID] = job
	m.order = append(m.order, job.ID)
	return *job, nil
}

func (m *corpusMemoryStore) Get(_ context.Context, tenant, id string) (CorpusScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, err := m.get(tenant, id)
	if err != nil {
		return CorpusScanJob{}, err
	}
	return *job, nil
}

func (m *corpusMemoryStore) List(_ context.Context, tenant string, _ int) ([]CorpusScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []CorpusScanJob{}
	for _, id := range m.order {
		if job := m.jobs[id]; job != nil && job.TenantID == tenant {
			out = append(out, *job)
		}
	}
	return out, nil
}

func (m *corpusMemoryStore) AppendChunk(_ context.Context, tenant, id string, chunk CorpusScanChunk) (CorpusScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, err := m.get(tenant, id)
	if err != nil {
		return CorpusScanJob{}, err
	}
	if job.Status != "uploading" || job.CancelRequested {
		return CorpusScanJob{}, ErrCorpusScanState
	}
	if chunk.Index != job.NextChunk {
		return CorpusScanJob{}, ErrCorpusScanChunkOrder
	}
	if job.UploadedBytes+chunk.Size > job.SizeBytes {
		return CorpusScanJob{}, ErrCorpusScanTooLarge
	}
	m.data[id] = append(m.data[id], chunk.Data...)
	job.UploadedBytes += chunk.Size
	job.NextChunk++
	job.SourceKeys = append(job.SourceKeys, chunk.Key)
	return *job, nil
}

func (m *corpusMemoryStore) Queue(_ context.Context, tenant, id string) (CorpusScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, err := m.get(tenant, id)
	if err != nil {
		return CorpusScanJob{}, err
	}
	if job.Status != "uploading" || job.CancelRequested {
		return CorpusScanJob{}, ErrCorpusScanState
	}
	if job.UploadedBytes != job.SizeBytes {
		return CorpusScanJob{}, ErrCorpusScanIncomplete
	}
	sum := sha256.Sum256(m.data[id])
	if hex.EncodeToString(sum[:]) != job.SHA256 {
		return CorpusScanJob{}, ErrCorpusScanDigest
	}
	job.Status = "queued"
	return *job, nil
}

func (m *corpusMemoryStore) ClaimNext(_ context.Context, owner string) (CorpusScanJob, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.order {
		if job := m.jobs[id]; job != nil && job.Status == "running" {
			return CorpusScanJob{}, false, nil
		}
	}
	for _, id := range m.order {
		if job := m.jobs[id]; job != nil && job.Status == "queued" && !job.CancelRequested {
			job.Status, job.ownerToken = "running", owner
			return *job, true, nil
		}
	}
	return CorpusScanJob{}, false, nil
}

func (m *corpusMemoryStore) Heartbeat(_ context.Context, j CorpusScanJob, p corpusscan.Progress) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	job := m.jobs[j.ID]
	if job == nil || job.Status != "running" || job.ownerToken != j.ownerToken {
		return ErrCorpusScanLeaseLost
	}
	if job.CancelRequested {
		return ErrCorpusScanCanceled
	}
	job.ProcessedBytes, job.TotalRecords = p.ProcessedBytes, p.TotalRecords
	return nil
}

func (m *corpusMemoryStore) Finish(_ context.Context, j CorpusScanJob, o CorpusScanOutcome) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	job := m.jobs[j.ID]
	if job == nil || job.Status != "running" || job.ownerToken != j.ownerToken {
		return ErrCorpusScanLeaseLost
	}
	job.Status, job.ErrorCode, job.ReportKey, job.MaskedKey, job.MaskedFormat = o.Status, o.ErrorCode, o.ReportKey, o.MaskedKey, o.MaskedFormat
	if job.CancelRequested {
		job.Status, job.ErrorCode, job.ReportKey, job.MaskedKey, job.MaskedFormat = "canceled", "canceled", "", "", ""
	}
	p := o.Report.Progress
	job.ProcessedBytes, job.TotalRecords, job.ScannedRecords, job.HitRecords, job.UnscannedRecords, job.IncompleteRecords =
		p.ProcessedBytes, p.TotalRecords, p.ScannedRecords, p.HitRecords, p.UnscannedRecords, p.IncompleteRecords
	job.Stats, job.Samples, job.Unscanned, job.Notes = nonNil(o.Report.Stats), nonNil(o.Report.Samples), nonNil(o.Report.Unscanned), nonNil(o.Notes)
	job.RulePackVersion = o.Report.RulePackVersion
	job.HasReport, job.HasMasked = job.ReportKey != "", job.MaskedKey != ""
	job.ExpiresAt = time.Now().Add(corpusScanRetention)
	return nil
}

func (m *corpusMemoryStore) Cancel(_ context.Context, tenant, id string) (CorpusScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, err := m.get(tenant, id)
	if err != nil {
		return CorpusScanJob{}, err
	}
	switch job.Status {
	case "uploading", "queued":
		job.Status, job.ErrorCode, job.CancelRequested = "canceled", "canceled", true
	case "running":
		job.CancelRequested = true
	}
	return *job, nil
}

func (m *corpusMemoryStore) Delete(_ context.Context, tenant, id string) (CorpusScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, err := m.get(tenant, id)
	if err != nil {
		return CorpusScanJob{}, err
	}
	if job.Status == "running" {
		return CorpusScanJob{}, ErrCorpusScanState
	}
	delete(m.jobs, id)
	return *job, nil
}

func (m *corpusMemoryStore) Reap(context.Context) error { return nil }

func (m *corpusMemoryStore) Expired(context.Context, int) ([]CorpusScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []CorpusScanJob{}
	for _, id := range m.order {
		if job := m.jobs[id]; job != nil && job.ExpiresAt.Before(time.Now()) && job.Status != "running" && job.Status != "queued" {
			out = append(out, *job)
		}
	}
	return out, nil
}

func (m *corpusMemoryStore) Purge(_ context.Context, j CorpusScanJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.jobs, j.ID)
	return nil
}

func (m *corpusMemoryStore) PendingSourceCleanup(context.Context, int) ([]CorpusScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []CorpusScanJob{}
	for _, id := range m.order {
		if job := m.jobs[id]; job != nil && len(job.SourceKeys) > 0 && job.Status != "uploading" && job.Status != "queued" && job.Status != "running" {
			out = append(out, *job)
		}
	}
	return out, nil
}

func (m *corpusMemoryStore) ClearSourceKeys(_ context.Context, j CorpusScanJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if job := m.jobs[j.ID]; job != nil {
		job.SourceKeys = []string{}
	}
	return nil
}

func (m *corpusMemoryStore) expire(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[id].ExpiresAt = time.Now().Add(-time.Second)
}

type corpusAuditRepo struct {
	auditDetailSystemRepo
	mu      sync.Mutex
	actions []string
}

func (r *corpusAuditRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.actions = append(r.actions, op.ActionType)
	return nil
}

func (r *corpusAuditRepo) has(action string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.actions {
		if a == action {
			return true
		}
	}
	return false
}

type corpusTestEnv struct {
	t       *testing.T
	handler *CorpusScanHandler
	store   *corpusMemoryStore
	engine  *corpusFakeEngine
	audit   *corpusAuditRepo
	root    string
	router  chi.Router
}

func newCorpusTestEnv(t *testing.T) *corpusTestEnv {
	t.Helper()
	root := t.TempDir()
	local, err := retentionstore.NewLocalStore(root)
	if err != nil {
		t.Fatal(err)
	}
	audit := &corpusAuditRepo{}
	deps := &Dependencies{RetentionStore: local, SystemRepo: audit}
	store := newCorpusMemoryStore()
	h := NewCorpusScanHandler(deps, store, nil)
	engine := &corpusFakeEngine{}
	h.engine = engine
	r := chi.NewRouter()
	r.Post("/admin/v1/security/corpus-scans", h.Create)
	r.Get("/admin/v1/security/corpus-scans", h.List)
	r.Get("/admin/v1/security/corpus-scans/{id}", h.Get)
	r.Delete("/admin/v1/security/corpus-scans/{id}", h.Delete)
	r.Put("/admin/v1/security/corpus-scans/{id}/chunks/{n}", h.UploadChunk)
	r.Post("/admin/v1/security/corpus-scans/{id}/start", h.Start)
	r.Post("/admin/v1/security/corpus-scans/{id}/cancel", h.Cancel)
	r.Get("/admin/v1/security/corpus-scans/{id}/report", h.DownloadReport)
	r.Get("/admin/v1/security/corpus-scans/{id}/masked", h.DownloadMasked)
	return &corpusTestEnv{t: t, handler: h, store: store, engine: engine, audit: audit, root: root, router: r}
}

func (e *corpusTestEnv) do(role, tenant, method, path string, body []byte) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if role != "" {
		user := &repository.User{ID: "user-" + role, TenantID: tenant, Role: role, Status: "active"}
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func (e *corpusTestEnv) create(role, tenant, name string, content []byte) string {
	e.t.Helper()
	sum := sha256.Sum256(content)
	body, _ := json.Marshal(map[string]any{"file_name": name, "size_bytes": len(content), "sha256": hex.EncodeToString(sum[:])})
	rec := e.do(role, tenant, http.MethodPost, "/admin/v1/security/corpus-scans", body)
	if rec.Code != http.StatusCreated {
		e.t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		JobID string `json:"job_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.JobID
}

func (e *corpusTestEnv) upload(role, tenant, id string, parts ...[]byte) {
	e.t.Helper()
	for index, part := range parts {
		rec := e.do(role, tenant, http.MethodPut, "/admin/v1/security/corpus-scans/"+id+"/chunks/"+strconv.Itoa(index), part)
		if rec.Code != http.StatusOK {
			e.t.Fatalf("chunk %d = %d %s", index, rec.Code, rec.Body)
		}
	}
}

func (e *corpusTestEnv) job(tenant, id string) CorpusScanJob {
	e.t.Helper()
	job, err := e.store.Get(context.Background(), tenant, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return job
}

func (e *corpusTestEnv) files() []string {
	var out []string
	_ = filepath.Walk(e.root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && !strings.HasSuffix(p, ".json") && !strings.Contains(p, string(filepath.Separator)+".tmp"+string(filepath.Separator)) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func TestCorpusScanEndToEndJSONL(t *testing.T) {
	env := newCorpusTestEnv(t)
	content := []byte(`{"instruction":"给 13812345678 打电话","output":"已拨 13812345678"}` + "\n" + `坏行` + "\n" + `{"text":"无"}` + "\n")
	id := env.create("security_officer", "tenant-a", "train.jsonl", content)
	env.upload("security_officer", "tenant-a", id, content[:20], content[20:])
	if rec := env.do("security_officer", "tenant-a", http.MethodPost, "/admin/v1/security/corpus-scans/"+id+"/start", nil); rec.Code != http.StatusAccepted {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	if !env.handler.runOnce() {
		t.Fatal("queued job was not claimed")
	}
	job := env.job("tenant-a", id)
	if job.Status != "succeeded" || job.TotalRecords != 3 || job.HitRecords != 1 || job.UnscannedRecords != 1 || job.RulePackVersion != "rp-test" {
		t.Fatalf("job = %+v", job)
	}
	if len(job.SourceKeys) != 0 {
		t.Fatalf("source chunks were not deleted: %+v", job.SourceKeys)
	}
	if len(env.files()) != 2 {
		t.Fatalf("only report and masked copy should remain, got %v", env.files())
	}

	detail := env.do("auditor", "tenant-a", http.MethodGet, "/admin/v1/security/corpus-scans/"+id, nil)
	if detail.Code != http.StatusOK || strings.Contains(detail.Body.String(), "13812345678") || strings.Contains(detail.Body.String(), "source_keys") {
		t.Fatalf("detail = %d %s", detail.Code, detail.Body)
	}
	report := env.do("auditor", "tenant-a", http.MethodGet, "/admin/v1/security/corpus-scans/"+id+"/report", nil)
	if report.Code != http.StatusOK || strings.Contains(report.Body.String(), "13812345678") || !strings.Contains(report.Body.String(), `"hit_records": 1`) {
		t.Fatalf("report = %d %s", report.Code, report.Body)
	}
	if !strings.Contains(report.Header().Get("Content-Disposition"), "train.report.json") {
		t.Fatalf("report disposition = %q", report.Header().Get("Content-Disposition"))
	}
	if denied := env.do("auditor", "tenant-a", http.MethodGet, "/admin/v1/security/corpus-scans/"+id+"/masked", nil); denied.Code != http.StatusForbidden {
		t.Fatalf("auditor masked download = %d", denied.Code)
	}
	masked := env.do("security_officer", "tenant-a", http.MethodGet, "/admin/v1/security/corpus-scans/"+id+"/masked", nil)
	want := `{"instruction":"给 [手机号] 打电话","output":"已拨 [手机号]"}` + "\n" + `坏行` + "\n" + `{"text":"无"}` + "\n"
	if masked.Code != http.StatusOK || masked.Body.String() != want {
		t.Fatalf("masked = %d %q", masked.Code, masked.Body)
	}
	for _, action := range []string{"create_corpus_scan", "start_corpus_scan", "download_corpus_scan_report", "download_corpus_scan_masked"} {
		if !env.audit.has(action) {
			t.Errorf("missing audit %s", action)
		}
	}

	if rec := env.do("security_officer", "tenant-a", http.MethodDelete, "/admin/v1/security/corpus-scans/"+id, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if len(env.files()) != 0 || !env.audit.has("delete_corpus_scan") {
		t.Fatalf("files after delete = %v", env.files())
	}
}

func TestCorpusScanCrossTenantAccessReturns404(t *testing.T) {
	env := newCorpusTestEnv(t)
	content := []byte("13812345678\n")
	id := env.create("platform_admin", "tenant-a", "a.txt", content)
	for _, tc := range []struct {
		method, suffix string
		body           []byte
	}{
		{http.MethodGet, "", nil}, {http.MethodPut, "/chunks/0", content}, {http.MethodPost, "/start", nil},
		{http.MethodPost, "/cancel", nil}, {http.MethodGet, "/report", nil}, {http.MethodGet, "/masked", nil}, {http.MethodDelete, "", nil},
	} {
		rec := env.do("platform_admin", "tenant-b", tc.method, "/admin/v1/security/corpus-scans/"+id+tc.suffix, tc.body)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s from tenant-b = %d %s", tc.method, tc.suffix, rec.Code, rec.Body)
		}
	}
	if list := env.do("platform_admin", "tenant-b", http.MethodGet, "/admin/v1/security/corpus-scans", nil); strings.Contains(list.Body.String(), id) {
		t.Fatalf("tenant-b list leaks job: %s", list.Body)
	}
}

func TestCorpusScanRolesAndValidation(t *testing.T) {
	env := newCorpusTestEnv(t)
	for _, role := range []string{"auditor", "tenant_admin", "chat_user", "developer"} {
		body, _ := json.Marshal(map[string]any{"file_name": "a.txt", "size_bytes": 1, "sha256": strings.Repeat("a", 64)})
		if rec := env.do(role, "tenant-a", http.MethodPost, "/admin/v1/security/corpus-scans", body); rec.Code != http.StatusForbidden {
			t.Errorf("%s create = %d", role, rec.Code)
		}
	}
	if rec := env.do("chat_user", "tenant-a", http.MethodGet, "/admin/v1/security/corpus-scans", nil); rec.Code != http.StatusForbidden {
		t.Errorf("chat_user list = %d", rec.Code)
	}
	if rec := env.do("", "", http.MethodGet, "/admin/v1/security/corpus-scans", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous list = %d", rec.Code)
	}
	for name, body := range map[string]map[string]any{
		"unsupported": {"file_name": "a.exe", "size_bytes": 1, "sha256": strings.Repeat("a", 64)},
		"too large":   {"file_name": "a.pdf", "size_bytes": int64(101 << 20), "sha256": strings.Repeat("a", 64)},
		"bad sha":     {"file_name": "a.txt", "size_bytes": 1, "sha256": "xyz"},
		"zero size":   {"file_name": "a.txt", "size_bytes": 0, "sha256": strings.Repeat("a", 64)},
		"unknown key": {"file_name": "a.txt", "size_bytes": 1, "sha256": strings.Repeat("a", 64), "tenant_id": "x"},
		"jsonl 2GB+1": {"file_name": "a.jsonl", "size_bytes": int64(2<<30) + 1, "sha256": strings.Repeat("a", 64)},
	} {
		raw, _ := json.Marshal(body)
		if rec := env.do("security_officer", "tenant-a", http.MethodPost, "/admin/v1/security/corpus-scans", raw); rec.Code < 400 || rec.Code >= 500 {
			t.Errorf("%s = %d", name, rec.Code)
		}
	}
	// 路径分隔符只保留文件名。
	id := env.create("security_officer", "tenant-a", `..\..\etc/x.txt`, []byte("a"))
	if job := env.job("tenant-a", id); job.FileName != "x.txt" {
		t.Fatalf("file name = %q", job.FileName)
	}
}

func TestCorpusScanChunkRules(t *testing.T) {
	env := newCorpusTestEnv(t)
	content := []byte("0123456789")
	id := env.create("security_officer", "tenant-a", "a.txt", content)
	if rec := env.do("security_officer", "tenant-a", http.MethodPut, "/admin/v1/security/corpus-scans/"+id+"/chunks/1", content[:5]); rec.Code != http.StatusConflict {
		t.Fatalf("out-of-order chunk = %d", rec.Code)
	}
	if rec := env.do("security_officer", "tenant-a", http.MethodPut, "/admin/v1/security/corpus-scans/"+id+"/chunks/0", bytes.Repeat([]byte("x"), corpusScanMaxChunkBytes+1)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized chunk = %d", rec.Code)
	}
	if rec := env.do("security_officer", "tenant-a", http.MethodPut, "/admin/v1/security/corpus-scans/"+id+"/chunks/0", append(content, 'x')); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunk beyond declared size = %d", rec.Code)
	}
	if rec := env.do("security_officer", "tenant-a", http.MethodPost, "/admin/v1/security/corpus-scans/"+id+"/start", nil); rec.Code != http.StatusConflict {
		t.Fatalf("start before upload = %d", rec.Code)
	}
	env.upload("security_officer", "tenant-a", id, []byte("01234"), []byte("XXXXX"))
	rec := env.do("security_officer", "tenant-a", http.MethodPost, "/admin/v1/security/corpus-scans/"+id+"/start", nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "sha256_mismatch") {
		t.Fatalf("digest mismatch start = %d %s", rec.Code, rec.Body)
	}
	if rejected := env.files(); len(rejected) != 2 {
		t.Fatalf("stored chunks = %v", rejected)
	}
}

func TestCorpusScanCancelRunningJobDeletesEverything(t *testing.T) {
	env := newCorpusTestEnv(t)
	env.engine.block = make(chan struct{})
	content := []byte("13812345678\n")
	id := env.create("security_officer", "tenant-a", "a.txt", content)
	env.upload("security_officer", "tenant-a", id, content)
	env.do("security_officer", "tenant-a", http.MethodPost, "/admin/v1/security/corpus-scans/"+id+"/start", nil)
	done := make(chan struct{})
	go func() { env.handler.runOnce(); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for env.job("tenant-a", id).Status != "running" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rec := env.do("security_officer", "tenant-a", http.MethodDelete, "/admin/v1/security/corpus-scans/"+id, nil); rec.Code != http.StatusConflict {
		t.Fatalf("delete running job = %d", rec.Code)
	}
	if rec := env.do("security_officer", "tenant-a", http.MethodPost, "/admin/v1/security/corpus-scans/"+id+"/cancel", nil); rec.Code != http.StatusOK {
		t.Fatalf("cancel = %d %s", rec.Code, rec.Body)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("executor did not stop after cancel")
	}
	job := env.job("tenant-a", id)
	if job.Status != "canceled" || job.HasMasked || job.HasReport || len(job.SourceKeys) != 0 {
		t.Fatalf("job = %+v", job)
	}
	if files := env.files(); len(files) != 0 {
		t.Fatalf("files left after cancel: %v", files)
	}
	if !env.audit.has("cancel_corpus_scan") {
		t.Fatal("cancel not audited")
	}
}

func TestCorpusScanEngineFailureMarksJobFailedAndDeletesSource(t *testing.T) {
	env := newCorpusTestEnv(t)
	env.engine.fail = errCorpusEngineUnavailable
	content := []byte("13812345678\n")
	id := env.create("security_officer", "tenant-a", "a.txt", content)
	env.upload("security_officer", "tenant-a", id, content)
	env.do("security_officer", "tenant-a", http.MethodPost, "/admin/v1/security/corpus-scans/"+id+"/start", nil)
	env.handler.runOnce()
	job := env.job("tenant-a", id)
	if job.Status != "failed" || job.ErrorCode != "engine_unavailable" || len(env.files()) != 0 {
		t.Fatalf("job = %+v files=%v", job, env.files())
	}
	if rec := env.do("security_officer", "tenant-a", http.MethodGet, "/admin/v1/security/corpus-scans/"+id+"/masked", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("download of failed job = %d", rec.Code)
	}
}

func TestCorpusScanDocumentProducesTextCopy(t *testing.T) {
	env := newCorpusTestEnv(t)
	env.engine.extract = "第一段 13812345678\n\n第二段"
	content := []byte("PK\x03\x04fake-docx")
	id := env.create("security_officer", "tenant-a", "合同.docx", content)
	env.upload("security_officer", "tenant-a", id, content)
	env.do("security_officer", "tenant-a", http.MethodPost, "/admin/v1/security/corpus-scans/"+id+"/start", nil)
	env.handler.runOnce()
	job := env.job("tenant-a", id)
	if job.Status != "succeeded" || job.MaskedFormat != "txt" || job.TotalRecords != 2 {
		t.Fatalf("job = %+v", job)
	}
	masked := env.do("security_officer", "tenant-a", http.MethodGet, "/admin/v1/security/corpus-scans/"+id+"/masked", nil)
	if masked.Body.String() != "第一段 [手机号]\n第二段\n" || !strings.Contains(masked.Header().Get("Content-Disposition"), "filename*=UTF-8''%E5%90%88%E5%90%8C.masked.txt") {
		t.Fatalf("masked = %q disposition=%q", masked.Body, masked.Header().Get("Content-Disposition"))
	}

	env.engine.rejected = true
	bad := env.create("security_officer", "tenant-a", "坏.pdf", []byte("%PDF-broken"))
	env.upload("security_officer", "tenant-a", bad, []byte("%PDF-broken"))
	env.do("security_officer", "tenant-a", http.MethodPost, "/admin/v1/security/corpus-scans/"+bad+"/start", nil)
	env.handler.runOnce()
	if job := env.job("tenant-a", bad); job.Status != "failed" || job.ErrorCode != "extract_failed" {
		t.Fatalf("rejected document = %+v", job)
	}
}

func TestCorpusScanCleanupRemovesExpiredJobsAndLeftoverSources(t *testing.T) {
	env := newCorpusTestEnv(t)
	content := []byte("13812345678\n")
	id := env.create("security_officer", "tenant-a", "a.txt", content)
	env.upload("security_officer", "tenant-a", id, content)
	env.do("security_officer", "tenant-a", http.MethodPost, "/admin/v1/security/corpus-scans/"+id+"/start", nil)
	env.handler.runOnce()
	stale := env.create("security_officer", "tenant-a", "b.txt", content)
	env.upload("security_officer", "tenant-a", stale, content)
	if len(env.files()) != 3 {
		t.Fatalf("files before cleanup = %v", env.files())
	}
	env.store.expire(id)
	env.store.expire(stale)
	if removed := env.handler.CleanupOnce(context.Background()); removed != 2 {
		t.Fatalf("removed = %d", removed)
	}
	if files := env.files(); len(files) != 0 {
		t.Fatalf("files after cleanup = %v", files)
	}
	if _, err := env.store.Get(context.Background(), "tenant-a", id); !errors.Is(err, ErrCorpusScanNotFound) {
		t.Fatalf("expired job still present: %v", err)
	}
}

func TestCorpusScanRequiresLocalStorage(t *testing.T) {
	h := NewCorpusScanHandler(&Dependencies{}, newCorpusMemoryStore(), nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/security/corpus-scans", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u", TenantID: "t", Role: "platform_admin"}))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "local_storage_required") {
		t.Fatalf("list without local store = %d %s", rec.Code, rec.Body)
	}
}
