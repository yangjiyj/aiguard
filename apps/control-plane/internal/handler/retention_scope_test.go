package handler

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestRetentionScopeAndWindowNormalizesUTCAndKeepsEndExclusive(t *testing.T) {
	req := httptest.NewRequest("GET", "/audit/access-retention?from=2026-08-01T08:00:00%2B08:00&to=2026-08-31T08:00:00%2B08:00", nil)
	scope, start, end, err := retentionScopeAndWindow(req)
	if err != nil {
		t.Fatalf("retentionScopeAndWindow: %v", err)
	}
	if scope != customerRetentionScope {
		t.Fatalf("scope=%q, want %q", scope, customerRetentionScope)
	}
	if !start.Equal(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)) || !end.Equal(time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("window=%s..%s, want UTC half-open boundary", start, end)
	}
}

func TestRetentionScopeAndWindowRejectsIncompleteOrClosedWindow(t *testing.T) {
	for _, path := range []string{
		"/audit/access-retention?from=2026-08-01T00:00:00Z",
		"/audit/access-retention?from=2026-08-02T00:00:00Z&to=2026-08-01T00:00:00Z",
	} {
		if _, _, _, err := retentionScopeAndWindow(httptest.NewRequest("GET", path, nil)); err == nil {
			t.Fatalf("window %q unexpectedly accepted", path)
		}
	}
}

type scopedUploadedFileTestRepo struct {
	scopedCalled bool
	start        time.Time
	end          time.Time
	scope        string
}

func (r *scopedUploadedFileTestRepo) GetAccessContentLog(context.Context, string, string) (*repository.AccessContentLog, error) {
	return nil, nil
}

func (r *scopedUploadedFileTestRepo) GetAccessContentLogs(context.Context, string, []string) ([]repository.AccessContentLog, error) {
	return nil, nil
}

func (r *scopedUploadedFileTestRepo) ResolveUploadedFileBytes(context.Context, string, []string) (map[string]repository.ResolvedUploadedFile, error) {
	return nil, nil
}

func (r *scopedUploadedFileTestRepo) ResolveUploadedFileBytesScoped(_ context.Context, _ string, _ []string, start, end time.Time, scope string) (map[string]repository.ResolvedUploadedFile, error) {
	r.scopedCalled = true
	r.start = start
	r.end = end
	r.scope = scope
	return map[string]repository.ResolvedUploadedFile{"ref-1": {ReferenceID: "ref-1"}}, nil
}

func TestResolveUploadedFileBytesUsesTenantScopeAndWindow(t *testing.T) {
	repo := &scopedUploadedFileTestRepo{}
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	got, err := resolveUploadedFileBytes(context.Background(), repo, "tenant-a", []string{"ref-1"}, customerRetentionScope, start, end)
	if err != nil {
		t.Fatalf("resolveUploadedFileBytes: %v", err)
	}
	if !repo.scopedCalled || !repo.start.Equal(start) || !repo.end.Equal(end) || repo.scope != customerRetentionScope {
		t.Fatalf("scoped resolver received wrong isolation: called=%v start=%s end=%s scope=%q", repo.scopedCalled, repo.start, repo.end, repo.scope)
	}
	if _, ok := got["ref-1"]; !ok {
		t.Fatalf("scoped resolver result missing reference: %#v", got)
	}
}
