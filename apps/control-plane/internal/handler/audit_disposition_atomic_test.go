package handler

import (
	"context"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeLinkedDispositionRepo struct {
	fakeAuditDispositionRepo
	linkedCalls int
	err         error
}

func (f *fakeLinkedDispositionRepo) UpsertLinked(ctx context.Context, d *repository.AuditDisposition) (*repository.AuditDisposition, error) {
	f.linkedCalls++
	if f.err != nil {
		return nil, f.err
	}
	return f.Upsert(ctx, d)
}

func (f *fakeLinkedDispositionRepo) UpsertAuthorized(
	ctx context.Context,
	d *repository.AuditDisposition,
	_ []string,
	_, _ string,
) (*repository.AuditDisposition, error) {
	f.linkedCalls++
	if f.err != nil {
		return nil, f.err
	}
	return f.Upsert(ctx, d)
}
func TestAuditDispositionUsesAtomicLinkAndDoesNotRepeatGroupMutation(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
	}{{"save", nil, http.StatusOK}, {"missing event", repository.ErrNotFound, http.StatusNotFound}, {"rollback", errors.New("group write failed"), http.StatusInternalServerError}} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeLinkedDispositionRepo{err: tc.err}
			groups := &fakeAlertGroupRepo{}
			deps := &Dependencies{AuditDispositionRepo: repo, AlertGroupRepo: groups}
			req := alertGroupTestRequest(http.MethodPut, "/admin/v1/audit/dispositions", "tenant-a", "operator", strings.NewReader(`{"subject_type":"security_event","subject_id":"event","status":"false_positive"}`))
			rr := httptest.NewRecorder()
			UpsertAuditDisposition(deps)(rr, req)
			if rr.Code != tc.code || repo.linkedCalls != 1 || groups.fpEventID != "" {
				t.Fatalf("atomic path not respected: status=%d calls=%d group=%s", rr.Code, repo.linkedCalls, groups.fpEventID)
			}
		})
	}
}
