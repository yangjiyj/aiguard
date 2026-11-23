package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// N6: principal_id/grant_id are trimmed at the handler and must then be canonical UUIDs; a
// non-canonical value is a 400 invalid_request, never a PostgreSQL 22P02 surfacing as 503.
func TestG1SoD4HandlerExceptionPrincipalIDStrict(t *testing.T) {
	f := newT15SoDHandlerFixture(t)
	body := func(pid, gid, seed string) string {
		return fmt.Sprintf(`{"principal_id":%q,"grant_id":%q,"action":"file_write","resource_type":"file","resource_id":"/tmp/t15.txt","arguments_sha256":%q,"reason":"n6","ttl_seconds":60,"idempotency_key":%q}`,
			pid, gid, strings.Repeat(seed, 64), "t15:exception:"+strings.Repeat(seed, 64))
	}
	post := func(b string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		f.api.CreateException(rr, t15SoDAdminRequest("reviewer-b", "tenant_admin", "/admin/v1/agent/approval-exceptions", "", b))
		return rr
	}
	id := f.principal.ID
	for i, pid := range []string{"x" + id + "y", " " + id + "x", "{" + id + "}", strings.ToUpper(id), "urn:uuid:" + id, strings.ReplaceAll(id, "-", "")} {
		rr := post(body(pid, f.grantID, fmt.Sprintf("%x", i)))
		if rr.Code != http.StatusBadRequest || t15SoDErrorCode(t, rr) != "invalid_request" {
			t.Fatalf("principal_id %q: %d %s", pid, rr.Code, rr.Body.String())
		}
	}
	if rr := post(body(id, "{"+f.grantID+"}", "8")); rr.Code != http.StatusBadRequest {
		t.Fatalf("braced grant_id: %d %s", rr.Code, rr.Body.String())
	}
	// Surrounding whitespace is trimmed before validation, so a padded canonical id is accepted.
	if rr := post(body(" "+id+"\t", " "+f.grantID+" ", "9")); rr.Code != http.StatusCreated {
		t.Fatalf("trimmed canonical ids: %d %s", rr.Code, rr.Body.String())
	}
}
