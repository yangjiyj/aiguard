package handler

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// F-UNKSESS batch 6 acceptance: the real hookd a0296bf6 uploader (git archive, subprocess) posts
// its queued batch (7 valid + 1 session_id "unknown") to the real CP Events handler + PostgreSQL.
// After 2 outer rounds the bad event is acked (rejected, not resent), unacked=0, the 7 are stored.
func TestAgentEndpointEventsHookdUploaderE2E(t *testing.T) {
	if os.Getenv("GP38_HOOKD_SRC") == "" || os.Getenv("GP38_GO") == "" {
		t.Skip("GP38_HOOKD_SRC / GP38_GO not set (git archive of hookd a0296bf6 + go binary)")
	}
	db, tenant, eps := unksessSetup(t)
	var pol struct {
		Version  int64  `json:"version"`
		Checksum string `json:"checksum"`
	}
	if err := json.Unmarshal(runHookdProbe(t, "TestGP38HookdPolicyDump", "E2E_MODE=policy"), &pol); err != nil || pol.Version < 1 {
		t.Fatalf("hookd builtin policy: %+v %v", pol, err)
	}
	var posts int64
	srv := hookdE2EServer(t, db, tenant, eps[0], hookdE2ERepo{repository.NewAgentEndpointRepository(db), pol.Version, pol.Checksum}, &posts)
	fixture, _ := os.Getwd()
	fixture += "/../../../../packages/shared-go/endpointevents/testdata/hookd-a0296bf6/batch-a-cc-t13-deny.json"
	var report struct {
		BadEventID string `json:"bad_event_id"`
		SessionID  string `json:"session_id"`
		Rounds     []struct {
			Round                      int
			RunErr                     string `json:"run_err"`
			Unacked, Rejected, Dropped int64
		}
	}
	raw := runHookdProbe(t, "TestGP38HookdE2EUnknownAcked", "E2E_MODE=rounds", "E2E_URL="+srv.URL, "E2E_ENDPOINT="+eps[0], "E2E_FIXTURE="+fixture)
	if err := json.Unmarshal(raw, &report); err != nil || len(report.Rounds) != 2 {
		t.Fatalf("report: %v %s", err, raw)
	}
	t.Logf("hookd report: %s posts=%d", raw, posts)
	for _, r := range report.Rounds {
		if r.Unacked != 0 || r.Rejected != 1 {
			t.Fatalf("round %d: unacked=%d rejected=%d (want 0/1) run_err=%q", r.Round, r.Unacked, r.Rejected, r.RunErr)
		}
	}
	if posts != 1 {
		t.Fatalf("events POSTs=%d, want 1 (round 2 must have nothing left to resend)", posts)
	}
	var stored, bad int
	if err := db.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND session_id=$2),
		(SELECT count(*) FROM agent_events WHERE tenant_id=$1 AND id=lower($3))`, tenant, report.SessionID, report.BadEventID).Scan(&stored, &bad); err != nil || stored != 7 || bad != 0 {
		t.Fatalf("stored=%d bad=%d (%v)", stored, bad, err)
	}
}
