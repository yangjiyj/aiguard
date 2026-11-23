package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// hookdE2ERepo serves hookd's own builtin policy ref (dumped by the a0296bf6 probe) so the
// uploader's policy.Sync is satisfied from its pre-applied local bundle and never calls /policy.
type hookdE2ERepo struct {
	*repository.AgentEndpointRepository
	version  int64
	checksum string
}

func (r hookdE2ERepo) Policy(context.Context, string) (map[string]any, error) {
	return map[string]any{"version": r.version, "checksum": r.checksum}, nil
}

// hookdE2EServer wraps the real Events handler; endpoint auth is replaced by a fixed endpoint
// context (the token middleware is not under test). Counts POSTs to /agent/v1/events.
func hookdE2EServer(t *testing.T, db *pgxpool.Pool, tenant, endpoint string, repo hookdE2ERepo, posts *int64) *httptest.Server {
	api := &AgentEndpointAPI{Repo: repo}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/v1/events" || r.Method != http.MethodPost {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
			return
		}
		atomic.AddInt64(posts, 1)
		api.Events(w, r.WithContext(contextWithEndpoint(r.Context(), &repository.AgentEndpointContext{
			TenantID: tenant, EndpointID: endpoint, PolicyVersion: repo.version, Mode: "monitor", CaptureLevel: "full"})))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runHookdProbe runs one probe test inside the git-archived a0296bf6 hookd module.
func runHookdProbe(t *testing.T, name string, env ...string) []byte {
	t.Helper()
	out := t.TempDir() + "/out.json"
	cmd := exec.Command(os.Getenv("GP38_GO"), "test", "-count=1", "-v", "-run", "^"+name+"$", "./internal/uploader/")
	cmd.Dir, cmd.Env = os.Getenv("GP38_HOOKD_SRC"), append(os.Environ(), append(env, "E2E_OUT="+out)...)
	if mod := os.Getenv("GP38_HOOKD_GOMODCACHE"); mod != "" { // hookd's own module cache (x/sys)
		cmd.Env = append(cmd.Env, "GOMODCACHE="+mod)
	}
	if log, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(log), "--- PASS: "+name) {
		t.Fatalf("hookd probe %s: %v\n%s", name, err, log)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
