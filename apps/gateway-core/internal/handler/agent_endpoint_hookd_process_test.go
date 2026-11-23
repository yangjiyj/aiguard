package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHookdProcessWireUploadAndLostACK(t *testing.T) {
	binary := os.Getenv("HOOKD_CONTRACT_BINARY")
	if binary == "" {
		t.Skip("explicit hookd binary required")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "0b6dfb31b36305b615f1d4ce6ac9e1c0c54c0f7fb32a349815618f1e787a0852" {
		t.Fatal("unreviewed hookd binary")
	}
	root := t.TempDir()
	var mu sync.Mutex
	var batches [][]byte
	var gzipSeen bool
	var queuePresentOnLostACK bool
	const token = "fixture-endpoint-token"
	const endpoint = "ep_wirefixture"
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agent/license-status":
			writeJSON(w, map[string]any{"licensed": true})
		case "/admin/v1/internal/agent/endpoints/register":
			if r.Header.Get("Authorization") != "Bearer fixture-enrollment-token" {
				t.Error("enrollment credential changed")
			}
			writeJSON(w, map[string]any{"endpoint_id": endpoint, "endpoint_token": token, "mode": "monitor", "capture_level": "metadata", "config": map[string]any{"version": 1, "report_batch_max": 200}, "policy": map[string]any{"version": 0}})
		case "/admin/v1/internal/agent/endpoints/resolve":
			var v map[string]string
			_ = json.NewDecoder(r.Body).Decode(&v)
			if v["token_hash"] != endpointTokenHash(token) {
				t.Error("token hash mismatch")
			}
			writeJSON(w, map[string]any{"endpoint_id": endpoint, "tenant_id": "tenant-wire-fixture", "licensed": true, "mode": "monitor", "capture_level": "metadata"})
		case "/admin/v1/internal/agent/events":
			if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Content-Encoding") != "" {
				t.Error("proxy credential or content encoding mismatch")
			}
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			batches = append(batches, body)
			attempt := len(batches)
			mu.Unlock()
			if attempt == 1 {
				files, _ := filepath.Glob(filepath.Join(root, "queue", "*.jsonl"))
				mu.Lock()
				queuePresentOnLostACK = len(files) > 0
				mu.Unlock()
				conn, _, e := w.(http.Hijacker).Hijack()
				if e != nil {
					t.Error(e)
					return
				}
				_ = conn.Close()
				return
			}
			var batch struct {
				Events []struct {
					ID string `json:"event_id"`
				} `json:"events"`
			}
			if e := json.Unmarshal(body, &batch); e != nil {
				t.Error(e)
			}
			ids := []string{}
			for _, e := range batch.Events {
				ids = append(ids, e.ID)
			}
			writeJSON(w, map[string]any{"accepted": []string{}, "duplicates": ids, "rejected": []string{}, "policy": map[string]any{"version": 0}})
		case "/admin/v1/internal/agent/endpoints/heartbeat":
			writeJSON(w, map[string]any{"mode": "monitor", "capture_level": "metadata", "policy": map[string]any{"version": 0}})
		default:
			t.Errorf("unexpected control path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	gateway := &AgentEndpointGateway{controlURL: upstream.URL, client: upstream.Client(), enabled: true, bodyLimit: 8 << 20, auth: make(map[string]endpointAuthCacheEntry), rateLimiter: newEndpointRateLimiter()}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/v1/events" {
			mu.Lock()
			gzipSeen = gzipSeen || r.Header.Get("Content-Encoding") == "gzip"
			mu.Unlock()
		}
		gateway.ServeHTTP(w, r)
	}))
	defer server.Close()
	env := []string{}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "JJDGUARD_") && !strings.HasPrefix(v, "CLAUDE_PLUGIN_") && !strings.HasPrefix(v, "CLAUDE_CODE_VERSION=") {
			env = append(env, v)
		}
	}
	env = append(env, "JJDGUARD_STATE_DIR="+root, "CLAUDE_CODE_VERSION=wire-fixture")
	run := func(input []byte, args ...string) []byte {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = env
		cmd.Dir = root
		cmd.Stdin = bytes.NewReader(input)
		data, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("hookd %v failed: %v %s", args, e, data)
		}
		return data
	}
	if got := strings.TrimSpace(string(run([]byte("fixture-enrollment-token\n"), "enroll", "--server", server.URL, "--token-stdin"))); got != endpoint {
		t.Fatalf("enrollment: %s", got)
	}
	// Suppress automatic background uploaders while collecting this isolated batch.
	if err := os.WriteFile(filepath.Join(root, "uploader.lock"), []byte("controlled-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"session_id": "wire-session-" + strings.Repeat("s", 80), "prompt_id": "wire-prompt", "cwd": root, "tool_name": "Read", "tool_use_id": "wire-tool", "tool_input": map[string]any{"file_path": filepath.Join(root, "fixture.txt")}, "tool_response": map[string]any{"text": "benign fixture"}, "last_assistant_message": "benign completion", "agent_id": "wire-agent", "agent_type": "fixture", "error": "controlled tool failure", "denied_by": "user"}
	events := []string{"UserPromptSubmit", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "PermissionDenied", "SubagentStart", "SubagentStop", "InstructionsLoaded", "PreCompact", "Stop", "SessionEnd"}
	for _, name := range events {
		input["hook_event_name"] = name
		data, _ := json.Marshal(input)
		_ = run(data, "claude-code")
	}
	files, _ := filepath.Glob(filepath.Join(root, "queue", "*.jsonl"))
	queued := []json.RawMessage{}
	for _, f := range files {
		data, e := os.ReadFile(f)
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			if len(line) > 0 {
				queued = append(queued, append([]byte(nil), line...))
			}
		}
	}
	if len(queued) != len(events) {
		t.Fatalf("queue events %d expected %d", len(queued), len(events))
	}
	if err := os.Remove(filepath.Join(root, "uploader.lock")); err != nil {
		t.Fatal(err)
	}
	_ = run(nil, "uploader", "--once")
	var doctor map[string]any
	if err := json.Unmarshal(run(nil, "doctor", "--json"), &doctor); err != nil {
		t.Fatal(err)
	}
	queue := doctor["queue"].(map[string]any)
	if queue["unacked_events"] != float64(0) || queue["rejected_events"] != float64(0) {
		t.Fatalf("queue did not fully acknowledge: %v", queue)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(batches) != 2 || !bytes.Equal(batches[0], batches[1]) || !queuePresentOnLostACK || !gzipSeen {
		t.Fatalf("lost ACK witness: batches=%d queue-retained=%v gzip=%v", len(batches), queuePresentOnLostACK, gzipSeen)
	}
	var batch struct {
		Events   []json.RawMessage `json:"events"`
		Endpoint string            `json:"endpoint_id"`
		Schema   string            `json:"schema_version"`
	}
	if err := json.Unmarshal(batches[1], &batch); err != nil {
		t.Fatal(err)
	}
	if batch.Endpoint != endpoint || batch.Schema != "events.v1" || len(batch.Events) != len(events) {
		t.Fatal("wire envelope mismatch")
	}
	source := map[string]any{}
	types := map[string]bool{}
	for _, e := range queued {
		var v map[string]any
		_ = json.Unmarshal(e, &v)
		source[v["event_id"].(string)] = v
	}
	for _, e := range batch.Events {
		var v map[string]any
		_ = json.Unmarshal(e, &v)
		if !reflect.DeepEqual(source[v["event_id"].(string)], v) {
			t.Fatal("wire event changed")
		}
		types[v["event_type"].(string)] = true
	}
	if len(types) != len(events) {
		t.Fatalf("event kind coverage %d", len(types))
	}
	if out := os.Getenv("HOOKD_CONTRACT_EVIDENCE_DIR"); out != "" {
		if err := os.MkdirAll(out, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "hookd-wire-batch.json"), batches[1], 0600); err != nil {
			t.Fatal(err)
		}
		witness := map[string]any{"scope": "real hookd process and gateway handler with controlled upstream; not real CP or database", "binary_sha256": hex.EncodeToString(sum[:]), "queued_events": len(queued), "event_types": types, "attempts": len(batches), "same_body_on_replay": true, "queue_retained_before_ack": true, "queue_unacked_after": queue["unacked_events"], "gzip": gzipSeen}
		data, _ := json.MarshalIndent(witness, "", "  ")
		if err := os.WriteFile(filepath.Join(out, "hookd-wire-witness.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
