package aiconvo

import (
	"net/http"
	"strings"
	"testing"
)

func TestCodexThreadKey(t *testing.T) {
	key := func(h http.Header, tenant, caller string) string { return CodexThreadKey(h, tenant, caller) }
	h := http.Header{"Thread-Id": {"thread-a"}, "Session-Id": {"process-1"}}
	first := key(h, "tenant", "caller")
	if first == "" || strings.Contains(first, "thread-a") {
		t.Fatal("must retain a scoped opaque identity")
	}
	h.Set("Session-Id", "process-2")
	if key(h, "tenant", "caller") != first {
		t.Fatal("process restart split a thread")
	}
	h.Set("Thread-Id", "thread-b")
	if key(h, "tenant", "caller") == first {
		t.Fatal("independent threads merged")
	}
	h.Set("Thread-Id", "thread-a")
	if key(h, "other", "caller") == first || key(h, "tenant", "other") == first {
		t.Fatal("caller boundary missing")
	}
	if key(h, "", "caller") != "" {
		t.Fatal("tenant required")
	}
	for _, legacy := range []http.Header{{"Thread_id": {"thread-a"}}, {"Session_id": {"thread-a"}}, {"Session-Id": {"thread-a"}}} {
		if key(legacy, "tenant", "caller") != first {
			t.Fatal("legacy identity split a thread")
		}
	}
	for _, bad := range []http.Header{
		{"Thread-Id": {"a", "b"}}, {"Thread-Id": {"a"}, "Thread_id": {"b"}},
		{"Thread-Id": {strings.Repeat("x", 257)}}, {"Thread-Id": {"a,b"}},
		{"Thread-Id": {"bad\nvalue"}}, {"Thread-Id": {""}, "Session-Id": {"fallback"}},
	} {
		if key(bad, "tenant", "caller") != "" {
			t.Fatal("ambiguous identity accepted")
		}
	}
}
