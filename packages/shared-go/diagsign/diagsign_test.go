package diagsign

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

var key = []byte("0123456789abcdef0123456789abcdef")

func mk(now time.Time) Task {
	p := map[string]any{"service": "gateway-core", "grep": "req_abc", "since_minutes": 10}
	ts := now.UTC().Format(time.RFC3339)
	return Task{ID: "t_1", Action: "container_logs", Params: p, IssuedAt: ts,
		Sig: Sign(key, "t_1", "container_logs", ts, p)}
}

func TestCanonicalSortedCompact(t *testing.T) {
	got := string(Canonical("t_1", "a", "T", map[string]any{"b": 1, "a": "x<&>"}))
	want := `t_1|a|T|{"a":"x<&>","b":1}`
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if string(Canonical("i", "ping", "T", nil)) != `i|ping|T|{}` {
		t.Fatal("nil params should be {}")
	}
}

func TestVerifyOKAndJSONRoundTrip(t *testing.T) {
	now := time.Now()
	task := mk(now)
	raw, _ := json.Marshal(task)
	var back Task
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAt(key, back, now); err != nil {
		t.Fatalf("round trip verify: %v", err)
	}
}

func TestVerifyWrongKeyAndTamper(t *testing.T) {
	now := time.Now()
	task := mk(now)
	if err := VerifyAt([]byte("other-key-other-key-other-key-00"), task, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	task.Params["grep"] = "a;rm -rf /"
	if err := VerifyAt(key, task, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tamper: %v", err)
	}
	task = mk(now)
	task.Action = "disk"
	if err := VerifyAt(key, task, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("action tamper: %v", err)
	}
	task = mk(now)
	task.Sig = "zz"
	if err := VerifyAt(key, task, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("non hex: %v", err)
	}
	if err := VerifyAt(nil, mk(now), now); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("empty key: %v", err)
	}
}

func TestVerifyExpiry(t *testing.T) {
	now := time.Now()
	task := mk(now.Add(-121 * time.Second))
	if err := VerifyAt(key, task, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("old: %v", err)
	}
	task = mk(now.Add(-119 * time.Second))
	if err := VerifyAt(key, task, now); err != nil {
		t.Fatalf("fresh: %v", err)
	}
	task = mk(now.Add(5 * time.Minute))
	if err := VerifyAt(key, task, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("future: %v", err)
	}
}
