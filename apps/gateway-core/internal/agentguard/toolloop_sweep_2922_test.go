package agentguard

import (
	"fmt"
	"testing"
	"time"
)

func toolFailureKeys2922(w *ToolFailureWindow) (events, reported int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.events), len(w.reported)
}

// 复审：events、reported 按键清扫——过了去重记忆期（24 小时）的键整个删掉，不随不同的 actor/工具无限增长；
// 还在期限内的键保留。
func TestToolFailureWindow2922SweepsStaleKeys(t *testing.T) {
	w := NewToolFailureWindow(10*time.Minute, 1)
	start := time.Unix(1_700_000_000, 0)
	for i := 0; i < toolFailureSweepEvery; i++ {
		if _, reached := w.RecordFailureWithin(ToolFailureEvent{ActorKey: fmt.Sprintf("actor-%d", i), ToolName: "Bash", Target: "t", Now: start}, 0, 1); !reached {
			t.Fatalf("fixture: threshold 1 reports the first failure of actor %d", i)
		}
	}
	if events, reported := toolFailureKeys2922(w); events != toolFailureSweepEvery || reported != toolFailureSweepEvery {
		t.Fatalf("fixture: %d keys tracked, got events=%d reported=%d", toolFailureSweepEvery, events, reported)
	}
	later := start.Add(toolFailureDedupeRetention + time.Hour)
	for i := 0; i < toolFailureSweepEvery; i++ {
		w.RecordFailureWithin(ToolFailureEvent{ActorKey: "fresh", ToolName: "Bash", Target: fmt.Sprintf("f-%d", i), Now: later.Add(time.Duration(i) * time.Millisecond)}, 0, 1000)
	}
	if events, reported := toolFailureKeys2922(w); events != 1 || reported != 0 {
		t.Fatalf("stale keys past the dedupe retention are swept, got events=%d reported=%d", events, reported)
	}
}
