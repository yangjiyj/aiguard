package agentguard

import (
	"testing"
	"time"
)

func burstStampCount2922(w *BehaviorWindow, key string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.events[key])
}

// 复审第 2 项：每个键只留最近 threshold 条时间戳（取当次阈值）；这类调用没配阈值时留有限条数。
func TestBehaviorWindow2922KeepsOnlyThresholdStamps(t *testing.T) {
	w := NewBehaviorWindow(time.Hour, BehaviorThresholds{})
	start := time.Unix(1_700_000_000, 0)
	thresholds := BehaviorThresholds{FileReadBurst: 3, Window: time.Hour}
	for i := 0; i < 10; i++ {
		got := w.RecordWithThresholds(BehaviorEvent{ActorKey: "a", Kind: BehaviorFileRead, Now: start.Add(time.Duration(i) * time.Second)}, thresholds)
		if (i >= 2) != (got.Reason == behaviorBurstReason) {
			t.Fatalf("call %d: burst=%v, want the 3rd and later calls to burst: %+v", i, got.Reason == behaviorBurstReason, got)
		}
	}
	if n := burstStampCount2922(w, "a:"+string(BehaviorFileRead)); n != 3 {
		t.Fatalf("a key keeps only the latest threshold stamps, got %d", n)
	}
	for i := 0; i < 500; i++ {
		w.RecordWithThresholds(BehaviorEvent{ActorKey: "a", Kind: BehaviorNetworkEgress, Now: start.Add(time.Duration(i) * time.Second)}, thresholds)
	}
	if n := burstStampCount2922(w, "a:"+string(BehaviorNetworkEgress)); n != burstStampsWithoutThreshold {
		t.Fatalf("a kind without a threshold keeps a bounded tail (%d), got %d", burstStampsWithoutThreshold, n)
	}
}

// 复审第 2 项：清扫按各键当前配置的窗口，配置调短后旧的长窗口不再拖住计数（原 maxWindow 只增不减）。
func TestBehaviorWindow2922SweepFollowsTheCurrentWindow(t *testing.T) {
	w := NewBehaviorWindow(10*time.Second, BehaviorThresholds{})
	start := time.Unix(1_700_000_000, 0)
	long := BehaviorThresholds{FileReadBurst: 100, Window: time.Hour}
	w.RecordWithThresholds(BehaviorEvent{ActorKey: "a", Kind: BehaviorFileRead, Now: start}, long)
	w.RecordWithThresholds(BehaviorEvent{ActorKey: "b", Kind: BehaviorFileRead, Now: start}, long)
	w.RecordWithThresholds(BehaviorEvent{ActorKey: "a", Kind: BehaviorFileRead, Now: start.Add(time.Second)},
		BehaviorThresholds{FileReadBurst: 100, Window: 10 * time.Second})
	w.mu.Lock()
	w.sweepLocked(start.Add(time.Minute))
	_, keptA := w.events["a:"+string(BehaviorFileRead)]
	_, keptB := w.events["b:"+string(BehaviorFileRead)]
	w.mu.Unlock()
	if keptA {
		t.Fatal("a key whose window was shortened to 10s is swept a minute later")
	}
	if !keptB {
		t.Fatal("a key still on a one-hour window is kept")
	}
}

// 复审次要项：行为窗口为空时取阈值不能空指针。
func TestBehaviorWindow2922NilWindowThresholds(t *testing.T) {
	var w *BehaviorWindow
	if got := w.Thresholds(); got != (BehaviorThresholds{}) {
		t.Fatalf("a nil window has no thresholds: %+v", got)
	}
	got := analyzeBehavior(ToolCallAnalysisInput{ToolName: "Read", ToolType: ToolTypeFile, ActorKey: "a",
		Arguments: map[string]any{"file_path": "/repo/a.go"}}, map[string]any{"file_path": "/repo/a.go"}, Decision{})
	if got.RawDecision != DecisionAllow {
		t.Fatalf("no behavior window, no burst: %+v", got)
	}
}

// 复审次要项：连续失败“达到或超过阈值且本窗口未触发过”就报告；阈值调低到已有次数以下时也报告一次。
func TestToolFailureWindow2922ReportsOncePerWindowAtOrAboveThreshold(t *testing.T) {
	w := NewToolFailureWindow(10*time.Minute, 5)
	start := time.Unix(1_700_000_000, 0)
	record := func(i int, at time.Duration, threshold int) (int, bool) {
		return w.RecordFailureWithin(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: string(rune('a' + i)), Now: start.Add(at)}, time.Hour, threshold)
	}
	for i := 0; i < 4; i++ {
		if _, reached := record(i, time.Duration(i)*time.Second, 5); reached {
			t.Fatalf("failure %d is below the threshold", i+1)
		}
	}
	if count, reached := record(4, 4*time.Second, 3); count != 5 || !reached {
		t.Fatalf("lowering the threshold below the count reports once: count=%d reached=%v", count, reached)
	}
	if _, reached := record(5, 5*time.Second, 3); reached {
		t.Fatal("already reported in this window")
	}
	if _, reached := record(6, 2*time.Hour, 1); !reached {
		t.Fatal("a new window reports again")
	}
}
