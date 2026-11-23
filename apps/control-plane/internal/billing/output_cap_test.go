package billing

import "testing"

// 流式截断上限：预算扣掉输入费用后，按输出单价折算能产出的最多 token。
func TestOutputTokenCapForBudget(t *testing.T) {
	price := DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000}
	usage := Usage{PromptTokens: 100_000, OutputTokens: 1_000}
	got, ok, err := OutputTokenCapForBudget(usage, price, 1_000_000)
	if err != nil || !ok || got != 450_000 {
		t.Fatalf("cap=%d ok=%v err=%v want 450000", got, ok, err)
	}
	// 预算连输入都不够：上限为 0，而不是负数。
	got, ok, err = OutputTokenCapForBudget(usage, price, 50_000)
	if err != nil || !ok || got != 0 {
		t.Fatalf("cap=%d ok=%v err=%v want 0", got, ok, err)
	}
	// 推理单价更高时按更贵的单价折算，宁可早截断。
	reasoning := Micros(4_000_000)
	price.Extensions.ReasoningPerMillionMicros = &reasoning
	got, ok, err = OutputTokenCapForBudget(usage, price, 1_000_000)
	if err != nil || !ok || got != 225_000 {
		t.Fatalf("cap=%d ok=%v err=%v want 225000", got, ok, err)
	}
	// 输出免费：没有可计算的上限。
	if _, ok, err = OutputTokenCapForBudget(usage, DirectPrice{InputPerMillionMicros: 1}, 1_000_000); err != nil || ok {
		t.Fatalf("free output must not produce a cap: ok=%v err=%v", ok, err)
	}
}
