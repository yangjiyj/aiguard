package repository

import "testing"

// TestMatchedSummaryTriageSuppressible 覆盖 CountTriageSuppressedSince 的行级判定纯逻辑（SFIX-1(c)）：
// （绝不因个别 FP 藏掉真信号）。与 control-plane alert.allTriageSuppressible / handler
// allSemanticTriageSuppressible 语义一致，跨桶适用（不限 semantic_attack）。
func TestMatchedSummaryTriageSuppressible(t *testing.T) {
	fp := func() map[string]any {
		f := map[string]any{"triage": map[string]any{"verdict": "likely_false_positive"}}
		return f
	}
	confirmed := map[string]any{"triage": map[string]any{"verdict": "confirmed_risk"}}
	noTriage := map[string]any{"rule_id": "secret"}

	cases := []struct {
		name    string
		summary map[string]any
		want    bool
	}{
		{
			name:    "single_likely_fp_suppressed",
			summary: map[string]any{"findings": []any{fp()}},
			want:    true,
		},
		{
			name:    "all_likely_fp_suppressed",
			summary: map[string]any{"findings": []any{fp(), fp()}},
			want:    true,
		},
		{
			name:    "_passes_through",
			summary: map[string]any{"findings": []any{fp()}},
			want:    true,
		},
		{
			name:    "mixed_fp_and_confirmed_passes_through",
			summary: map[string]any{"findings": []any{fp(), confirmed}},
			want:    false,
		},
		{
			name:    "no_triage_not_suppressed",
			summary: map[string]any{"findings": []any{noTriage}},
			want:    false,
		},
		{
			name:    "empty_findings_not_suppressed",
			summary: map[string]any{"findings": []any{}},
			want:    false,
		},
		{
			name:    "missing_findings_key_not_suppressed",
			summary: map[string]any{},
			want:    false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matchedSummaryTriageSuppressible(c.summary); got != c.want {
				t.Fatalf("matchedSummaryTriageSuppressible(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}
