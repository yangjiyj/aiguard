package repository

import (
	"strings"
	"testing"
)

func TestOccurrenceProjectionFallsBackToTheRealPreviewKey(t *testing.T) {
	if strings.Contains(alertOccurrenceProjection, "matched_text_preview_preview") {
		t.Fatal("回退键写错了：引擎写的是 matched_text_preview")
	}
	fallback := "COALESCE(NULLIF(p.finding->>'redacted_evidence',''),NULLIF(p.finding->>'matched_text_preview',''),'')"
	if got := strings.Count(alertOccurrenceProjection, fallback); got != 2 {
		t.Fatalf("redacted_evidence 和 evidence_status 两处都应回退到 matched_text_preview，实际 %d 处", got)
	}
}
