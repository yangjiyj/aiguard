package handler

import "testing"

func TestReportSeverityLabelsUseTheUnifiedNames(t *testing.T) {
	for in, want := range map[string]string{"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"} {
		if got := riskLevelLabel(in); got != want {
			t.Fatalf("riskLevelLabel(%q)=%q want %q", in, got, want)
		}
	}
	if skillAdmissionSeverityLabels["medium"] != "中危" || skillAdmissionSeverityLabels["high"] != "高危" {
		t.Fatalf("skill admission labels: %+v", skillAdmissionSeverityLabels)
	}
}
