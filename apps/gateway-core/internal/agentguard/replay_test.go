package agentguard

import (
	"path/filepath"
	"testing"
)

func TestReplayCaseFilesReportsBenignAndRedteamMetrics(t *testing.T) {
	report, err := ReplayCaseFiles(
		filepath.Join("testdata", "benign_tool_calls.json"),
		filepath.Join("testdata", "redteam_tool_calls.json"),
	)
	if err != nil {
		t.Fatalf("replay case files: %v", err)
	}
	if report.Benign.Total < 5 || report.Redteam.Total < 5 {
		t.Fatalf("expected existing benign/redteam fixtures to be loaded: %#v", report)
	}
	if report.Benign.FalseBlockCount != 0 || report.Benign.FalseBlockRate != 0 {
		t.Fatalf("benign false block metrics should stay zero: %#v", report.Benign)
	}
	if report.Redteam.DetectedCount != report.Redteam.Total || report.Redteam.DetectionRate != 1 {
		t.Fatalf("redteam detection should be 100%% for high-risk fixtures: %#v", report.Redteam)
	}
	if len(report.Cases) != report.Benign.Total+report.Redteam.Total {
		t.Fatalf("case details length mismatch: got %d report=%#v", len(report.Cases), report)
	}
}
