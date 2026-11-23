package handler

import (
	"strings"
	"testing"
)

func TestToolURLGitHubServiceRiskRemainsPassive(t *testing.T) {
	target := "https://" + strings.Join([]string{"api", "github", "com"}, ".") + "/repos/enterprise/code"
	findings := analyzeURLRisk(target, "fetch")
	for _, finding := range findings {
		if finding.Category == "sensitive_service" && finding.Severity == "high" {
			return
		}
	}
	t.Fatalf("GitHub tool URL lost sensitive-service classification: %+v", findings)
}
