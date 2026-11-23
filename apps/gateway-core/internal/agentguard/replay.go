package agentguard

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const maxReplayCaseFileSize = 10 << 20

type ReplayCase struct {
	Name             string             `json:"name"`
	ToolName         string             `json:"tool_name"`
	ToolType         string             `json:"tool_type"`
	Arguments        map[string]any     `json:"arguments"`
	Fragments        []ContextFragment  `json:"fragments"`
	Mode             Mode               `json:"mode"`
	AllowedDomains   []string           `json:"allowed_domains"`
	CommandAllowlist []CommandAllowRule `json:"command_allowlist"`
	WantRaw          DecisionAction     `json:"want_raw"`
	WantEffective    DecisionAction     `json:"want_effective"`
}

type ReplaySuiteReport struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Benign      ReplayMetrics      `json:"benign"`
	Redteam     ReplayMetrics      `json:"redteam"`
	Cases       []ReplayCaseResult `json:"cases"`
}

type ReplayMetrics struct {
	Total           int     `json:"total"`
	BlockedCount    int     `json:"blocked_count"`
	FalseBlockCount int     `json:"false_block_count"`
	FalseBlockRate  float64 `json:"false_block_rate"`
	DetectedCount   int     `json:"detected_count"`
	MissedCount     int     `json:"missed_count"`
	DetectionRate   float64 `json:"detection_rate"`
}

type ReplayCaseResult struct {
	Suite             string         `json:"suite"`
	Name              string         `json:"name"`
	ToolName          string         `json:"tool_name"`
	ToolType          string         `json:"tool_type"`
	RawDecision       DecisionAction `json:"raw_decision"`
	EffectiveDecision DecisionAction `json:"effective_decision"`
	WantRaw           DecisionAction `json:"want_raw,omitempty"`
	WantEffective     DecisionAction `json:"want_effective,omitempty"`
	Detected          bool           `json:"detected"`
	Passed            bool           `json:"passed"`
	Reason            string         `json:"reason,omitempty"`
}

func ReplayCaseFiles(benignPath, redteamPath string) (*ReplaySuiteReport, error) {
	benign, err := LoadReplayCases(benignPath)
	if err != nil {
		return nil, fmt.Errorf("load benign cases: %w", err)
	}
	redteam, err := LoadReplayCases(redteamPath)
	if err != nil {
		return nil, fmt.Errorf("load redteam cases: %w", err)
	}
	report := &ReplaySuiteReport{GeneratedAt: time.Now().UTC()}
	report.Benign, report.Cases = ReplayCases("benign", benign)
	redteamMetrics, redteamCases := ReplayCases("redteam", redteam)
	report.Redteam = redteamMetrics
	report.Cases = append(report.Cases, redteamCases...)
	return report, nil
}

func LoadReplayCases(path string) ([]ReplayCase, error) {
	cleanPath, err := validateReplayCasePath(path)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(cleanPath) // #nosec G304 -- replay only reads validated local JSON fixtures chosen by the operator.
	if err != nil {
		return nil, err
	}
	var cases []ReplayCase
	if err := json.Unmarshal(body, &cases); err != nil {
		return nil, err
	}
	return cases, nil
}

func validateReplayCasePath(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	if cleanPath == "." || filepath.Ext(cleanPath) != ".json" {
		return "", fmt.Errorf("replay case file must be a .json file")
	}
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("replay case file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("replay case file must be a regular file")
	}
	if info.Size() > maxReplayCaseFileSize {
		return "", fmt.Errorf("replay case file exceeds %d bytes", maxReplayCaseFileSize)
	}
	return cleanPath, nil
}

func ReplayCases(suite string, cases []ReplayCase) (ReplayMetrics, []ReplayCaseResult) {
	metrics := ReplayMetrics{Total: len(cases)}
	results := make([]ReplayCaseResult, 0, len(cases))
	for _, item := range cases {
		decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
			ToolName:         item.ToolName,
			ToolType:         item.ToolType,
			Arguments:        item.Arguments,
			ContextFragments: item.Fragments,
			Mode:             item.Mode,
			AllowedDomains:   item.AllowedDomains,
			CommandAllowlist: item.CommandAllowlist,
		})
		if decision.EffectiveDecision == DecisionBlock {
			metrics.BlockedCount++
		}
		detected := decision.RawDecision != DecisionAllow || decision.EffectiveDecision != DecisionAllow
		if suite == "benign" && decision.EffectiveDecision == DecisionBlock {
			metrics.FalseBlockCount++
		}
		if suite == "redteam" {
			if detected {
				metrics.DetectedCount++
			} else {
				metrics.MissedCount++
			}
		}
		results = append(results, ReplayCaseResult{
			Suite:             suite,
			Name:              item.Name,
			ToolName:          item.ToolName,
			ToolType:          item.ToolType,
			RawDecision:       decision.RawDecision,
			EffectiveDecision: decision.EffectiveDecision,
			WantRaw:           item.WantRaw,
			WantEffective:     item.WantEffective,
			Detected:          detected,
			Passed:            replayCasePassed(suite, item, decision, detected),
			Reason:            decision.EffectiveReason,
		})
	}
	metrics.FalseBlockRate = replayRatio(metrics.FalseBlockCount, metrics.Total)
	metrics.DetectionRate = replayRatio(metrics.DetectedCount, metrics.Total)
	return metrics, results
}

func replayCasePassed(suite string, item ReplayCase, decision Decision, detected bool) bool {
	if item.WantRaw != "" && item.WantRaw != decision.RawDecision {
		return false
	}
	if item.WantEffective != "" && item.WantEffective != decision.EffectiveDecision {
		return false
	}
	if suite == "benign" && decision.EffectiveDecision == DecisionBlock {
		return false
	}
	if suite == "redteam" && !detected {
		return false
	}
	return true
}

func replayRatio(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}
