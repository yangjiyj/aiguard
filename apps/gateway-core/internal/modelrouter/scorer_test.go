package modelrouter

import (
	"testing"
)

func TestScoreTokenTier(t *testing.T) {
	cfg := ScorerConfig{
		LowThreshold:     0.3,
		HighThreshold:    0.7,
		TokenWeight:      1.0,
		KeywordWeight:    0.0,
		MaxTokensForNorm: 10000,
	}

	// 500 tokens / 10000 = 0.05 → low
	s := ComputeScore(500, "", cfg)
	if s.Tier != "low" {
		t.Errorf("500 tokens: expected tier=low, got %s (value=%f)", s.Tier, s.Value)
	}

	// 9000 tokens / 10000 = 0.9 → high
	s = ComputeScore(9000, "", cfg)
	if s.Tier != "high" {
		t.Errorf("9000 tokens: expected tier=high, got %s (value=%f)", s.Tier, s.Value)
	}
}

func TestScoreKeywordBoost(t *testing.T) {
	cfg := ScorerConfig{
		LowThreshold:  0.3,
		HighThreshold: 0.7,
		TokenWeight:   0.0,
		KeywordWeight: 1.0,
		HighKeywords:  []string{"analyze", "reason"},
		LowKeywords:   []string{"simple", "quick"},
	}

	// high keyword present → keywordScore=1.0 → value=1.0 → high
	s := ComputeScore(0, "please analyze this document", cfg)
	if s.Tier != "high" {
		t.Errorf("high keyword: expected tier=high, got %s (value=%f)", s.Tier, s.Value)
	}

	// low keyword present, no high → keywordScore=0.0 → value=0.0 → low
	s = ComputeScore(0, "quick summary please", cfg)
	if s.Tier != "low" {
		t.Errorf("low keyword: expected tier=low, got %s (value=%f)", s.Tier, s.Value)
	}
}

func TestScoreFactorsRecorded(t *testing.T) {
	cfg := ScorerConfig{
		LowThreshold:  0.3,
		HighThreshold: 0.7,
		TokenWeight:   0.5,
		KeywordWeight: 0.5,
		HighKeywords:  []string{"analyze"},
		MaxTokensForNorm: 1000,
	}

	s := ComputeScore(200, "please analyze this", cfg)

	// factors should contain tokens key
	if _, ok := s.Factors["tokens"]; !ok {
		t.Error("factors missing 'tokens' key")
	}
	tokensVal, ok := s.Factors["tokens"].(int)
	if !ok || tokensVal != 200 {
		t.Errorf("factors[tokens] = %v, want 200", s.Factors["tokens"])
	}

	// matched_high should contain "analyze"
	matchedHigh, ok := s.Factors["matched_high"].([]string)
	if !ok {
		t.Errorf("factors[matched_high] type = %T, want []string", s.Factors["matched_high"])
	} else if len(matchedHigh) == 0 || matchedHigh[0] != "analyze" {
		t.Errorf("factors[matched_high] = %v, want [analyze]", matchedHigh)
	}
}
