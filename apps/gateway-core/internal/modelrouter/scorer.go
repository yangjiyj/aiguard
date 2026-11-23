package modelrouter

import "strings"

// ScorerConfig defines thresholds, weights, and keywords for complexity scoring.
type ScorerConfig struct {
	LowThreshold     float64
	HighThreshold    float64
	TokenWeight      float64
	KeywordWeight    float64
	HighKeywords     []string
	LowKeywords      []string
	MaxTokensForNorm int
}

// Score holds the computed complexity score and tier classification.
type Score struct {
	Value   float64
	Tier    string
	Factors map[string]any
}

// ComputeScore scores a request's complexity based on token count and keyword presence.
// Returns a Score with Value in [0,1], Tier in {"low","mid","high"}, and Factors for logging.
func ComputeScore(promptTokens int, text string, cfg ScorerConfig) Score {
	maxTok := cfg.MaxTokensForNorm
	if maxTok <= 0 {
		maxTok = 10000
	}
	tokenScore := float64(promptTokens) / float64(maxTok)
	if tokenScore > 1 {
		tokenScore = 1
	}

	var matchedHigh, matchedLow []string
	for _, kw := range cfg.HighKeywords {
		if kw != "" && strings.Contains(text, kw) {
			matchedHigh = append(matchedHigh, kw)
		}
	}
	for _, kw := range cfg.LowKeywords {
		if kw != "" && strings.Contains(text, kw) {
			matchedLow = append(matchedLow, kw)
		}
	}
	keywordScore := 0.5
	if len(matchedHigh) > 0 {
		keywordScore = 1.0
	}
	if len(matchedLow) > 0 && len(matchedHigh) == 0 {
		keywordScore = 0.0
	}

	value := cfg.TokenWeight*tokenScore + cfg.KeywordWeight*keywordScore
	tier := "mid"
	if value < cfg.LowThreshold {
		tier = "low"
	} else if value >= cfg.HighThreshold {
		tier = "high"
	}
	return Score{
		Value: value,
		Tier:  tier,
		Factors: map[string]any{
			"tokens":        promptTokens,
			"token_score":   tokenScore,
			"keyword_score": keywordScore,
			"matched_high":  matchedHigh,
			"matched_low":   matchedLow,
		},
	}
}
