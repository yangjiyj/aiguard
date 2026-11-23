package handler

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
)

const maxSystemSettingsBodyBytes = 64 << 10

var semanticBooleanSettingKeys = map[string]struct{}{
	"inspect_user_input":               {},
	"inspect_model_output":             {},
	"inspect_builtin_context":          {},
	"inspect_history":                  {},
	"inspect_tool_results":             {},
	"semantic_enabled":                 {},
	"semantic_input_enabled":           {},
	"semantic_agent_enabled":           {},
	"semantic_output_enabled":          {},
	"security_audit_only":              {},
	"judge_allow_private_egress":       {},
	"tier1_enabled":                    {},
	"fp_suppression_enabled":           {},
	"source_aware_enabled":             {},
	"confidence_gating_enabled":        {},
	"coding_traffic_downgrade_enabled": {},
	"file_content_dlp_enabled":         {},
	guardrailFailClosedSettingKey:      {},
}

func validateSemanticSettingValues(ctx context.Context, settings map[string]string) error {
	return validateSemanticSettingValuesWithNetwork(ctx, settings, defaultSemanticJudgeNetwork())
}

func validateSemanticSettingValuesWithNetwork(ctx context.Context, settings map[string]string, network semanticJudgeNetwork) error {
	for key := range semanticBooleanSettingKeys {
		if raw, ok := settings[key]; ok {
			value := strings.ToLower(strings.TrimSpace(raw))
			if value != "true" && value != "false" {
				return fmt.Errorf("%s must be true or false", key)
			}
		}
	}
	if semanticSettingEnabled(settings, "semantic_output_enabled") {
		return fmt.Errorf("semantic_output_enabled cannot be enabled; output uses deterministic data and content checks")
	}
	if raw, ok := settings["semantic_sample_rate"]; ok {
		value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil || value < 0 || value > 1 {
			return fmt.Errorf("semantic_sample_rate must be between 0 and 1")
		}
	}
	if raw, ok := settings[semanticBlockMinConfidenceKey]; ok {
		value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil || math.IsNaN(value) || value < 0.5 || value > 1 {
			return fmt.Errorf("%s must be between 0.5 and 1.0", semanticBlockMinConfidenceKey)
		}
	}
	if raw, ok := settings["semantic_total_timeout"]; ok {
		value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil || value < 1 || value > 60 {
			return fmt.Errorf("semantic_total_timeout must be between 1 and 60")
		}
	}
	if raw, ok := settings["judge_backend"]; ok {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "bundled", "provider", "custom":
		default:
			return fmt.Errorf("judge_backend is unsupported")
		}
	}
	if raw, ok := settings["judge_url"]; ok && strings.TrimSpace(raw) != "" {
		if _, err := prepareSemanticJudgeEndpoint(
			ctx,
			raw,
			semanticSettingEnabled(settings, "judge_allow_private_egress"),
			network,
		); err != nil {
			return err
		}
	}
	if raw, ok := settings["tier1_url"]; ok {
		value := strings.TrimSpace(raw)
		if value != "" && value != defaultTier1URL {
			return fmt.Errorf("tier1_url is managed and cannot be changed")
		}
	}
	if len(settings["judge_model"]) > 255 ||
		len(settings["judge_provider_id"]) > 128 ||
		len(settings["judge_api_key"]) > 8192 {
		return fmt.Errorf("semantic judge field exceeds limit")
	}
	return nil
}

func semanticSettingEnabled(settings map[string]string, key string) bool {
	return strings.EqualFold(strings.TrimSpace(settings[key]), "true")
}
