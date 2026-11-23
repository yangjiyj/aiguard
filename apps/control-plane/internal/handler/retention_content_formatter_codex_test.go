package handler

import (
	"strconv"
	"strings"
	"testing"
)

func TestFormatAccessRetentionRequestSalvagesTruncatedCodexResponsesJSON(t *testing.T) {
	instructions := strings.Repeat("You are Codex. current_turn uses shell_command with sandbox_permissions.\n", 16)
	raw := `{"instructions":` + strconv.Quote(instructions) + `,"input":[{"role":"developer","content":[{"type":"input_text","text":"developer runtime"}]},{"role":"user","content":[{"type":"input_text","text":"只保留这句真实用户问题"}]}],"truncated":`

	got := formatAccessRetentionRequest(raw)
	if got != "只保留这句真实用户问题" {
		t.Fatalf("截断 JSON 未抽出真实用户输入: %q", got)
	}
	if strings.Contains(got, "【系统】") || strings.Contains(got, "You are Codex") {
		t.Fatalf("截断 JSON 的系统上下文不得展示: %q", got)
	}
}

func TestFormatAccessRetentionResponseLabelsCodexRuntimeNoise(t *testing.T) {
	raw := "response trace:\n" + strings.Repeat("You are Codex. current_turn uses shell_command and sandbox_permissions.\n", 16)

	got := formatAccessRetentionResponse(raw, "")
	if got != "" {
		t.Fatalf("Codex 运行指令不得展示: %q", got)
	}
}

func TestFormatAccessRetentionResponseLabelsCodexPersonalityRuntimeNoise(t *testing.T) {
	raw := strings.Repeat("# Personality\nYou have a vivid inner life as Codex: intelligent, playful, curious, and deeply present.\n# General\nYou bring a senior engineer's judgment to the work and search files with rg.\n", 4)

	got := formatAccessRetentionResponse(raw, "")
	if got != "" {
		t.Fatalf("Codex 人格运行提示不得展示: %q", got)
	}
}
