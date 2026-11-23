package handler

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

func TestChatInputArtifactCandidatesRetainsInlineImage(t *testing.T) {
	image := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
	messages := []Message{{
		Role:    "user",
		Content: json.RawMessage(`[{"type":"text","text":"inspect"},{"type":"image_url","image_url":{"url":"data:image/png;base64,` + image + `"}}]`),
	}}

	candidates := chatInputArtifactCandidates(messages)
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v", candidates)
	}
	candidate := candidates[0]
	if candidate.Direction != retentionartifact.DirectionInput || candidate.Kind != retentionartifact.KindImage || candidate.Payload == nil {
		t.Fatalf("candidate = %#v", candidate)
	}
	if candidate.Ordinal != 0 || candidate.OriginalSHA256 == "" {
		t.Fatalf("candidate metadata = %#v", candidate)
	}
}
