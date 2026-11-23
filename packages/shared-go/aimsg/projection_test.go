package aimsg

import (
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

func TestRetentionProjectionSeparatesUserOutputAndArtifacts(t *testing.T) {
	projection := RetentionProjection{
		UserInput:   "inspect this image",
		ModelOutput: "inspection complete",
		Status:      ParseComplete,
		Artifacts: []retentionartifact.Candidate{{
			Direction:      retentionartifact.DirectionInput,
			Kind:           retentionartifact.KindImage,
			OriginalSHA256: "abc123",
		}},
	}

	if err := projection.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if projection.UserInput == projection.ModelOutput {
		t.Fatal("user input and model output must remain separate")
	}
	if len(projection.Artifacts) != 1 || projection.Artifacts[0].Direction != retentionartifact.DirectionInput {
		t.Fatalf("Artifacts = %#v, want one input artifact", projection.Artifacts)
	}
}

func TestRetentionProjectionDoesNotBackfillUnknownContent(t *testing.T) {
	projection := RetentionProjection{Status: ParseAmbiguous}

	if err := projection.Validate(); err != nil {
		t.Fatalf("ambiguous empty projection should be valid: %v", err)
	}
	if projection.UserInput != "" || projection.ModelOutput != "" {
		t.Fatalf("ambiguous projection exposed content: %#v", projection)
	}
}
