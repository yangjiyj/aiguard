package aimsg

import (
	"fmt"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

type ParseStatus string

const (
	ParseComplete    ParseStatus = "complete"
	ParseTextOnly    ParseStatus = "text_only"
	ParsePartial     ParseStatus = "partial"
	ParseAmbiguous   ParseStatus = "ambiguous"
	ParseUnsupported ParseStatus = "unsupported"
)

type RetentionProjection struct {
	UserInput       string
	UserInputSHA256 string
	ModelOutput     string
	ConversationID  string
	TurnKey         string
	Model           string
	ParserName      string
	ParserVersion   string
	Status          ParseStatus
	Artifacts       []retentionartifact.Candidate
}

func (p RetentionProjection) Validate() error {
	switch p.Status {
	case ParseComplete, ParseTextOnly, ParsePartial, ParseAmbiguous, ParseUnsupported:
	default:
		return fmt.Errorf("invalid retention projection status %q", p.Status)
	}
	for _, artifact := range p.Artifacts {
		if err := artifact.Validate(); err != nil {
			return err
		}
	}
	return nil
}
