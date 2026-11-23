package main

import (
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"testing"
)

func TestReviewScopeRejectsUnverifiedOrAdditionalHits(t *testing.T) {
	valid := repository.AlertOccurrence{EventID: "e1", Category: "weapon", ContentSource: "tool_result", EvidenceRecovered: true, RawEvidenceSHA256: "raw", EvidenceContextSHA256: "context"}
	for _, tc := range []struct {
		name  string
		items []repository.AlertOccurrence
		valid bool
	}{
		{"exact", []repository.AlertOccurrence{valid}, true},
		{"extra", []repository.AlertOccurrence{valid, valid}, false},
		{"missing", nil, false},
		{"different", []repository.AlertOccurrence{{EventID: "e2", Category: "weapon", ContentSource: "tool_result", EvidenceRecovered: true, RawEvidenceSHA256: "raw", EvidenceContextSHA256: "context"}}, false},
		{"unverified", []repository.AlertOccurrence{{EventID: "e1", Category: "weapon", ContentSource: "tool_result", RawEvidenceSHA256: "raw", EvidenceContextSHA256: "context"}}, false},
		// 2.9.22 起新事件直接存了原文，不经留存回捞（EvidenceRecovered 为假），同样是可复核的证据。
		{"stored raw", []repository.AlertOccurrence{{EventID: "e1", Category: "weapon", ContentSource: "tool_result", RawEvidence: "原文片段", RawEvidenceSHA256: "raw", EvidenceContextSHA256: "context"}}, true},
		{"blank raw", []repository.AlertOccurrence{{EventID: "e1", Category: "weapon", ContentSource: "tool_result", RawEvidence: "  ", RawEvidenceSHA256: "raw", EvidenceContextSHA256: "context"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHits(tc.items, map[string]bool{"e1": true}, "weapon", "raw", "context")
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
