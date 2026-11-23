package handler

import (
	"encoding/base64"
	"io"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

// artifactAttachmentsFromCandidates adapts the shared protocol parser to the
// legacy attachment shape. It keeps bytes only in memory until the retention
// writer externalizes them and uses a fingerprint, never a raw provider ID.
func artifactAttachmentsFromCandidates(candidates []retentionartifact.Candidate) []ExtractedAttachment {
	out := make([]ExtractedAttachment, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate.Validate() != nil {
			continue
		}
		key := candidate.StableKey()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		fieldName := "agent_artifact." + string(candidate.Direction)
		if candidate.Payload != nil {
			body, err := io.ReadAll(io.LimitReader(candidate.Payload, maxAttachmentContextBytes+1))
			if err != nil || len(body) > maxAttachmentContextBytes {
				continue
			}
			attachment := attachmentFromBytes("agent_artifact", fieldName, candidate.DisplayName, candidate.DeclaredMIME, body)
			if attachment.DataBase64 == "" {
				attachment.DataBase64 = base64.StdEncoding.EncodeToString(body)
			}
			out = append(out, attachment)
			continue
		}
		out = append(out, ExtractedAttachment{
			Source: "agent_artifact_reference", FieldName: fieldName,
			FileName: candidate.DisplayName, ReferenceID: strings.TrimSpace(candidate.ReferenceFingerprint),
			ContentType: candidate.DeclaredMIME, Size: candidate.DeclaredSize,
			SHA256: candidate.OriginalSHA256,
		})
	}
	return out
}
