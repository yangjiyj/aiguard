package aimsg

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

func openAIArtifactCandidates(raw json.RawMessage, direction retentionartifact.Direction) []retentionartifact.Candidate {
	var parts []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil
	}
	candidates := make([]retentionartifact.Candidate, 0)
	for _, part := range parts {
		partType := strings.ToLower(rawString(part["type"]))
		name := rawString(part["filename"])
		if name == "" {
			name = rawString(part["name"])
		}
		switch partType {
		case "image_url", "input_image", "image_generation_call", "image":
			value := rawURL(part["image_url"])
			if value == "" {
				value = rawString(part["result"])
			}
			if value == "" {
				value = rawString(part["url"])
			}
			if candidate, ok := artifactCandidate(value, direction, retentionartifact.KindImage, name, rawString(part["mime_type"])); ok {
				candidate.Ordinal = len(candidates)
				candidates = append(candidates, candidate)
			}
		case "input_file", "file", "document":
			value := rawString(part["file_data"])
			if value == "" {
				value = rawString(part["file_url"])
			}
			if value == "" {
				value = rawString(part["file_id"])
			}
			if nested, ok := part["file"]; ok && len(bytes.TrimSpace(nested)) > 0 {
				var file map[string]json.RawMessage
				if json.Unmarshal(nested, &file) == nil {
					if name == "" {
						name = rawString(file["filename"])
					}
					if value == "" {
						value = rawString(file["file_data"])
					}
					if value == "" {
						value = rawString(file["file_url"])
					}
					if value == "" {
						value = rawString(file["file_id"])
					}
				}
			}
			if candidate, ok := artifactCandidate(value, direction, retentionartifact.KindFile, name, rawString(part["mime_type"])); ok {
				candidate.Ordinal = len(candidates)
				candidates = append(candidates, candidate)
			}
		}
	}
	return candidates
}

func anthropicArtifactCandidates(blocks []anthropicContentBlock, direction retentionartifact.Direction) []retentionartifact.Candidate {
	candidates := make([]retentionartifact.Candidate, 0)
	for _, block := range blocks {
		kind := retentionartifact.KindFile
		switch strings.ToLower(strings.TrimSpace(block.Type)) {
		case "image":
			kind = retentionartifact.KindImage
		case "document":
		default:
			continue
		}
		name := strings.TrimSpace(block.Title)
		if name == "" {
			name = strings.TrimSpace(block.Name)
		}
		if block.Source == nil {
			continue
		}
		var candidate retentionartifact.Candidate
		var ok bool
		switch strings.ToLower(strings.TrimSpace(block.Source.Type)) {
		case "base64":
			candidate, ok = artifactCandidateFromBase64(
				block.Source.Data, direction, kind, name, block.Source.MediaType,
			)
		case "url":
			candidate, ok = artifactCandidate(
				block.Source.URL, direction, kind, name, block.Source.MediaType,
			)
		}
		if ok {
			candidate.Ordinal = len(candidates)
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func artifactCandidate(value string, direction retentionartifact.Direction, kind retentionartifact.Kind, name, declaredMIME string) (retentionartifact.Candidate, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return retentionartifact.Candidate{}, false
	}
	if candidate, ok := artifactCandidateFromDataURL(value, direction, kind, name); ok {
		if candidate.DeclaredMIME == "" {
			candidate.DeclaredMIME = strings.TrimSpace(declaredMIME)
		}
		return candidate, true
	}
	if candidate, ok := artifactCandidateFromBase64(value, direction, kind, name, declaredMIME); ok {
		return candidate, true
	}
	origin := retentionartifact.OriginUploadReference
	candidate := retentionartifact.Candidate{
		Direction:            direction,
		Kind:                 kind,
		Origin:               origin,
		DisplayName:          strings.TrimSpace(name),
		DeclaredMIME:         strings.TrimSpace(declaredMIME),
		ReferenceID:          value,
		ReferenceFingerprint: ContentSHA256Hex(value),
	}
	if strings.HasPrefix(strings.ToLower(value), "http://") || strings.HasPrefix(strings.ToLower(value), "https://") {
		candidate.Origin = retentionartifact.OriginRemoteReference
		candidate.RemoteURL = value
	}
	return candidate, true
}

func artifactCandidateFromDataURL(value string, direction retentionartifact.Direction, kind retentionartifact.Kind, name string) (retentionartifact.Candidate, bool) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "data:") {
		return retentionartifact.Candidate{}, false
	}
	comma := strings.IndexByte(value, ',')
	if comma < 0 {
		return retentionartifact.Candidate{}, false
	}
	meta := value[len("data:"):comma]
	if !strings.Contains(strings.ToLower(meta), "base64") {
		return retentionartifact.Candidate{}, false
	}
	mediaType := meta
	if i := strings.IndexByte(meta, ';'); i >= 0 {
		mediaType = meta[:i]
	}
	return artifactCandidateFromBase64(value[comma+1:], direction, kind, name, mediaType)
}

func artifactCandidateFromBase64(value string, direction retentionartifact.Direction, kind retentionartifact.Kind, name, declaredMIME string) (retentionartifact.Candidate, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return retentionartifact.Candidate{}, false
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(value)
		if err != nil {
			return retentionartifact.Candidate{}, false
		}
	}
	return retentionartifact.Candidate{
		Direction:      direction,
		Kind:           kind,
		Origin:         retentionartifact.OriginInlineBytes,
		DisplayName:    strings.TrimSpace(name),
		DeclaredMIME:   strings.TrimSpace(declaredMIME),
		DeclaredSize:   int64(len(data)),
		OriginalSHA256: ContentSHA256Hex(string(data)),
		Payload:        bytes.NewReader(data),
	}, true
}

func rawString(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return strings.TrimSpace(value)
	}
	return ""
}

func rawURL(raw json.RawMessage) string {
	if value := rawString(raw); value != "" {
		return value
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return ""
	}
	return rawString(object["url"])
}
