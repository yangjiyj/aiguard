package handler

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

// reverseProxyArtifactMetadata 是旧 file_metadata_json 的兼容投影。它只含可展示的
// 协议元数据；对象键、引用 ID、远程 URL 和任何内联字节绝不能进入该列。
type reverseProxyArtifactMetadata struct {
	Direction    retentionartifact.Direction `json:"direction"`
	Kind         retentionartifact.Kind      `json:"kind"`
	DisplayName  string                      `json:"display_name,omitempty"`
	DeclaredMIME string                      `json:"declared_mime,omitempty"`
	DeclaredSize int64                       `json:"declared_size,omitempty"`
	Ordinal      int                         `json:"ordinal"`
}

func reverseProxyArtifactMetadataJSON(candidates []retentionartifact.Candidate) []byte {
	metadata := make([]reverseProxyArtifactMetadata, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Validate() != nil {
			continue
		}
		metadata = append(metadata, reverseProxyArtifactMetadata{
			Direction:    candidate.Direction,
			Kind:         candidate.Kind,
			DisplayName:  candidate.DisplayName,
			DeclaredMIME: candidate.DeclaredMIME,
			DeclaredSize: candidate.DeclaredSize,
			Ordinal:      candidate.Ordinal,
		})
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return []byte("[]")
	}
	return encoded
}
func parseReverseProxyOutputProjection(path string, body []byte) (aimsg.RetentionProjection, bool) {
	lowerPath := strings.ToLower(path)
	switch {
	case strings.Contains(lowerPath, "/responses"):
		return aimsg.ParseOpenAIResponsesResponse(body)
	case strings.Contains(lowerPath, "/messages"):
		return aimsg.ParseAnthropicMessagesResponse(body)
	default:
		return aimsg.ParseOpenAIChatResponse(body)
	}
}
