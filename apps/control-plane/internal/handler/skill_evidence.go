package handler

import (
	"encoding/json"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/skillscan"
)

func sanitizeSkillVersionEvidence(version *repository.SkillAssetVersion) *repository.SkillAssetVersion {
	if version == nil {
		return nil
	}
	safe := *version
	var findings []skillscan.Finding
	if json.Unmarshal(version.FindingsJSON, &findings) != nil {
		safe.FindingsJSON = json.RawMessage("[]")
		return &safe
	}
	safe.FindingsJSON, _ = json.Marshal(skillscan.SanitizeFindings(findings))
	return &safe
}
