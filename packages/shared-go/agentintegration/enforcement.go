package agentintegration

import (
	"os"
	"strings"
)

// 未显式允许拦截的部署（包括非法值）只记录。
func EnforcementGate() string {
	if os.Getenv("INTEGRATION_KEY_ENFORCEMENT") == "allow_block" {
		return "allow_block"
	}
	return "record_only"
}

func EffectiveEnforcement(configured string, integration bool) string {
	if !integration {
		return "block"
	}
	if configured == "block" && EnforcementGate() == "allow_block" {
		return "block"
	}
	return "record"
}

func (k *Credential) ResolveEnforcement() {
	k.EnforcementGate = EnforcementGate()
	k.EffectiveEnforcement = EffectiveEnforcement(k.Enforcement, true)
	k.EffectiveDLPEnforcement = EffectiveEnforcement(k.DLPEnforcement, true)
	if k.ModelAllowlist == nil {
		k.ModelAllowlist = []string{}
	}
}

// 模型名称必须精确、非空；租户归属另由数据库校验。
func ValidateCredentialControls(k Credential) error {
	if k.Enforcement != "" && k.Enforcement != "record" && k.Enforcement != "block" {
		return ErrInvalid
	}
	if k.DLPEnforcement != "" && k.DLPEnforcement != "record" && k.DLPEnforcement != "block" {
		return ErrInvalid
	}
	if k.ModelRestriction != "" && k.ModelRestriction != "allowlist" {
		return ErrInvalid
	}
	if len(k.ModelAllowlist) > 500 || (k.ModelRestriction == "allowlist" && len(k.ModelAllowlist) == 0) || (k.ModelRestriction == "" && len(k.ModelAllowlist) > 0) {
		return ErrInvalid
	}
	for _, name := range k.ModelAllowlist {
		if name == "" || strings.TrimSpace(name) != name || strings.Contains(name, "*") {
			return ErrInvalid
		}
	}
	return nil
}

type CredentialUpdate struct {
	ModelAllowlist *[]string
	Enforcement    *string
	DLPEnforcement *string
}
