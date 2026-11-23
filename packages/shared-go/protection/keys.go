package protection

// 防护项键、原因码、阶段原因与参数名的常量。网关、独立代理、控制面引用防护项时用这些常量，
// 不要再写字面量（注册表 items 也用它们登记）。

// 防护项键。
const (
	KeyCloudMetadata    = "agent.cloud_metadata"
	KeyPrivateNetwork   = "agent.private_network"
	KeyCloudCredential  = "agent.cloud_credential"
	KeySSHPrivateKey    = "agent.ssh_private_key"
	KeyEnvFile          = "agent.env_file"
	KeySystemSecretFile = "agent.system_secret_file"
	KeySecretMount      = "agent.secret_mount"
	KeyGitCredential    = "agent.git_credential"
	KeySensitiveName    = "agent.sensitive_name"
	KeySecretEgress     = "agent.secret_egress"
	// KeyRestrictedFile 见 registry.go。

	KeyHighRiskWithoutRule   = "agent.high_risk_without_rule"
	KeyParseRejected         = "agent.parse_rejected"
	KeyIdentityRejected      = "agent.identity_rejected"
	KeyConfirmWithoutChannel = "agent.confirm_without_channel"
	KeyToolFailureLoop       = "agent.tool_failure_loop"
	KeyBurst                 = "agent.burst"

	KeySkillIdentityInvalid      = "skill.identity_invalid"
	KeySkillDangerousCommand     = "skill.dangerous_command"
	KeySkillAdmissionUnavailable = "skill.admission_unavailable"
)

// 兜底类防护项的原因码。
const (
	ReasonParseRejected             = "destructive_parse_rejected_fail_safe"
	ReasonIdentityRejected          = "destructive_identity_rejected"
	ReasonToolFailureLoop           = "tool_failure_loop"
	ReasonBehaviorBurst             = "behavior_burst"
	ReasonSkillAdmissionUnavailable = "skill_admission_unavailable"
)

// 阶段原因（拦截记录的 cause）：没有分析器原因码可对应时，按处置阶段决定的防护项。
const (
	CauseAnalyzerHighRisk                = "analyzer_high_risk_block"
	CauseConfirmWithoutChannelFailClosed = "confirm_without_channel_fail_closed"
)

// PhaseCauseKeys 返回阶段原因到防护项键的对照（副本）。
func PhaseCauseKeys() map[string]string {
	return map[string]string{
		CauseAnalyzerHighRisk:                KeyHighRiskWithoutRule,
		CauseConfirmWithoutChannelFailClosed: KeyConfirmWithoutChannel,
	}
}

// 参数名。
const (
	ParamWindowSeconds     = "window_seconds"
	ParamThreshold         = "threshold"
	ParamTrustedAgentTypes = "trusted_agent_types"
)

// DefaultIntParam 返回注册表里某一项整数参数的默认值；没有这一项或这个参数时为 0。
func DefaultIntParam(key, param string) int {
	return Settings(nil).IntParam(key, param)
}
