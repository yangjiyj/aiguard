// Package protection 是 2.9.22 起全部“可配置防护项”的唯一注册表。
// 网关、独立代理、控制面都从这里取键、原因码、可选动作和默认值；
// 不在这里登记的原因码不得产生阻断或确认（见 gateway-core 守门测试）。
package protection

type Action string

const (
	ActionRecord     Action = "record"
	ActionAlertAllow Action = "alert_allow"
	ActionConfirm    Action = "confirm"
	ActionBlock      Action = "block"
)

type Group string

const (
	GroupAgentTarget     Group = "agent_target"
	GroupAgentFallback   Group = "agent_fallback"
	GroupAgentRestricted Group = "agent_restricted"
	GroupSkill           Group = "skill"
	GroupMCP             Group = "mcp"
	GroupEndpoint        Group = "endpoint"
)

const KeyRestrictedFile = "agent.restricted_file"

type ParamKind string

const (
	ParamInt        ParamKind = "int"
	ParamStringList ParamKind = "string_list"
)

type Param struct {
	Key     string    `json:"key"`
	Label   string    `json:"label"`
	Kind    ParamKind `json:"kind"`
	Default any       `json:"default"`
	Min     int       `json:"min,omitempty"`
	Max     int       `json:"max,omitempty"`
}

type Item struct {
	Key     string   `json:"key"`
	Group   Group    `json:"group"`
	Label   string   `json:"label"`
	Reasons []string `json:"-"`
	Actions []Action `json:"actions"`
	Default Action   `json:"default_action"`
	Params  []Param  `json:"params,omitempty"`
}

func (i Item) Allows(a Action) bool {
	for _, x := range i.Actions {
		if x == a {
			return true
		}
	}
	return false
}

var (
	racb = []Action{ActionRecord, ActionAlertAllow, ActionConfirm, ActionBlock}
	rab  = []Action{ActionRecord, ActionAlertAllow, ActionBlock}
)

var items = []Item{
	{Key: KeyCloudMetadata, Group: GroupAgentTarget, Label: "云元数据地址", Reasons: []string{"blocked_cloud_metadata", "blocked_cloud_metadata_hostname"}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeyPrivateNetwork, Group: GroupAgentTarget, Label: "内网与本机地址", Reasons: []string{"blocked_loopback_or_private_ip"}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeyCloudCredential, Group: GroupAgentTarget, Label: "云凭据文件", Reasons: []string{"blocked_cloud_credential_path"}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeySSHPrivateKey, Group: GroupAgentTarget, Label: "SSH 私钥", Reasons: []string{"blocked_ssh_private_key_path"}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeyEnvFile, Group: GroupAgentTarget, Label: ".env 文件", Reasons: []string{"blocked_env_file"}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeySystemSecretFile, Group: GroupAgentTarget, Label: "系统口令与进程环境", Reasons: []string{"blocked_system_secret_file"}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeySecretMount, Group: GroupAgentTarget, Label: "密钥挂载目录", Reasons: []string{"blocked_secret_mount_path"}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeyGitCredential, Group: GroupAgentTarget, Label: "git 口令", Reasons: []string{"blocked_git_credential_dump", "blocked_git_credentials_file"}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeySensitiveName, Group: GroupAgentTarget, Label: "名字像敏感文件", Reasons: []string{"sensitive_name_hint"}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeySecretEgress, Group: GroupAgentTarget, Label: "密钥外发", Reasons: []string{"high_confidence_secret_egress"}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeyRestrictedFile, Group: GroupAgentRestricted, Label: "受限文件", Reasons: []string{"restricted_file_pattern"}, Actions: rab, Default: ActionBlock},
	{Key: KeyHighRiskWithoutRule, Group: GroupAgentFallback, Label: "未配置规则的高风险调用", Actions: racb, Default: ActionAlertAllow},
	{Key: KeyParseRejected, Group: GroupAgentFallback, Label: "参数无法解析", Reasons: []string{ReasonParseRejected}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeyIdentityRejected, Group: GroupAgentFallback, Label: "调用身份异常", Reasons: []string{ReasonIdentityRejected}, Actions: racb, Default: ActionAlertAllow,
		Params: []Param{{Key: ParamTrustedAgentTypes, Label: "可信客户端", Kind: ParamStringList, Default: []string{}}}},
	{Key: KeyConfirmWithoutChannel, Group: GroupAgentFallback, Label: "需要确认但无法确认", Actions: rab, Default: ActionAlertAllow},
	{Key: KeyToolFailureLoop, Group: GroupAgentFallback, Label: "工具连续失败", Reasons: []string{ReasonToolFailureLoop}, Actions: racb, Default: ActionAlertAllow,
		Params: []Param{
			{Key: ParamWindowSeconds, Label: "窗口（秒）", Kind: ParamInt, Default: 600, Min: 10, Max: 86400},
			{Key: ParamThreshold, Label: "次数", Kind: ParamInt, Default: 5, Min: 2, Max: 1000},
		}},
	{Key: KeyBurst, Group: GroupAgentFallback, Label: "短时调用过多", Reasons: []string{ReasonBehaviorBurst}, Actions: racb, Default: ActionAlertAllow,
		Params: []Param{{Key: ParamWindowSeconds, Label: "窗口（秒）", Kind: ParamInt, Default: 10, Min: 1, Max: 3600}}},
	{Key: KeySkillIdentityInvalid, Group: GroupSkill, Label: "Skill 身份异常", Reasons: []string{"skill_identity_misplaced", "skill_identity_invalid", "skill_identity_conflict"}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeySkillDangerousCommand, Group: GroupSkill, Label: "Skill 参数含危险命令", Reasons: []string{"skill_dangerous_command"}, Actions: racb, Default: ActionAlertAllow},
	{Key: KeySkillAdmissionUnavailable, Group: GroupSkill, Label: "准入服务不可用", Reasons: []string{ReasonSkillAdmissionUnavailable}, Actions: racb, Default: ActionAlertAllow},
}

func All() []Item {
	out := make([]Item, len(items))
	copy(out, items)
	return out
}

func Lookup(key string) (Item, bool) {
	for _, item := range items {
		if item.Key == key {
			return item, true
		}
	}
	return Item{}, false
}

func ItemForReason(reason string) (Item, bool) {
	for _, item := range items {
		for _, r := range item.Reasons {
			if r == reason {
				return item, true
			}
		}
	}
	return Item{}, false
}

// Rank 给动作排强弱，数值大者更严。
func Rank(a Action) int {
	switch a {
	case ActionBlock:
		return 4
	case ActionConfirm:
		return 3
	case ActionAlertAllow:
		return 2
	case ActionRecord:
		return 1
	default:
		return 0
	}
}
