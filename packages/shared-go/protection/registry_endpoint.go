package protection

import "strings"

// 端侧（hookd）内置规则的防护项。规则本身（匹配条件）在控制面
// apps/control-plane/internal/agentendpoint.BuiltinRules，这里只登记处置：键为
// endpoint.rule.<规则 ID>，原因码就是规则 ID。两边的规则 ID 由控制面测试对齐。
const endpointRuleKeyPrefix = "endpoint.rule."

// 端侧内置规则里按文件路径命中的三条（原因码即规则 ID）：例外按路径层级比对，与 agent.env_file 等同口径。
const (
	EndpointRuleEnvFiles          = "builtin_env_files"
	EndpointRuleSSHPrivateKeys    = "builtin_ssh_private_keys"
	EndpointRuleSSHAuthorizedKeys = "builtin_ssh_authorized_keys"
)

// EndpointRuleKey 返回端侧内置规则对应的防护项键。
func EndpointRuleKey(ruleID string) string { return endpointRuleKeyPrefix + ruleID }

// EndpointRuleID 从防护项键取回端侧内置规则 ID；不是端侧规则的键返回空串。
func EndpointRuleID(key string) string {
	if !strings.HasPrefix(key, endpointRuleKeyPrefix) {
		return ""
	}
	return strings.TrimPrefix(key, endpointRuleKeyPrefix)
}

func init() {
	for _, rule := range []struct{ id, label string }{
		{"builtin_destructive_rm", "递归删除根目录"},
		{"builtin_destructive_system", "格式化磁盘、关机或重启"},
		{"builtin_destructive_dd", "dd 写入块设备"},
		{"builtin_secret_arguments", "参数里带密钥"},
		{EndpointRuleSSHAuthorizedKeys, "SSH 授权公钥文件"},
		{EndpointRuleSSHPrivateKeys, "SSH 私钥文件"},
		{EndpointRuleEnvFiles, ".env 文件"},
		{"builtin_curl_file_egress", "curl 上传本地文件"},
	} {
		items = append(items, Item{
			Key: EndpointRuleKey(rule.id), Group: GroupEndpoint, Label: rule.label,
			Reasons: []string{rule.id}, Actions: racb, Default: ActionAlertAllow,
		})
	}
}
