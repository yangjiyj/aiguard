package handler

// agentDirectAPICallCategory 是引擎对网关原生入口每条送检消息都附带的「直接 API 调用」识别标签
// （security-engine _detect_policy_context：client_type=api）。它描述的是请求从哪条入口进来，
// 不是内容风险：引擎把它标成观察（counts_as_security_finding=false，agent_inventory_metadata）。
const agentDirectAPICallCategory = "agent_direct_api_call"

// isRequestContextLabel 判断一条 finding 是否只是请求识别标签。客户把「API 直接调用检测」策略
// 设成拦截时引擎会把它计为真实命中（counts=true / action=block），那时仍按命中处理，不在此列。
func isRequestContextLabel(finding SecurityFinding) bool {
	return finding.Category == agentDirectAPICallCategory &&
		!countsAsSecurityFinding(finding) &&
		!isBlockingSecurityAction(finding.Action)
}

// splitRequestContextLabels 把请求识别标签从安全事件的 findings 里拿出来：事件只记真实命中与
// 需留证的观察，标签以 request_labels 附在事件上（请求本身的 request_logs 审计结果仍原样保留）。
// 以前每条安全事件都带一条「直接 API 调用」，现场命中统计里它占了四成。
func splitRequestContextLabels(findings []SecurityFinding) ([]SecurityFinding, []string) {
	var labels []string
	kept := findings
	for i, finding := range findings {
		if !isRequestContextLabel(finding) {
			if len(labels) > 0 {
				kept = append(kept, finding)
			}
			continue
		}
		if len(labels) == 0 {
			kept = append(make([]SecurityFinding, 0, len(findings)-1), findings[:i]...)
		}
		if !containsRequestLabel(labels, finding.Category) {
			labels = append(labels, finding.Category)
		}
	}
	return kept, labels
}

func containsRequestLabel(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
