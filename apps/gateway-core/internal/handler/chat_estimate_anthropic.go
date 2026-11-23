package handler

import (
	"os"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// Chat -> Anthropic Messages 路径的额度预占（quota admission）输入估算系数。
//
// 现象（客户现场 2026-10-23）：Chat 门户的长对话每个请求结算时 actual 都比 estimated 多 14%~17%，
// 触发 quota.admission.reservation_overrun；原生 /v1/messages 路径没有。
//
// 排查结论（代码核对 + 现场 6 组数据回归；未用真实 Claude 分词器复算，见下"未验证"）：
//  1. 不是"转换新增内容"：Chat 门户只透传 model/messages/stream/temperature/top_p/max_tokens
//     （enterprise-ai-portal/src/app/api/chat/route.ts），不带 system、不带 tools；转换
//     （provider/anthropic_chat_compat.go）只多出 cache_control 标记，标记不产生输入 token。
//     编程助手路径带的 system/tools/tool_calls 本来就在 Chat 请求里，估算已经覆盖
//     （tool_calls 历史由 c4cacd85b 补上）。
//  2. 不是"缓存没计入"：actual 的 prompt = input_tokens + cache_read + cache_creation（provider/adapter.go
//     TransformResponse、relay/transform.go usageMap、shared-go llmusage.Canonicalize 三处口径一致），
//     是整个输入的总量；估算的对象本来就是输入总量，缓存只是总量内部的分账。流式累积
//     （streaming_relay.go mergeUsage）对 Anthropic 的累计 usage 取 max，不会重复相加。
//  3. 是估算器本身的乘性偏低：estimateTextTokens 按字符数启发式（ASCII 3 字节/token、其余字符
//     1.5 token/字），没有针对当前 Claude 分词器校准。原生 Messages 路径"不告警"是因为它把每个内容块
//     拆成独立消息重复计 8 token 开销、tools 在 Tools 与 system 消息里各算一遍
//     （messages_native.go collectInputContent/collectTools），碰巧偏大，并不是估得准。
//
// 系数依据：现场 6 组 (estimated, actual) 的 estimated 含固定的输出预留 M。门户前端不下发 max_tokens
// （route.ts 只转发客户端带来的值，前端未设置），即 M=4096；扣除 M 后 actual 与输入估算之比为
// 1.19~1.21（M=8192 时 1.24~1.26），变异系数 <0.6%，是稳定的乘性偏差，且不随对话变长收敛。
// 取 1.25：M=4096 时新估算/actual = 1.06~1.08，M=8192 时 1.05~1.07，都落在 [0.95, 1.30] 内。
//
// 未验证：没有拿真实 Anthropic count_tokens 逐条复核；中文/代码/JSON 各自的真实比例只能由现场数据反推，
// 混合比例变化时偏差会变。因此做成可调环境变量，上线后以 reservation_overrun 聚合通知里的
// max_estimated/max_actual 复核。
//
// 范围：只放大 Chat 入口且上游为 Anthropic Messages 的输入估算；输出预留（max_tokens）、原生 Messages、
// Responses、其他上游协议不变。actual 仍按上游 usage 结算，不改计费口径；准入/拦截判定逻辑不变，
// 只是该路径的预占量变大（输入部分约 +25%），enforce 模式下 TPM/日月额度预占相应更紧。
// 关闭或调整：UAG_ANTHROPIC_CHAT_ESTIMATE_PERMILLE（1000=关闭，范围 1000~2000）。
const (
	anthropicChatEstimatePermilleEnv             = "UAG_ANTHROPIC_CHAT_ESTIMATE_PERMILLE"
	anthropicChatEstimatePermilleDefault   int64 = 1250
	anthropicChatEstimatePermilleMaximum   int64 = 2000
	anthropicChatEstimatePermilleNoScaling int64 = 1000
)

func anthropicChatEstimatePermille() int64 {
	raw := strings.TrimSpace(os.Getenv(anthropicChatEstimatePermilleEnv))
	if raw == "" {
		return anthropicChatEstimatePermilleDefault
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return anthropicChatEstimatePermilleDefault
	}
	if value < anthropicChatEstimatePermilleNoScaling {
		return anthropicChatEstimatePermilleNoScaling
	}
	if value > anthropicChatEstimatePermilleMaximum {
		return anthropicChatEstimatePermilleMaximum
	}
	return value
}

// chatAdmissionPromptPermille 返回本次 Chat 请求预占估算应乘的系数（千分比）。
// 只对 Chat 入口且上游最终是 Anthropic Messages 的请求放大；原生 /v1/messages、/v1/responses 以及
// 其他上游协议保持 1000（不变）。v2 路由下上游协议要到逐次尝试才确定，所以这里按已确定的上游协议、
// 供应商类型、是否配置了 Claude 原生 Messages 桥接综合判断。
func chatAdmissionPromptPermille(envelope *modelrouter.RequestEnvelope, modelRecord *modelrouter.ModelRecord) int64 {
	if envelope == nil || envelope.EndpointType != "chat" {
		return anthropicChatEstimatePermilleNoScaling
	}
	upstream := strings.ToLower(strings.TrimSpace(envelope.UpstreamProtocol))
	// 桥接判定与 selectModelRouteProtocol 一致：只有路由能力表为 Explicit 时才会走 chat->messages 桥接。
	bridgedToMessages := modelRecord != nil && modelRecord.ProtocolCapabilities.Explicit &&
		shouldBridgeClaudeChatToNativeMessages(modelRecord)
	isAnthropicMessages := upstream == "messages" ||
		strings.EqualFold(strings.TrimSpace(envelope.Provider), "anthropic") ||
		bridgedToMessages
	if !isAnthropicMessages {
		return anthropicChatEstimatePermilleNoScaling
	}
	return anthropicChatEstimatePermille()
}

// scaleEstimatePermille 把估算值乘以 permille/1000（向上取整），在 maxExactTokenCount 处饱和。
func scaleEstimatePermille(value, permille int64) int64 {
	if permille <= anthropicChatEstimatePermilleNoScaling || value <= 0 {
		return value
	}
	if value > maxExactTokenCount/permille {
		return maxExactTokenCount
	}
	return (value*permille + 999) / 1000
}
