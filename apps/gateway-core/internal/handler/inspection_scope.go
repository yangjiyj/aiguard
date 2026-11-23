package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
	"hash"
	"os"
	"sort"
	"strings"
)

type inputInspectionPlanKey struct{}

func protocolMessageIndex(index int) *int { return &index }

func setNativeInspectionOrigin(message *Message, path nativeJSONPath) {
	message.SecuritySource = messageRoleToSource(message.Role)
	message.SecurityMessageRole = message.Role
	parts := make([]string, len(path))
	for i, part := range path {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(fmt.Sprint(part), "~", "~0"), "/", "~1")
	}
	message.SecuritySourcePath = "/" + strings.Join(parts, "/")
	if len(path) > 0 && path[0] == "tools" {
		message.SecuritySource = "tool_def"
	}
	if len(path) > 1 && path[0] == "messages" {
		if index, ok := path[1].(int); ok {
			message.SecurityMessageIndex = protocolMessageIndex(index)
		}
	}
}

type inputInspectionTargetKey struct{}
type inputInspectionTarget struct {
	source, role, path string
	messageIndex       int
	latest, history    bool
	agentActions       []map[string]interface{}
}
type inputInspectionPlan struct {
	targets  map[int]inputInspectionTarget
	policy   inspectionscope.Policy
	judgment []map[string]any
	userTask string
	// agentRequestKind marks agent-internal requests (aimsg.AgentRequestKind);
	// it never changes a target's source, only how the engine disposes of
	// keyword-combination findings.
	agentRequestKind string
}

// agentRequestKindForMessages recognizes agent-internal requests such as
// Claude Code's security monitor from the client type and system prompt.
func agentRequestKindForMessages(agentType string, messages []Message) string {
	items := make([]aimsg.ConvMessage, 0, len(messages))
	for _, m := range messages {
		source := m.SecuritySource
		if source == "" {
			source = messageRoleToSource(m.Role)
		}
		items = append(items, aimsg.ConvMessage{Role: m.Role, Source: source, Content: messageText(m.Content)})
	}
	return aimsg.AgentRequestKind(agentType, items)
}

func (h *ChatCompletionsHandler) inspectionPolicy(ctx context.Context) inspectionscope.Policy {
	if h != nil && h.toolRiskClient != nil {
		return h.toolRiskClient.InspectionPolicy(ctx)
	}
	return inspectionscope.Default()
}
func inspectionMessagesWithTools(req *ChatCompletionRequest, policy inspectionscope.Policy) []Message {
	if !policy.InspectBuiltinContext || len(req.Tools) == 0 {
		return req.Messages
	}
	for _, m := range req.Messages {
		if m.SecuritySource == "tool_def" {
			return req.Messages
		}
	}
	result := append([]Message(nil), req.Messages...)
	for i, tool := range req.Tools {
		body, _ := json.Marshal(tool)
		result = append(result, Message{Role: "tool", Content: jsonQuote(string(body)), SecuritySource: "tool_def", SecurityMessageRole: "tool", SecuritySourcePath: fmt.Sprintf("/tools/%d", i)})
	}
	return result
}
func gatewayInputInspectionPlan(messages []Message, policy inspectionscope.Policy) inputInspectionPlan {
	items := make([]aimsg.ConvMessage, len(messages))
	for i, m := range messages {
		source := m.SecuritySource
		if source == "" {
			source = messageRoleToSource(m.Role)
		}
		if source == "" {
			source = "unknown"
		}
		role := m.SecurityMessageRole
		if role == "" {
			role = m.Role
		}
		index := m.SecurityMessageIndex
		path := m.SecuritySourcePath
		if path == "" {
			j := i
			index = &j
			path = fmt.Sprintf("/messages/%d", i)
		}
		items[i] = aimsg.ConvMessage{Role: role, Source: source, Content: messageText(m.Content), MessageIndex: index, SourcePath: path, HasAttachments: len(extractAttachments(m.Content)) > 0}
	}
	latest := aimsg.LatestUserPosition(items)
	plan := inputInspectionPlan{targets: map[int]inputInspectionTarget{}, policy: policy, judgment: aimsg.JudgmentContext(items, policy)}
	plan.userTask = aimsg.LatestUserTask(items)
	for i, m := range items {
		isLatest := aimsg.IsLatestUser(items, i, latest)
		history := aimsg.InspectionIsHistory(items, i, latest)
		if !policy.Includes(m.Source, isLatest, history) {
			continue
		}
		source := m.Source
		if source == "user" && !isLatest {
			source = "user_history"
		}
		index := -1
		if m.MessageIndex != nil {
			index = *m.MessageIndex
		}
		plan.targets[i] = inputInspectionTarget{
			source: source, role: m.Role, path: m.SourcePath, messageIndex: index,
			latest: isLatest, history: history,
			agentActions: structuredAgentActions(messages[i].ToolCalls),
		}
	}
	return plan
}

// historyTaskAgnostic reports whether history segments may be reused across
// different user tasks. Default false: task-relative verdicts must not cross
// tasks without a fresh judgment.
func historyTaskAgnostic() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GATEWAY_FP_HISTORY_TASK_AGNOSTIC"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// historyTaskHash is the task a segment was first judged under. An empty task
// (no latest user message) produces an empty part, which still separates cleanly
// from any real task hash.
func historyTaskHash(ctx context.Context) string {
	plan, ok := ctx.Value(inputInspectionPlanKey{}).(inputInspectionPlan)
	if !ok {
		return ""
	}
	task := strings.TrimSpace(plan.userTask)
	if task == "" {
		return ""
	}
	return scanfp.SHA256Hex(task)
}

func inspectionFingerprintScope(ctx context.Context, envelope *modelrouter.RequestEnvelope, source, actor string) string {
	plan, hasPlan := ctx.Value(inputInspectionPlanKey{}).(inputInspectionPlan)
	target, hasTarget := ctx.Value(inputInspectionTargetKey{}).(inputInspectionTarget)
	policy := ""
	if hasPlan {
		policy = plan.policy.Fingerprint()
	}
	// C2 incremental inspection. History segments are byte-identical across
	// turns, but the old scope mixed in the latest user task (twice: via
	// semanticTask.Scope() and plan.userTask) plus the judgment context. One new
	// user message therefore invalidated every previously inspected segment and
	// the entire 7-15万 token history was re-windowed and re-judged each turn.
	// History scope is now per message segment: envelope identity + policy
	// fingerprint + role/source/path. Trusted history (assistant, user_history)
	// stays task-agnostic. Untrusted history (tool_result / rag / web_content)
	// additionally carries the task it was first judged under, because its
	// verdict is task-relative -- see the R2 note below. Only the latest user
	// message and the latest tool result keep the full causal-task scope; their
	// judge context still carries the complete user_task.
	actions := ""
	if hasTarget {
		actions = agentActionsDigest(target.agentActions)
	}
	attachments := attachmentsDigest(attachmentsFromContext(ctx))
	if hasTarget && target.history {
		parts := []string{fingerprintContextScope(envelope, source, actor),
			policy, source, target.role, target.path}
		// R2: an untrusted segment's verdict is task-relative ("summarize this
		// tool output" vs "run this tool output"), so its scope keeps the task it
		// was first judged under. A new task misses once, is judged once, and is
		// then reused inside that task. GATEWAY_FP_HISTORY_TASK_AGNOSTIC=true
		// drops the task from the scope for maximum reuse at that risk.
		if inspectionscope.IsUntrustedSource(source) && !historyTaskAgnostic() {
			parts = append(parts, historyTaskHash(ctx))
		}
		if actions != "" {
			parts = append(parts, "agent_actions", actions)
		}
		if attachments != "" {
			parts = append(parts, "attachments", attachments)
		}
		if hasPlan && plan.agentRequestKind != "" {
			parts = append(parts, "agent_request_kind", plan.agentRequestKind)
		}
		// 有可信会话键时历史折叠按会话隔离：新会话里同一内容重新出完整事件，不并到旧会话。
		if envelope != nil && envelope.InspectionSessionKey != "" {
			parts = append(parts, "session", envelope.InspectionSessionKey)
		}
		return scanfp.SHA256Hex(strings.Join(parts, "\x00"))
	}
	base := fingerprintContextScope(envelope, source, actor, semanticTaskFromContext(ctx).Scope())
	if envelope != nil && envelope.InspectionSessionKey != "" {
		// 有可信会话键时重放折叠也按会话隔离，新会话首条照常出完整事件。
		base = scanfp.SHA256Hex(base + "\x00session\x00" + envelope.InspectionSessionKey)
	}
	if actions != "" {
		base = scanfp.SHA256Hex(base + "\x00agent_actions\x00" + actions)
	}
	if attachments != "" {
		base = scanfp.SHA256Hex(base + "\x00attachments\x00" + attachments)
	}
	if !hasPlan {
		return base
	}
	contextBytes, _ := json.Marshal(plan.judgment)
	scope := base + "|" + policy + "|" + string(contextBytes) + "|" + plan.userTask
	if plan.agentRequestKind != "" {
		// Same text in a session and in a security-monitor replay must not share verdicts.
		scope += "|agent_request_kind|" + plan.agentRequestKind
	}
	return scanfp.SHA256Hex(scope)
}

// latestUserSessionFoldScope 是"同一会话里同一条最新 user 消息"的事件折叠作用域。
//
// 编程助手一轮任务里每次工具往返都把同一条 user 消息原样重发；判定上下文随工具结果变化，
// inspectionFingerprintScope 每次都 miss，于是每次往返各写一条完整告警。本作用域只用来找
// "本会话首条完整事件"做 occurrence 折叠，不用于跳过检测：每次请求照常送检，只有命中的
// 上下文键（动作、规则、处置）与首条完全相同才折叠。没有可信会话键或不是最新 user 消息时返回空串。
func latestUserSessionFoldScope(ctx context.Context, envelope *modelrouter.RequestEnvelope, source, actor string) string {
	if envelope == nil || envelope.InspectionSessionKey == "" {
		return ""
	}
	target, ok := ctx.Value(inputInspectionTargetKey{}).(inputInspectionTarget)
	if !ok || !target.latest {
		return ""
	}
	plan, _ := ctx.Value(inputInspectionPlanKey{}).(inputInspectionPlan)
	parts := []string{"latest_user_session_fold_v1", fingerprintContextScope(envelope, source, actor),
		plan.policy.Fingerprint(), target.role, target.path, envelope.InspectionSessionKey,
		"attachments", attachmentsDigest(attachmentsFromContext(ctx)),
		"agent_request_kind", plan.agentRequestKind}
	return scanfp.SHA256Hex(strings.Join(parts, "\x00"))
}

func addInputInspectionContext(ctx context.Context, values map[string]interface{}) {
	if plan, ok := ctx.Value(inputInspectionPlanKey{}).(inputInspectionPlan); ok {
		values["inspection_policy_fingerprint"] = plan.policy.Fingerprint()
		values["judgment_context"] = plan.judgment
		// The engine must quote task text as evidence, not as authority.
		text := []rune(plan.userTask)
		if len(text) > 4096 {
			text = text[:4096]
		}
		values["user_task"] = string(text)
		if plan.agentRequestKind != "" {
			values["agent_request_kind"] = plan.agentRequestKind
		}
	}
	if target, ok := ctx.Value(inputInspectionTargetKey{}).(inputInspectionTarget); ok {
		values["source_path"] = target.path
		values["is_latest_user"] = target.latest
		values["inspection_is_history"] = target.history
		if target.messageIndex < 0 {
			delete(values, "message_index")
		}
		if len(target.agentActions) > 0 {
			values["agent_actions"] = target.agentActions
			if len(target.agentActions) == 1 {
				values["agent_action"] = target.agentActions[0]
			}
		}
	}
}

func structuredAgentActions(calls []ToolCall) []map[string]interface{} {
	actions := make([]map[string]interface{}, 0, len(calls))
	for _, call := range calls {
		name := strings.TrimSpace(call.Function.Name)
		if name == "" {
			continue
		}
		args := map[string]interface{}{}
		if raw := strings.TrimSpace(call.Function.Arguments); raw != "" {
			_ = json.Unmarshal([]byte(raw), &args)
		}
		actions = append(actions, map[string]interface{}{"tool": name, "args": args})
	}
	return actions
}

// agentActionsDigest identifies the structured tool calls an assistant message
// carries, "" when it has none. The engine derives high_risk_action from them
// (agent_actions in the judgment context), so a verdict on the message text alone
// must not be reused for the same text with different calls. A message without
// tool calls keeps exactly the scope it always had, so existing cache entries
// stay valid. json.Marshal orders map keys, so the digest is stable across turns.
func agentActionsDigest(actions []map[string]interface{}) string {
	if len(actions) == 0 {
		return ""
	}
	raw, err := json.Marshal(actions)
	if err != nil {
		raw = []byte(fmt.Sprint(actions))
	}
	return scanfp.SHA256Hex(string(raw))
}

// attachmentsDigest identifies the file bytes and references a message carries,
// "" when it has none. Attachments reach the engine through their own context
// channel (withAttachments) and the file-type policy and file DLP must always see
// the real bytes, so a verdict on the text alone, or on other bytes, must not be
// reused for this message. The payload is streamed through the hash in chunks so a
// large base64 body is not copied. A message without attachments keeps exactly the
// scope it always had, so existing cache entries stay valid.
func attachmentsDigest(atts []map[string]interface{}) string {
	if len(atts) == 0 {
		return ""
	}
	h := sha256.New()
	sep := []byte{0}
	for _, att := range atts {
		keys := make([]string, 0, len(att))
		for key := range att {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			writeDigestString(h, key)
			h.Write(sep)
			if value, ok := att[key].(string); ok {
				writeDigestString(h, value)
			} else {
				raw, _ := json.Marshal(att[key])
				h.Write(raw)
			}
			h.Write(sep)
		}
		h.Write([]byte{1})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeDigestString(h hash.Hash, s string) {
	const chunk = 64 << 10
	for len(s) > chunk {
		h.Write([]byte(s[:chunk]))
		s = s[chunk:]
	}
	h.Write([]byte(s))
}
