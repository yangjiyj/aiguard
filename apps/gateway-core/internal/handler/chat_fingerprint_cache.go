package handler

// P1-B 已检指纹缓存（安全三视图重构 模块 2a，契约 9）的网关侧胶水：
//   - ctx 标注管道：命中重放的 security_event 在 matched_summary 带
//     scan_mode=fingerprint_reuse + first_seen_request_id（证据不减量的技术溯源字段）。
//     用 ctx-value 而非改 AuditWriter 签名——同 skipSemanticCtxKey 先例，接口零涟漪，
//     Real/Async 两个 writer 均在入口读取（异步 outbox 序列化前标注已入 payload，不丢）。
//   - content_source 映射复用 P1-A 的 messageRoleToSource（chat_completions.go），不另造映射函数。
//   - SetFingerprintStore：chat/messages/responses 三 handler 的注入口（nil=禁用，默认零回归）。

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

type fingerprintReuseCtxKey struct{}
type securityEventIDCtxKey struct{}
type fingerprintOccurrenceCtxKey struct{}
type securityEventStageCtxKey struct{}

type fingerprintOccurrence struct {
	RepresentativeEventID string
	ContextKey            string
}

type securityOccurrenceRecorder interface {
	RecordSecurityEventOccurrence(ctx context.Context, envelope *modelrouter.RequestEnvelope, representativeEventID, contextKey string) error
}

func withFingerprintReuse(ctx context.Context, firstSeenRequestID string) context.Context {
	return context.WithValue(ctx, fingerprintReuseCtxKey{}, firstSeenRequestID)
}

func withSecurityEventStage(ctx context.Context, stage string) context.Context {
	normalized := strings.ToLower(strings.TrimSpace(stage))
	switch normalized {
	case "input", "output", "tool":
		return context.WithValue(ctx, securityEventStageCtxKey{}, normalized)
	default:
		return ctx
	}
}

func securityEventStageFromContext(ctx context.Context) string {
	stage, _ := ctx.Value(securityEventStageCtxKey{}).(string)
	switch strings.ToLower(strings.TrimSpace(stage)) {
	case "input", "output", "tool":
		return strings.ToLower(strings.TrimSpace(stage))
	default:
		return ""
	}
}

func annotateSecurityEventStage(ctx context.Context, matchedSummary map[string]interface{}) {
	if matchedSummary == nil {
		return
	}
	stage := securityEventStageFromContext(ctx)
	if stage == "" {
		return
	}
	matchedSummary["stage"] = stage
	if _, ok := matchedSummary["source"]; !ok {
		matchedSummary["source"] = "gateway"
	}
}

// fingerprintReuseFromContext 返回 (first_seen_request_id, 是否为指纹重放路径)。
func fingerprintReuseFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(fingerprintReuseCtxKey{}).(string)
	return v, ok
}

func withSecurityEventID(ctx context.Context, eventID string) context.Context {
	if strings.TrimSpace(eventID) == "" {
		return ctx
	}
	return context.WithValue(ctx, securityEventIDCtxKey{}, eventID)
}

func securityEventIDFromContext(ctx context.Context) string {
	eventID, _ := ctx.Value(securityEventIDCtxKey{}).(string)
	return strings.TrimSpace(eventID)
}

func withFingerprintOccurrence(ctx context.Context, representativeEventID, contextKey string) context.Context {
	if strings.TrimSpace(representativeEventID) == "" || strings.TrimSpace(contextKey) == "" {
		return ctx
	}
	return context.WithValue(ctx, fingerprintOccurrenceCtxKey{}, fingerprintOccurrence{
		RepresentativeEventID: representativeEventID,
		ContextKey:            contextKey,
	})
}

func fingerprintOccurrenceFromContext(ctx context.Context) (fingerprintOccurrence, bool) {
	occurrence, ok := ctx.Value(fingerprintOccurrenceCtxKey{}).(fingerprintOccurrence)
	return occurrence, ok && occurrence.RepresentativeEventID != "" && occurrence.ContextKey != ""
}

func fingerprintContextScope(envelope *modelrouter.RequestEnvelope, contentSource, actorType string, semanticTask ...string) string {
	if envelope == nil {
		base := contentSource + "|" + actorType
		for _, task := range semanticTask {
			if task != "" {
				base += "\x00" + task
			}
		}
		return scanfp.SHA256Hex(base)
	}
	parts := []string{
		envelope.ProjectID,
		envelope.UserID,
		envelope.ClientID,
		envelope.SourceIP,
		envelope.AgentType,
		contentSource,
		actorType,
	}
	for _, task := range semanticTask {
		if task != "" {
			parts = append(parts, task)
		}
	}
	return scanfp.SHA256Hex(strings.Join(parts, "\x00"))
}

// Cached findings carry content-relative spans, but their message position
// belongs to the earlier request. Never mutate the shared cache/replay slice.
func reanchorReplayedInputFindings(findings []SecurityFinding, messageIndex int, messageRole string) []SecurityFinding {
	anchored := append([]SecurityFinding(nil), findings...)
	for i := range anchored {
		index := messageIndex
		anchored[i].MessageIndex = &index
		anchored[i].MessageRole = strings.ToLower(strings.TrimSpace(messageRole))
	}
	return anchored
}

func fingerprintDetectionContextKey(
	envelope *modelrouter.RequestEnvelope,
	action string,
	findings []SecurityFinding,
	contentSource, actorType, semanticStatus string,
) string {
	semanticStatus = normalizedFingerprintSemanticStatus(semanticStatus, findings)
	// Position/role anchors describe this request, not a changed detection.
	// Provenance remains in ContextScope and ContentSource; risk fields remain
	// in the hash, so new policy decisions still create complete evidence.
	detectionFindings := append([]SecurityFinding(nil), findings...)
	for i := range detectionFindings {
		detectionFindings[i].MessageIndex = nil
		detectionFindings[i].MessageRole = ""
	}
	payload := struct {
		Scope          string            `json:"scope"`
		Action         string            `json:"action"`
		SemanticStatus string            `json:"semantic_status"`
		Findings       []SecurityFinding `json:"findings"`
	}{
		Scope:          fingerprintContextScope(envelope, contentSource, actorType),
		Action:         strings.ToLower(strings.TrimSpace(action)),
		SemanticStatus: strings.ToLower(strings.TrimSpace(semanticStatus)),
		Findings:       detectionFindings,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return scanfp.SHA256Hex(string(raw))
}

func normalizedFingerprintSemanticStatus(status string, findings []SecurityFinding) string {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "incomplete" {
		return status
	}
	if status == "completed" {
		for _, finding := range findings {
			if finding.Type == "semantic_attack" {
				return status
			}
		}
	}
	return ""
}

func countsAsSecurityFinding(finding SecurityFinding) bool {
	return finding.CountsAsSecurityFinding == nil || *finding.CountsAsSecurityFinding
}

func hasSecurityFindings(findings []SecurityFinding) bool {
	for _, finding := range findings {
		if countsAsSecurityFinding(finding) {
			return true
		}
	}
	return false
}

// retainedObservationReasons 是引擎明确要求「只留证据、不计为安全发现」的观察（disposition=observation）：
//   - policy_semantic_observe：策略「智能分析命中时」=仅记录（security-engine policy_bindings）；
//   - quoted_profanity_reference / bare_profanity_reference：辱骂词被引用或讨论时降为观察
//     （security-engine profanity，「仍留证据」）。
//   - agent_tool_failure_loop：工具连续失败，是运行类观察（不是安全风险），会进控制面「运行异常」通道。
//
// 这些观察即使没有同时命中别的规则，也要写一条事件留证；事件里的 finding 仍是
// counts_as_security_finding=false，告警桥按 isPassiveObservationOnlyEvent 只作证据、不出可处置告警。
// 其余观察（智能体清单元数据、未确认的可疑语义、上下文豁免等）维持原样，不单独成事件。
var retainedObservationReasons = map[string]bool{
	"policy_semantic_observe":    true,
	"quoted_profanity_reference": true,
	"bare_profanity_reference":   true,
	toolFailureLoopCategory:      true,
}

func hasRetainedObservations(findings []SecurityFinding) bool {
	for _, finding := range findings {
		if countsAsSecurityFinding(finding) {
			continue
		}
		disposition, _ := finding.Triage["disposition"].(string)
		reason, _ := finding.Triage["disposition_reason"].(string)
		if disposition == "observation" && retainedObservationReasons[reason] {
			return true
		}
	}
	return false
}

// retainedObservationEventKey 标记「这次写入就是 chat 输入路径的观察事件」。写入器层闸门只认这个
// 标记放行纯观察；其它直接调用写入器的入口（embeddings、图片、文件上传等）与原来一样不落库。
type retainedObservationEventKey struct{}

func withRetainedObservationEvent(ctx context.Context) context.Context {
	return context.WithValue(ctx, retainedObservationEventKey{}, true)
}

// writerPersists 是写入器层闸门：与原来一致只放行安全发现与阻断，外加显式标记的观察事件。
func writerPersists(ctx context.Context, findings []SecurityFinding, actionTaken string) bool {
	if len(findings) == 0 || hasSecurityFindings(findings) || isBlockingSecurityAction(actionTaken) {
		return true
	}
	marked, _ := ctx.Value(retainedObservationEventKey{}).(bool)
	return marked && hasRetainedObservations(findings)
}

// persistableSecurityFindings：有安全发现，或有必须留证的观察。
func persistableSecurityFindings(findings []SecurityFinding) bool {
	return hasSecurityFindings(findings) || hasRetainedObservations(findings)
}

func hasFileAttachmentFindings(findings []SecurityFinding) bool {
	for _, finding := range findings {
		if !countsAsSecurityFinding(finding) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(finding.ContentSource), "file_attachment") ||
			strings.EqualFold(strings.TrimSpace(finding.Type), "file") {
			return true
		}
	}
	return false
}

func shouldPersistSecurityEvent(action string, findings []SecurityFinding) bool {
	if hasSecurityFindings(findings) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "reply", "mask":
		return true
	default:
		return false
	}
}

func (h *ChatCompletionsHandler) writeSecurityEvent(
	ctx context.Context,
	envelope *modelrouter.RequestEnvelope,
	findings []SecurityFinding,
	actionTaken, summary string,
) {
	blocking := isBlockingSecurityAction(actionTaken)
	noteRawEvidenceFindings(ctx, actionTaken, findings)
	if len(findings) > 0 && !persistableSecurityFindings(findings) && !blocking {
		return
	}
	// A block is never folded into an earlier event: each blocked request needs
	// its own record for the block number shown to the agent.
	if occurrence, ok := fingerprintOccurrenceFromContext(ctx); ok && !blocking {
		if recorder, supported := h.auditWriter.(securityOccurrenceRecorder); supported {
			if err := recorder.RecordSecurityEventOccurrence(ctx, envelope, occurrence.RepresentativeEventID, occurrence.ContextKey); err == nil {
				return
			}
		}
	}
	h.auditWriter.WriteSecurityEvent(ctx, envelope, findings, actionTaken, summary)
}

// annotateFingerprintReuse 把指纹重放标注并入 matched_summary（契约 9）。非重放 ctx 无操作。
func annotateFingerprintReuse(ctx context.Context, matchedSummary map[string]interface{}) {
	first, ok := fingerprintReuseFromContext(ctx)
	if !ok {
		return
	}
	matchedSummary["scan_mode"] = "fingerprint_reuse"
	if first != "" {
		matchedSummary["first_seen_request_id"] = first
	}
}

// SetFingerprintStore 注入已检指纹缓存（nil=禁用，默认零回归）。
func (h *ChatCompletionsHandler) SetFingerprintStore(store *scanfp.Store) {
	h.fingerprints = store
}

// SetFingerprintStore 注入指纹缓存；随每请求的内部 ChatCompletionsHandler 透传。
func (h *MessagesHandler) SetFingerprintStore(store *scanfp.Store) {
	h.fingerprints = store
}

// SetFingerprintStore 注入指纹缓存；随每请求的内部 ChatCompletionsHandler 透传。
func (h *ResponsesHandler) SetFingerprintStore(store *scanfp.Store) {
	h.fingerprints = store
}
