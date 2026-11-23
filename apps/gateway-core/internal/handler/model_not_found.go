package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

const (
	// modelNotFoundHint 是 404 model_not_found 必带的操作指引。
	modelNotFoundHint = "请到控制台查看可用模型"
	// requestStatusModelNotFound 是 request_logs.request_status 的新取值：
	// 客户端请求的模型名不在租户可用目录里（与「模型存在但没有可用线路」的
	// model_route_unavailable 区分开，不触发线路告警）。
	requestStatusModelNotFound = "model_not_found"

	modelResolutionSuffixAlias = "suffix_alias"

	rejectReasonKeyAllowlist = "key_allowlist"
	rejectReasonUserGrant    = "user_grant"

	routeUnavailableBaseMessage = "no usable upstream route for requested model"
)

// asModelNotFound 只认「目录里没有这个模型」；数据库故障等基础设施错误不算，
// 避免把故障说成 404 掩盖问题。
func asModelNotFound(err error) (*modelrouter.ModelNotFoundError, bool) {
	var miss *modelrouter.ModelNotFoundError
	if errors.As(err, &miss) && miss != nil {
		return miss, true
	}
	return nil, false
}

// modelNotFoundMessage 的文案只含客户端自己提交的模型名，不回显候选清单
// （歧义时的候选只进审计记录，避免向没有授权的调用方泄露目录）。
func modelNotFoundMessage(miss *modelrouter.ModelNotFoundError, requested string) string {
	switch miss.Reason {
	case modelrouter.ModelMissInactive:
		return fmt.Sprintf("model %q is disabled. %s", requested, modelNotFoundHint)
	case modelrouter.ModelMissAmbiguous:
		return fmt.Sprintf("model %q matches more than one model, use the full model name. %s", requested, modelNotFoundHint)
	default:
		return fmt.Sprintf("model %q does not exist or is not available to this tenant. %s", requested, modelNotFoundHint)
	}
}

// rejectModelNotFound 记录审计并按 OpenAI 风格返回 404。Anthropic 入口在
// flushNativeMessagesPreflightError 里把同一个错误转成 Anthropic 报文。
func rejectModelNotFound(
	ctx context.Context,
	w http.ResponseWriter,
	audit AuditWriter,
	partialEnvelope *modelrouter.RequestEnvelope,
	miss *modelrouter.ModelNotFoundError,
	requested string,
	requestID string,
	startedAt time.Time,
) {
	partialEnvelope.ClientModel = requested
	partialEnvelope.ModelResolution = miss.Reason
	partialEnvelope.ModelCandidates = append([]string(nil), miss.Candidates...)
	partialEnvelope.RejectReason = requestStatusModelNotFound
	audit.EnsureRequestLog(ctx, partialEnvelope)
	audit.FinalizeRequestLog(ctx, partialEnvelope, nil, requestStatusModelNotFound, http.StatusNotFound, int(time.Since(startedAt)/time.Millisecond), nil)
	writeErrorResponse(w, requestStatusModelNotFound, modelNotFoundMessage(miss, requested), requestID)
}

// applyModelAlias 在解析器把未加前缀的名字补全成唯一的全名后，让后续授权、计费、
// 路由、上游转发都以全名为准，同时记下客户端原始写法。返回新的模型名；
// 没有发生别名解析时返回空串。
func applyModelAlias(envelope *modelrouter.RequestEnvelope, record *modelrouter.ModelRecord) string {
	if record == nil || record.AliasFrom == "" {
		return ""
	}
	if envelope != nil {
		envelope.ClientModel = record.AliasFrom
		envelope.ModelResolution = modelResolutionSuffixAlias
		envelope.Model = record.ModelName
	}
	return record.ModelName
}

// modelDeniedMessage 说明被拒的是哪个模型、为什么：密钥白名单，还是账号（部门/个人）授权。
// 保留 "model is not allowed by user policy" 前缀，兼容已有的客户端文案匹配。
func modelDeniedMessage(ctx context.Context, name string) string {
	if !auth.KeyModelAllowed(ctx, name) {
		return fmt.Sprintf("model is not allowed by user policy: %q is not in this API key's model allowlist", name)
	}
	return fmt.Sprintf("model is not allowed by user policy: %q is not in your department/personal model grant", name)
}

func modelDenialRejectReason(ctx context.Context, name string) string {
	if !auth.KeyModelAllowed(ctx, name) {
		return rejectReasonKeyAllowlist
	}
	return rejectReasonUserGrant
}

// routeUnavailableMessage 返回 503 给客户端的文案：保持原来的固定文案，不暴露内部线路状态
// （没有凭证、熔断、健康门拒绝等）。具体拒绝原因只写进审计（routing_decision_json.reject_reason）
// 和服务端日志，运维用请求 ID 对照排查。
func routeUnavailableMessage(envelope *modelrouter.RequestEnvelope) string {
	if envelope != nil && strings.TrimSpace(envelope.RejectReason) != "" {
		log.Printf("model_route_unavailable request_id=%s model=%q reject_reason=%s", envelope.RequestID, envelope.Model, envelope.RejectReason)
	}
	return routeUnavailableBaseMessage
}

// auditRoutingDecision 返回写入 request_logs.routing_decision_json 的决策：
// 失败请求、别名解析或带拒绝原因的请求，在原决策（若有）上叠加客户端原始模型名等字段。
// 叠加在拷贝上进行，不改动信封里的原对象；没有任何需要补充时原样返回。
func auditRoutingDecision(envelope *modelrouter.RequestEnvelope, statusCode int) *modelrouter.RoutingDecision {
	if envelope == nil {
		return nil
	}
	// 只有解析/拒绝原因需要记录，或失败请求本来就带路由决策时才叠加，
	// 不为所有 >=400 的请求凭空写一份决策。
	needsOverlay := envelope.ModelResolution != "" || envelope.RejectReason != "" ||
		(envelope.RoutingDecision != nil && statusCode >= http.StatusBadRequest && envelope.ClientModel != "")
	if !needsOverlay {
		return envelope.RoutingDecision
	}
	var decision modelrouter.RoutingDecision
	if envelope.RoutingDecision != nil {
		decision = *envelope.RoutingDecision
	}
	decision.ClientModel = envelope.ClientModel
	decision.ModelResolution = envelope.ModelResolution
	decision.ModelCandidates = envelope.ModelCandidates
	decision.RejectReason = envelope.RejectReason
	return &decision
}

// rewriteRequestBodyModel 只替换请求体里的 model 字段，其余字段按原样（含大整数）保留。
func rewriteRequestBodyModel(body []byte, model string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		if err == nil {
			err = errors.New("request body must be a JSON object")
		}
		return nil, fmt.Errorf("failed to rewrite request model: %w", err)
	}
	encoded, err := json.Marshal(model)
	if err != nil {
		return nil, err
	}
	fields["model"] = encoded
	return json.Marshal(fields)
}

// errModelNotFoundRejected 表示 404 已经写给客户端、请求已审计；调用方直接返回。
var errModelNotFoundRejected = errors.New("model_not_found")

// rejectModelDenied 写 403（OpenAI 风格）并审计：消息指明被拒的模型与原因，
// reject_reason 区分密钥白名单与账号授权，client_model 记录客户端原始写法。
func rejectModelDenied(
	ctx context.Context,
	w http.ResponseWriter,
	audit AuditWriter,
	partialEnvelope *modelrouter.RequestEnvelope,
	model string,
	requestID string,
	startedAt time.Time,
) error {
	code := auth.ModelDenialCode(ctx, model)
	partialEnvelope.RejectReason = modelDenialRejectReason(ctx, model)
	audit.EnsureRequestLog(ctx, partialEnvelope)
	audit.FinalizeRequestLog(ctx, partialEnvelope, nil, code, http.StatusForbidden, int(time.Since(startedAt)/time.Millisecond), nil)
	writeErrorResponse(w, code, modelDeniedMessage(ctx, model), requestID)
	return fmt.Errorf("%s", code)
}

// featureContractRejectReason / featureContractMessage：能力契约不满足时，
// 把缺失的特征名（stream/tools/reasoning/cache_tokens 等内部枚举，无敏感信息）带进审计和客户端报错。
func featureContractRejectReason(reasons []string) string {
	if len(reasons) == 0 {
		return "feature_contract"
	}
	return "feature_contract:" + strings.Join(reasons, ",")
}

func featureContractMessage(reasons []string) string {
	message := "configured route cannot preserve the request feature contract"
	if len(reasons) > 0 {
		message += " (missing: " + strings.Join(reasons, ",") + ")"
	}
	return message
}

// plannedRouteRejectReason 区分 V2 规划阶段失败的原因：策略不适用、规划报错，
// 以及规划成功但没有任何可执行线路（具体原因看 model_route_v2.fallback_reason）。
func plannedRouteRejectReason(plan modelrouter.RoutePlan, planErr error, applied bool) string {
	switch {
	case !applied:
		return "route_policy_not_applied"
	case plan.Decision != nil && plan.Decision.ModelRouteV2 != nil && plan.Decision.ModelRouteV2.FallbackReason != "":
		return "route_plan_failed:" + plan.Decision.ModelRouteV2.FallbackReason
	case planErr != nil:
		return "route_plan_failed"
	}
	return "route_plan_failed"
}

func envelopeModelName(envelope *modelrouter.RequestEnvelope) string {
	if envelope == nil {
		return ""
	}
	return envelope.Model
}

// admittedRouteRejectReason 汇总「没有线路被放行」的原因：取各候选线路被排除的原因
// （semantic_capability:缺失特征 / missing_credential / health_gate_refused / endpoint_not_supported）。
// 优先报告缺失特征，便于一眼区分「特征契约不满足」与「线路不可用」。
func admittedRouteRejectReason(plan modelrouter.RoutePlan, shortfall []string) string {
	var features []string
	seen := map[string]bool{}
	for _, feature := range shortfall {
		if feature != "" && !seen[feature] {
			seen[feature] = true
			features = append(features, feature)
		}
	}
	if plan.Decision == nil || plan.Decision.ModelRouteV2 == nil {
		if len(features) > 0 {
			return featureContractRejectReason(features)
		}
		return "no_route_admitted"
	}
	var others []string
	for _, candidate := range plan.Decision.ModelRouteV2.Candidates {
		reason := candidate.ExclusionReason
		if reason == "" || reason == "selected_primary" {
			continue
		}
		if rest, ok := strings.CutPrefix(reason, "semantic_capability:"); ok {
			for _, feature := range strings.Split(rest, ",") {
				if feature != "" && !seen[feature] {
					seen[feature] = true
					features = append(features, feature)
				}
			}
			continue
		}
		if !seen[reason] {
			seen[reason] = true
			others = append(others, reason)
		}
	}
	if len(features) > 0 {
		return featureContractRejectReason(features)
	}
	if len(others) > 0 {
		return "no_route_admitted:" + strings.Join(others, ",")
	}
	return "no_route_admitted"
}
