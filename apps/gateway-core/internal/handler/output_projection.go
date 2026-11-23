package handler

import (
	"context"
	"encoding/json"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// 2.9.21 r2921f：网关→引擎 context 字段 output_projection（模型输出方向密级标记“只留证”的收窄契约）。
//
// 只由网关原生路径（chat_completions、messages、responses 原生与流式，不含反代）在送检时设置：
//   - model_text：上游模型生成的回答正文和思考/推理文字；
//   - model_tool_arguments：模型生成的工具调用参数，同时带 tool_name 与 tool_may_egress（JSON 布尔）。
//
// 原生元数据帧、Responses 终态快照、反代、proxy-server 以及拿不准是不是模型生成文字的调用点都不设，
// 引擎照 2.9.20 处理。终态快照与普通路径共用 applyOutputSecurityCore，用 withoutOutputProjection
// 让其中的自动标注失效。字段放在 context 里（CheckOutputRequest 顶层字段会被引擎丢掉）。

const (
	outputProjectionModelText          = "model_text"
	outputProjectionModelToolArguments = "model_tool_arguments"
)

type outputProjectionCtxKey struct{}

type outputProjection struct {
	kind          string
	toolName      string
	toolMayEgress bool
	suppressed    bool
}

func currentOutputProjection(ctx context.Context) (outputProjection, bool) {
	if ctx == nil {
		return outputProjection{}, false
	}
	value, ok := ctx.Value(outputProjectionCtxKey{}).(outputProjection)
	return value, ok
}

func outputProjectionSuppressed(ctx context.Context) bool {
	value, ok := currentOutputProjection(ctx)
	return ok && value.suppressed
}

// withOutputProjection 标注这次送检的是上游模型生成的回答正文或思考文字。
func withOutputProjection(ctx context.Context) context.Context {
	if ctx == nil || outputProjectionSuppressed(ctx) {
		return ctx
	}
	return context.WithValue(ctx, outputProjectionCtxKey{}, outputProjection{kind: outputProjectionModelText})
}

// withOutputToolArgumentsProjection 标注这次送检的是模型生成的工具调用参数。
func withOutputToolArgumentsProjection(ctx context.Context, toolName string, toolMayEgress bool) context.Context {
	if ctx == nil || outputProjectionSuppressed(ctx) {
		return ctx
	}
	return context.WithValue(ctx, outputProjectionCtxKey{}, outputProjection{
		kind: outputProjectionModelToolArguments, toolName: toolName, toolMayEgress: toolMayEgress,
	})
}

// withoutOutputProjection 让这条 ctx 上之后的标注全部失效（元数据帧、Responses 终态快照）。
func withoutOutputProjection(ctx context.Context) context.Context {
	if ctx == nil {
		return ctx
	}
	return context.WithValue(ctx, outputProjectionCtxKey{}, outputProjection{suppressed: true})
}

// addOutputProjectionContext 把标注写进送检 context；没有标注或已失效时什么都不写。
func addOutputProjectionContext(ctx context.Context, fields map[string]interface{}) {
	value, ok := currentOutputProjection(ctx)
	if !ok || value.suppressed || fields == nil {
		return
	}
	switch value.kind {
	case outputProjectionModelText:
		fields["output_projection"] = outputProjectionModelText
	case outputProjectionModelToolArguments:
		fields["output_projection"] = outputProjectionModelToolArguments
		fields["tool_name"] = value.toolName
		fields["tool_may_egress"] = value.toolMayEgress
	}
}

// providerExecutedToolCalls 记下送检视图里由模型服务方执行的工具调用的位置（choice 在 Choices 里的序号、
// 工具在 ToolCalls 里的序号）。原生投影和实时流累积器把视图编成 JSON 交给 applyOutputSecurityCore，
// ToolCall.ProviderExecuted 不进 JSON，这个标注只经 ctx 传过去。
type providerExecutedToolCalls map[[2]int]bool

type providerExecutedToolCallsCtxKey struct{}

// providerExecutedToolCallsOf 从内存里的送检视图取出服务方执行的工具位置。
func providerExecutedToolCallsOf(view ChatCompletionResponse) providerExecutedToolCalls {
	var calls providerExecutedToolCalls
	for choiceIndex, choice := range view.Choices {
		for toolIndex, call := range choice.Message.ToolCalls {
			if !call.ProviderExecuted {
				continue
			}
			if calls == nil {
				calls = make(providerExecutedToolCalls)
			}
			calls[[2]int{choiceIndex, toolIndex}] = true
		}
	}
	return calls
}

// withProviderExecutedToolCalls 把服务方执行的工具位置交给这一次 applyOutputSecurity。
func withProviderExecutedToolCalls(ctx context.Context, calls providerExecutedToolCalls) context.Context {
	if ctx == nil || len(calls) == 0 {
		return ctx
	}
	return context.WithValue(ctx, providerExecutedToolCallsCtxKey{}, calls)
}

func providerExecutedToolCallAt(ctx context.Context, choiceIndex, toolIndex int) bool {
	if ctx == nil {
		return false
	}
	calls, _ := ctx.Value(providerExecutedToolCallsCtxKey{}).(providerExecutedToolCalls)
	return calls[[2]int{choiceIndex, toolIndex}]
}

// outputToolCallMayEgress 用送检前的原始参数判断工具调用会不会外发；参数不是 JSON 对象、
// 由模型服务方执行的工具（Responses mcp_call、Messages server_tool_use 等）一律 true。
func outputToolCallMayEgress(call ToolCall) bool {
	if call.ProviderExecuted {
		return true
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil || args == nil {
		return true
	}
	return agentguard.ToolCallMayEgress(call.Function.Name, args)
}
