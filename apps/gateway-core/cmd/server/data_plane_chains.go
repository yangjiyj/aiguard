package main

import "net/http"

// dataPlaneChains 把数据面中间件链按用途拆开。
//
// model：模型类数据面（Chat/Responses/Embeddings/Images/Gemini 等）——认证 → 个人模型使用权限 → 集成策略。
// mcp：MCP 工具调用数据面——认证 → 集成策略，不经个人模型使用权限。
//
// 个人模型使用权限回答「这个账号能调用哪些模型」，MCP tools/call 不涉及模型选择，
// 管控靠 MCP 自己的六元组策略、红线与准入。部门分配模式为 emergency/service 的账号 ChatAllowed=false，
// 此前会在到达 MCP 策略之前被 forbidden_model 拒绝（MCP 路由当初为接入集成策略共用了 dataPlaneAuth，
// 之后个人模型门被加进同一条链，造成连带）。认证与集成策略仍然对 MCP 生效，原有拦截逻辑不变。
type dataPlaneChains struct {
	model func(http.Handler) http.Handler
	mcp   func(http.Handler) http.Handler
}

func newDataPlaneChains(authentication, userModel, integration func(http.Handler) http.Handler) dataPlaneChains {
	return dataPlaneChains{
		model: func(next http.Handler) http.Handler {
			return authentication(userModel(integration(next)))
		},
		mcp: func(next http.Handler) http.Handler {
			return authentication(integration(next))
		},
	}
}
