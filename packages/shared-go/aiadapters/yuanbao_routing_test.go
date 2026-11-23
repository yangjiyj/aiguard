package aiadapters

import "testing"

// TestYuanbaoRoutingTiers 元宝路由分级：真对话（detail/chat）走 content 级 + yuanbao_web 解码器；
// 轮询/元数据接口（list/promptSug/create/updateModel）走 summary 级（不留内容，去重降噪）。
func TestYuanbaoRoutingTiers(t *testing.T) {
	const host = "yuanbao.tencent.com"
	content := []string{
		"/api/chat/0OXoMc79xg0",
		"/api/user/agent/conversation/v1/detail",
	}
	summary := []string{
		"/api/user/agent/conversation/list",
		"/api/user/agent/conversation/promptSug",
		"/api/user/agent/conversation/create",
		"/api/user/agent/conversation/updateModel",
	}
	for _, p := range content {
		got, ok := MatchCatalog(host, p)
		if !ok || got.RetainLevel != "content" {
			t.Fatalf("%s 应 content 级，实得 ok=%v retain=%q", p, ok, got.RetainLevel)
		}
		if got.RequestDecoder != "yuanbao_web" || got.ResponseDecoder != "yuanbao_web" {
			t.Fatalf("%s 应走 yuanbao_web 解码器，实得 req=%q resp=%q", p, got.RequestDecoder, got.ResponseDecoder)
		}
	}
	for _, p := range summary {
		got, ok := MatchCatalog(host, p)
		if !ok || got.RetainLevel != "summary" {
			t.Fatalf("%s 应 summary 级（轮询降噪），实得 ok=%v retain=%q", p, ok, got.RetainLevel)
		}
	}
}
