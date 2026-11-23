package handler

import (
	"mime"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

// decodeOpenAICompatibleRequest 是真正的通用 OpenAI 兼容请求解码器（标准 /v1/chat/completions 形态）。
// 解除 web_decoder.go 旧条目对 decodeWorkBuddyInvokeRequest 的错绑：那个函数 host 写死
// ride-3-live-webapp.azurewebsites.net，对 api.openai.com 及所有 OpenAI 兼容厂商（together/
// fireworks/xai/openrouter/moonshot/perplexity/cerebras/bytedance 等 catalog 条目同用本解码器名）
// 永不命中 → 一直静默回退通用抽取器把 system+tools+全量历史平铺（投诉①病根之一）。
// 不做 host 判定：何时启用由 aiadapters catalog 的 request_decoder 字段路由决定；
// 形态不符（无 messages 数组）返回 false，embeddings/files 等端点照走原回退路径。
func decodeOpenAICompatibleRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	parsed, ok := aimsg.ParseOpenAIChatRequest(body)
	if !ok && req != nil && req.URL != nil && strings.Contains(strings.ToLower(req.URL.Path), "/responses") {
		return decodeOpenAIResponsesRequest(body)
	}
	if !ok {
		return ExtractedContent{}, false
	}
	return extractedFromParsedChat(parsed)
}
