package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// 现场 P3-9：客户端把 Base URL 多写了一层 /v1（例如 Claude Code 的 ANTHROPIC_BASE_URL
// 写成 https://主机:8080/v1，客户端再自己拼 /v1/messages），网关日志里出现
// POST /v1/v1/messages。该路径不存在任何处理器，但鉴权中间件挂在 /v1 子路由上、
// 先于路由匹配执行，于是用户只看到一个与路径无关的 401。
//
// 这里在凭据校验之前识别重复前缀，直接返回带明确改法的 404：
//   - 不转发、不查库、不回显请求中的任何内容（路径、查询串、凭据都不进响应）；
//   - 不做自动纠正转发，避免掩盖配置错误（网关入站没有任何既有的 /v1 兼容约定；
//     已有的 /v1 兼容只发生在出站拼接上游地址时）；
//   - 排在“请求头冲突”关键审计之后，该审计仍对这些路径照常生效。

const duplicateV1PrefixCode = "base_url_duplicate_v1_prefix"

// 提示文案固定且不含任何请求数据；不使用尖括号，避免 JSON 编码转义后影响阅读。
const (
	duplicateV1PrefixAnthropicMessage = "地址多了一层 /v1，请把 Base URL 改成不带 /v1 的网关地址：Anthropic 协议客户端（如 Claude Code）会自己拼接 /v1/messages，ANTHROPIC_BASE_URL 应写成 http(s)://网关地址:端口（末尾不要加 /v1）。"
	duplicateV1PrefixOpenAIMessage    = "地址多了一层 /v1，请把 Base URL 改成只带一层 /v1 的网关地址：OpenAI 协议客户端的 base_url 应写成 http(s)://网关地址:端口/v1，不要写成 /v1/v1。"
	duplicateV1PrefixGeminiMessage    = "地址多了一层 /v1，请把 Base URL 改成不带 /v1 的网关地址：Gemini 原生客户端会自己拼接 /v1beta/models/...，Base URL 应写成 http(s)://网关地址:端口（末尾不要加 /v1）。"
	duplicateV1PrefixGenericMessage   = "地址多了一层 /v1，请把 Base URL 改成正确的网关地址：Anthropic 协议客户端（如 Claude Code）不带 /v1，OpenAI 协议客户端只带一层 /v1。"
)

// classifyDuplicateV1Prefix 判断路径是否形如 /v1/v1/... 或 /v1/v1beta/...，并按第二层之后的
// 第一段推断客户端所用协议，用来选择错误体格式与改法。仅做大小写敏感的精确段匹配：
// /v1/V1/...、/v1/v10/...、/v1/models/v1 等都不是重复前缀。
func classifyDuplicateV1Prefix(path string) (protocol string, duplicated bool) {
	rest, ok := strings.CutPrefix(path, "/v1/")
	if !ok {
		return "", false
	}
	segment, tail, _ := strings.Cut(rest, "/")
	switch segment {
	case "v1beta":
		return "gemini", true
	case "v1":
		// 继续按后缀判断协议。
	default:
		return "", false
	}
	first, _, _ := strings.Cut(tail, "/")
	switch first {
	case "messages":
		return "anthropic", true
	case "chat", "responses", "embeddings", "images", "files", "models":
		return "openai", true
	default:
		return "generic", true
	}
}

func writeDuplicateV1PrefixHint(w http.ResponseWriter, protocol, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Request-Id", requestID)
	w.WriteHeader(http.StatusNotFound)

	switch protocol {
	case "anthropic":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "error",
			"error": map[string]string{
				"type":    "not_found_error",
				"code":    duplicateV1PrefixCode,
				"message": duplicateV1PrefixAnthropicMessage,
			},
			"request_id": requestID,
		})
	case "gemini":
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
			"code":    http.StatusNotFound,
			"status":  "NOT_FOUND",
			"message": duplicateV1PrefixGeminiMessage,
		}})
	default:
		message := duplicateV1PrefixGenericMessage
		if protocol == "openai" {
			message = duplicateV1PrefixOpenAIMessage
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{
			"type":       "invalid_request_error",
			"code":       duplicateV1PrefixCode,
			"message":    message,
			"request_id": requestID,
		}})
	}
}
