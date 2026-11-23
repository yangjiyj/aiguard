package handler

import "strings"

// isModelReplyContentType 判定一个正向代理响应体是否属于「模型回复正文」——
// 即应进入输出 DLP 检测的会话内容(JSON / SSE / NDJSON / 纯文本)。
// 大模型网页版的「App 交付」字节不属于会话内容：导航 HTML 外壳、压缩 JS/CSS、
// 图片/字体/音视频/wasm/二进制——它们是厂商公开的前端代码，对其做密钥/敏感词检测
// 语义上就是错的，且 secret_openai_key(sk-...) 这类规则会在压缩 JS 词碎片(block/in/
// text/css → sk*****ck 等)上必然误报，把页面外壳/主包 403 拦死，致网页版打不开、
// 输入框不出现。这些一律跳过输出检测、原样回写客户端。
// 采取「列已知非会话类型→跳过，其余默认检测」的保守策略：未知/缺失 content-type
// 仍按需检测，绝不因分类遗漏而漏检真实会话回复。
func isModelReplyContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch {
	case ct == "":
		return true // 缺失则保守检测
	case ct == "text/html", ct == "application/xhtml+xml":
		return false // 导航/页面外壳
	case ct == "text/css":
		return false
	case ct == "application/javascript", ct == "text/javascript",
		ct == "application/x-javascript", ct == "application/ecmascript",
		ct == "text/ecmascript":
		return false // 前端脚本包
	case ct == "application/wasm":
		return false
	case strings.HasPrefix(ct, "image/"),
		strings.HasPrefix(ct, "font/"),
		strings.HasPrefix(ct, "audio/"),
		strings.HasPrefix(ct, "video/"):
		return false
	case ct == "application/font-woff", ct == "application/font-woff2",
		ct == "application/vnd.ms-fontobject", ct == "application/x-font-ttf":
		return false
	case ct == "application/octet-stream", ct == "application/zip",
		ct == "application/gzip", ct == "application/x-protobuf",
		ct == "application/protobuf":
		return false // 二进制/打包/protobuf
	default:
		// application/json、application/*+json、text/event-stream、text/plain、
		// application/x-ndjson、以及未知类型 → 检测。
		return true
	}
}
