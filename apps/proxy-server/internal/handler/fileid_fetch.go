package handler

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"strings"
)

// openAICompatFileIDProviders 是已知提供 OpenAI 风格 `/v1/files/{id}/content` 文件下载接口的厂商。
// 模型用 file-id 返回生成文件/用户用 id 引用上传文件时,凭请求自带 API key 旁路把字节抓回留证。
var openAICompatFileIDProviders = map[string]bool{
	"openai":   true,
	"moonshot": true,
	"deepseek": true,
}

// hydrateFileIDAttachments 对 file-id / 签名短链引用式附件旁路抓真字节,抓到且能解码为图就当内联字节
// (DataBase64)走现有留证管道压缩落盘。两条路径:
//   - 相对签名下载短链(豆包/DeepSeek 网页版 biz_data.files signed_path,/file?file_id=&state=<签名>):
//     拼 https://{host}{path},复放 web 会话头(Cookie/UA/Referer)抓;无论成败都清掉 DownloadURL,
//     签名 token 不落库。
//   - file-id 引用(OpenAI 兼容厂商):用请求自带 Authorization 调 {host}/v1/files/{id}/content。
//
// 仅正向流量有效(此刻请求里的凭证/签名有效;历史无凭证不可恢复)。任何失败静默跳过=维持原样,无害。
// 必须在响应已回写客户端之后调用,不给用户响应加延迟。env RETENTION_FETCH_FILEID_BYTES=false 可关。
func hydrateFileIDAttachments(ctx context.Context, req *http.Request, targetHost, provider string, contents ...*ExtractedContent) {
	// GitHub Copilot 图片留证内联:上传字节(请求)与 /responses 对话引用靠裸 attachment id 关联。
	// 上传响应解码器把裸 id 以标记附件携带在 respContent 里,这里回贴到请求字节附件的 ReferenceID 并
	// 剥离标记。这是纯进程内 metadata 关联(不抓网络),与下方 file-id 旁路抓字节无关,故置于
	// RETENTION_FETCH_FILEID_BYTES 开关之前——即便该开关关闭,关联与标记剥离也必须执行,否则标记会
	// 泄漏进留证。仅对 uploads.github.com 生效(函数内 host 守门)。
	linkGitHubCopilotUploadReference(targetHost, contents...)

	if strings.EqualFold(strings.TrimSpace(os.Getenv("RETENTION_FETCH_FILEID_BYTES")), "false") {
		return
	}
	if req == nil || strings.TrimSpace(targetHost) == "" {
		return
	}
	auth := strings.TrimSpace(req.Header.Get("Authorization"))
	cookie := strings.TrimSpace(req.Header.Get("Cookie"))
	ua := strings.TrimSpace(req.Header.Get("User-Agent"))
	isOpenAICompat := openAICompatFileIDProviders[strings.ToLower(strings.TrimSpace(provider))]

	for _, c := range contents {
		if c == nil {
			continue
		}
		for i := range c.Attachments {
			a := &c.Attachments[i]
			if a.Source != "json_file_object" && a.Source != "json_file_reference" {
				continue
			}
			if strings.TrimSpace(a.DataBase64) != "" {
				continue
			}
			dl := strings.TrimSpace(a.DownloadURL)
			switch {
			case strings.HasPrefix(dl, "/") && !strings.HasPrefix(dl, "//"):
				// 相对签名下载短链:拼绝对 URL,复放 web 会话头。
				headers := map[string]string{"Referer": "https://" + targetHost + "/"}
				if cookie != "" {
					headers["Cookie"] = cookie
				}
				if ua != "" {
					headers["User-Agent"] = ua
				}
				if b := fetchHydratedBytes(ctx, "https://"+targetHost+dl, headers); len(b) > 0 && bytesAreDecodableImage(b) {
					a.DataBase64 = base64.StdEncoding.EncodeToString(b)
					a.Size = int64(len(b))
				}
				a.DownloadURL = "" // 不持久化签名短链 token(无论成败)
			case dl == "" && strings.TrimSpace(a.ReferenceID) != "" && isOpenAICompat:
				// file-id 引用(OpenAI 兼容):凭 Authorization 调 /v1/files/{id}/content。
				if auth == "" {
					continue
				}
				url := "https://" + targetHost + "/v1/files/" + strings.TrimSpace(a.ReferenceID) + "/content"
				if b := fetchHydratedBytes(ctx, url, map[string]string{"Authorization": auth}); len(b) > 0 && bytesAreDecodableImage(b) {
					a.DataBase64 = base64.StdEncoding.EncodeToString(b)
					a.Size = int64(len(b))
				}
			}
		}
	}
}

// fetchHydratedBytes 带指定头调下载 URL;走 egress 守卫(防 SSRF)+ 超时 + 大小上限,复用
// retainedAttachmentFetchClient。任何非 200/失败/超限返回 nil。
func fetchHydratedBytes(ctx context.Context, url string, headers map[string]string) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := retainedAttachmentFetchClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxFetchedAttachmentBytes)+1))
	if err != nil || len(body) == 0 || len(body) > maxFetchedAttachmentBytes {
		return nil
	}
	return body
}
