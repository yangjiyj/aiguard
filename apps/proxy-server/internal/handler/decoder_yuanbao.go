package handler

import (
	"encoding/json"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

// 腾讯元宝（yuanbao.tencent.com）网页版解码器。
//
// 元宝一次用户发消息会打一串 API：/api/user/agent/conversation/{create,list,promptSug,
// updateModel,v1/detail} + /api/chat/{id}。真正承载完整对话的是 v1/detail 响应，其结构为：
//
//	{"id": "<conversationId>", "convs": [
//	   {"speaker": "human"|"ai", "createTime": <unix>, "speechIndex": N,
//	    "speechesV2": [{"speechType": "text", "content": [{"type": "text", "msg": "..."}]}]}
//	]}
//
// 本解码器把 v1/detail 响应解成结构化对话（human→user / ai→assistant），剥掉元宝的
// markdown 零宽标注噪音（如 [](@mark_underline=1)），多媒体转附件。其余轮询/元数据接口
// （promptSug/list/create/updateModel）无真会话内容，由 decodeYuanbaoWebRequest 返回空匹配
// 抑制，避免每条都成一条留证记录。

// yuanbaoMarkNoiseRe 匹配元宝正文里的零宽 markdown 标注：[](@mark_underline=1) / [](@ref=2) 等。
var yuanbaoMarkNoiseRe = regexp.MustCompile(`\[\]\(@[A-Za-z_]+=\d+\)`)

type yuanbaoDetailResponse struct {
	ID    string        `json:"id"`
	Convs []yuanbaoConv `json:"convs"`
}

type yuanbaoConv struct {
	Speaker     string          `json:"speaker"`
	CreateTime  int64           `json:"createTime"`
	SpeechIndex int             `json:"speechIndex"`
	SpeechesV2  []yuanbaoSpeech `json:"speechesV2"`
}

type yuanbaoSpeech struct {
	SpeechType string               `json:"speechType"`
	Content    []yuanbaoContentItem `json:"content"`
}

type yuanbaoContentItem struct {
	Type     string `json:"type"`
	Msg      string `json:"msg"`
	ImageURL string `json:"imageUrl"`
	URL      string `json:"url"`
	ImageOri string `json:"imageOri"`
}

// decodeYuanbaoWebResponse 解析元宝 conversation/v1/detail 响应为结构化对话。
func decodeYuanbaoWebResponse(body []byte, contentType string) (ExtractedContent, bool) {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	var detail yuanbaoDetailResponse
	if err := json.Unmarshal(body, &detail); err != nil {
		return ExtractedContent{}, false
	}
	if len(detail.Convs) == 0 {
		return ExtractedContent{}, false
	}

	// 按真实时间线排序（createTime 升序，同刻按 speechIndex），detail 返回顺序不保证时序。
	convs := append([]yuanbaoConv(nil), detail.Convs...)
	sort.SliceStable(convs, func(i, j int) bool {
		if convs[i].CreateTime != convs[j].CreateTime {
			return convs[i].CreateTime < convs[j].CreateTime
		}
		return convs[i].SpeechIndex < convs[j].SpeechIndex
	})

	var messages []ConvMessage
	var attachments []ExtractedAttachment
	for _, c := range convs {
		role, source := "user", aimsg.SourceUser
		if strings.EqualFold(c.Speaker, "ai") {
			role, source = "assistant", aimsg.SourceAssistantHistory
		}
		var textParts []string
		for _, sp := range c.SpeechesV2 {
			for _, item := range sp.Content {
				if strings.EqualFold(item.Type, "text") {
					if t := cleanYuanbaoText(item.Msg); t != "" {
						textParts = append(textParts, t)
					}
					continue
				}
				// 非文本内容项按多媒体处理：取首个可用的图片/资源 URL 作引用附件。
				if u := firstNonEmpty(item.ImageOri, item.ImageURL, item.URL); u != "" {
					attachments = append(attachments, ExtractedAttachment{
						Source:      "yuanbao_" + role,
						FieldName:   "convs.content." + item.Type,
						ContentType: "image",
						DownloadURL: u,
					})
				}
			}
		}
		text := strings.TrimSpace(strings.Join(textParts, "\n"))
		if text == "" {
			continue
		}
		messages = append(messages, ConvMessage{
			Role:          role,
			Source:        source,
			Content:       text,
			ContentSHA256: aimsg.ContentSHA256Hex(text),
		})
	}

	if len(messages) == 0 && len(attachments) == 0 {
		return ExtractedContent{}, false
	}
	return ExtractedContent{
		Text:              aimsg.FlattenMessages(messages),
		SecurityText:      securityTextFromMessages(messages),
		SecurityTextKnown: true,
		ContentType:       "json",
		Messages:          messages,
		Attachments:       attachments,
		ConversationID:    strings.TrimSpace(detail.ID),
		Model:             "hunyuan",
	}, true
}

// decodeYuanbaoWebRequest 处理元宝请求侧：
//   - /api/chat 的用户消息（prompt 字段）抽成用户提问；
//   - conversation 元数据/轮询接口（detail/list/promptSug/create/updateModel）无真会话内容，
//     返回空匹配（matched=true, 内容空）抑制其被通用抽取器拉成噪音留证。
func decodeYuanbaoWebRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	path := ""
	if req != nil && req.URL != nil {
		path = strings.ToLower(req.URL.Path)
	}
	// 真会话入口 /api/chat：请求体带用户 prompt。
	if strings.Contains(path, "/api/chat") {
		var payload struct {
			Prompt  string `json:"prompt"`
			Content string `json:"content"`
			Msg     string `json:"msg"`
			Query   string `json:"query"`
		}
		if err := json.Unmarshal(body, &payload); err == nil {
			if t := cleanYuanbaoText(firstNonEmpty(payload.Prompt, payload.Content, payload.Msg, payload.Query)); t != "" {
				msg := ConvMessage{Role: "user", Source: aimsg.SourceUser, Content: t, ContentSHA256: aimsg.ContentSHA256Hex(t)}
				return ExtractedContent{Text: t, SecurityText: t, SecurityTextKnown: true, ContentType: "json", Messages: []ConvMessage{msg}}, true
			}
		}
	}
	// 元数据/轮询接口：识别为元宝会话管理噪音，返回空匹配抑制。
	if isYuanbaoMetadataPath(path) {
		return ExtractedContent{ContentType: "json", NonDialogue: true}, true
	}
	return ExtractedContent{}, false
}

func isYuanbaoMetadataPath(path string) bool {
	for _, frag := range []string{
		"/conversation/list", "/conversation/promptsug", "/conversation/create",
		"/conversation/updatemodel", "/conversation/v1/detail", "/conversation/info",
	} {
		if strings.Contains(path, frag) {
			return true
		}
	}
	return false
}

// cleanYuanbaoText 去掉元宝正文里的零宽 markdown 标注噪音并 trim。
func cleanYuanbaoText(s string) string {
	return strings.TrimSpace(yuanbaoMarkNoiseRe.ReplaceAllString(s, ""))
}
