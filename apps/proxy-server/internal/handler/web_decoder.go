package handler

import "net/http"

type WebDecoder interface {
	Name() string
	DecodeRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool)
	DecodeResponse(body []byte, contentType string) (ExtractedContent, bool)
}

type webDecoder struct {
	name           string
	decodeRequest  func(req *http.Request, body []byte, contentType string) (ExtractedContent, bool)
	decodeResponse func(body []byte, contentType string) (ExtractedContent, bool)
}

func (d webDecoder) Name() string { return d.name }

func (d webDecoder) DecodeRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	if d.decodeRequest == nil {
		return ExtractedContent{}, false
	}
	return d.decodeRequest(req, body, contentType)
}

func (d webDecoder) DecodeResponse(body []byte, contentType string) (ExtractedContent, bool) {
	if d.decodeResponse == nil {
		return ExtractedContent{}, false
	}
	return d.decodeResponse(body, contentType)
}

var webDecoders = map[string]WebDecoder{
	"chatgpt_web":             webDecoder{name: "chatgpt_web", decodeRequest: decodeChatGPTWebRequest, decodeResponse: decodeChatGPTWebResponse},
	"deepseek_web":            webDecoder{name: "deepseek_web", decodeRequest: decodeDeepSeekWebRequest, decodeResponse: decodeDeepSeekWebResponse},
	"claude_web":              webDecoder{name: "claude_web", decodeRequest: decodeClaudeWebRequest, decodeResponse: decodeClaudeWebResponse},
	"gemini_web":              webDecoder{name: "gemini_web", decodeRequest: decodeGeminiWebRequest, decodeResponse: decodeGeminiWebResponse},
	"kimi_web":                webDecoder{name: "kimi_web", decodeRequest: decodeKimiWebRequest, decodeResponse: decodeKimiWebResponse},
	"qwen_web":                webDecoder{name: "qwen_web", decodeResponse: decodeQwenWebResponse},
	"doubao_web":              webDecoder{name: "doubao_web", decodeRequest: decodeDoubaoWebRequest, decodeResponse: decodeDoubaoWebResponse},
	"codebuddy_web":           webDecoder{name: "codebuddy_web", decodeRequest: decodeCodeBuddyWebRequest, decodeResponse: decodeCodeBuddyWebResponse},
	"copilot":                 webDecoder{name: "copilot", decodeRequest: decodeVSCodeXWebRequest, decodeResponse: decodeChatGPTWebResponse},
	"github_copilot_upload":   webDecoder{name: "github_copilot_upload", decodeRequest: decodeGitHubCopilotAttachmentUpload, decodeResponse: decodeGitHubCopilotAttachmentUploadResponse},
	"workbuddy_web":           webDecoder{name: "workbuddy_web", decodeRequest: decodeWorkBuddyInvokeRequest},
	"workbuddy_invoke":        webDecoder{name: "workbuddy_invoke", decodeRequest: decodeWorkBuddyInvokeAttachmentsRequest, decodeResponse: decodeWorkBuddyInvokeAttachmentsResponse},
	"openai_compatible":       webDecoder{name: "openai_compatible", decodeRequest: decodeOpenAICompatibleRequest, decodeResponse: decodeChatGPTWebResponse},
	"anthropic_messages":      webDecoder{name: "anthropic_messages", decodeRequest: decodeAnthropicMessagesRequest, decodeResponse: decodeAnthropicMessagesResponse},
	"gemini_generate_content": webDecoder{name: "gemini_generate_content", decodeRequest: decodeGeminiGenerateContentRequest, decodeResponse: decodeGeminiGenerateContentResponse},
	"yuanbao_web":             webDecoder{name: "yuanbao_web", decodeRequest: decodeYuanbaoWebRequest, decodeResponse: decodeYuanbaoWebResponse},
}

var requestSniffWebDecoderNames = []string{"workbuddy_web", "chatgpt_web", "gemini_web"}
var responseSniffWebDecoderNames = []string{"deepseek_web", "chatgpt_web", "claude_web", "gemini_web", "anthropic_messages", "gemini_generate_content"}

func getWebDecoder(name string) (WebDecoder, bool) {
	if name == "" {
		return nil, false
	}
	decoder, ok := webDecoders[name]
	return decoder, ok
}

func decodeRequestWithSniffedWebDecoder(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	for _, name := range requestSniffWebDecoderNames {
		decoder, ok := getWebDecoder(name)
		if !ok {
			continue
		}
		if content, matched := decoder.DecodeRequest(req, body, contentType); matched {
			return content, true
		}
	}
	return ExtractedContent{}, false
}

func decodeResponseWithSniffedWebDecoder(body []byte, contentType string) (ExtractedContent, bool) {
	for _, name := range responseSniffWebDecoderNames {
		decoder, ok := getWebDecoder(name)
		if !ok {
			continue
		}
		if content, matched := decoder.DecodeResponse(body, contentType); matched {
			return content, true
		}
	}
	return ExtractedContent{}, false
}
