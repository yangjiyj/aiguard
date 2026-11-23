package handler

import (
	"encoding/base64"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

// Google AI Studio and Vertex AI use the same native GenerateContent body.
// Vertex project/location/model values are carried by the request path.
func decodeGeminiGenerateContentRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	parsed, ok := aimsg.ParseGeminiGenerateContentRequest(body)
	if !ok {
		return ExtractedContent{}, false
	}
	content, matched := extractedFromParsedChat(parsed)
	if matched && content.Model == "" && req != nil && req.URL != nil {
		content.Model = geminiModelFromPath(req.URL.Path)
	}
	return content, matched
}

type geminiGenerateContentResponse struct {
	Candidates   []geminiResponseCandidate `json:"candidates"`
	Model        string                    `json:"model"`
	ModelVersion string                    `json:"modelVersion"`
}

type geminiResponseCandidate struct {
	Content geminiResponseContent `json:"content"`
}

type geminiResponseContent struct {
	Parts []geminiResponsePart `json:"parts"`
}

type geminiResponsePart struct {
	Text                string                  `json:"text"`
	Thought             bool                    `json:"thought"`
	InlineData          *geminiResponseBlob     `json:"inlineData"`
	FileData            *geminiResponseFileData `json:"fileData"`
	FunctionCall        *geminiResponseCall     `json:"functionCall"`
	FunctionResponse    *geminiResponseResult   `json:"functionResponse"`
	ExecutableCode      *geminiResponseCode     `json:"executableCode"`
	CodeExecutionResult *geminiResponseExec     `json:"codeExecutionResult"`
}

type geminiResponseBlob struct {
	MimeType string `json:"mimeType"`
	Data     string `json:"data"`
}

type geminiResponseFileData struct {
	MimeType string `json:"mimeType"`
	FileURI  string `json:"fileUri"`
}

type geminiResponseCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

type geminiResponseResult struct {
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response"`
}

type geminiResponseCode struct {
	Language string `json:"language"`
	Code     string `json:"code"`
}

type geminiResponseExec struct {
	Outcome string `json:"outcome"`
	Output  string `json:"output"`
}

func decodeGeminiGenerateContentResponse(body []byte, contentType string) (ExtractedContent, bool) {
	if isEventStream(contentType, body) {
		return reassembleGeminiGenerateContentStream(parseSSEDataEvents(body))
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	var payload geminiGenerateContentResponse
	if err := json.Unmarshal(body, &payload); err != nil || len(payload.Candidates) == 0 {
		return ExtractedContent{}, false
	}
	return extractGeminiResponsePayload(payload, "json")
}

func reassembleGeminiGenerateContentStream(events []sseEvent) (ExtractedContent, bool) {
	var answer, reasoning, toolInput strings.Builder
	var attachments []ExtractedAttachment
	matched := false
	model := ""
	for _, event := range events {
		if !event.parsed {
			continue
		}
		raw, err := json.Marshal(event.decoded)
		if err != nil {
			continue
		}
		var payload geminiGenerateContentResponse
		if err := json.Unmarshal(raw, &payload); err != nil || len(payload.Candidates) == 0 {
			continue
		}
		matched = true
		if model == "" {
			model = payload.ModelVersion
			if model == "" {
				model = payload.Model
			}
		}
		appendGeminiResponseCandidates(payload.Candidates, &answer, &reasoning, &toolInput, &attachments)
	}
	if !matched {
		return ExtractedContent{}, false
	}
	return buildGeminiResponseExtracted(answer.String(), reasoning.String(), toolInput.String(), attachments, model, "text/event-stream")
}

func extractGeminiResponsePayload(payload geminiGenerateContentResponse, contentType string) (ExtractedContent, bool) {
	var answer, reasoning, toolInput strings.Builder
	var attachments []ExtractedAttachment
	appendGeminiResponseCandidates(payload.Candidates, &answer, &reasoning, &toolInput, &attachments)
	model := payload.ModelVersion
	if model == "" {
		model = payload.Model
	}
	return buildGeminiResponseExtracted(answer.String(), reasoning.String(), toolInput.String(), attachments, model, contentType)
}

func appendGeminiResponseCandidates(candidates []geminiResponseCandidate, answer, reasoning, toolInput *strings.Builder, attachments *[]ExtractedAttachment) {
	for _, candidate := range candidates {
		for _, part := range candidate.Content.Parts {
			if text := strings.TrimSpace(part.Text); text != "" {
				if part.Thought {
					reasoning.WriteString(text)
				} else {
					answer.WriteString(text)
				}
			}
			if part.FunctionCall != nil {
				name := strings.TrimSpace(part.FunctionCall.Name)
				prefix := "[tool_use]"
				if name != "" {
					prefix = "[tool_use:" + name + "]"
				}
				args := compactGeminiJSON(part.FunctionCall.Args)
				toolInput.WriteString(prefix)
				if args != "" {
					toolInput.WriteString(" ")
					toolInput.WriteString(args)
				}
			}
			if part.FunctionResponse != nil {
				name := strings.TrimSpace(part.FunctionResponse.Name)
				prefix := "[tool_result]"
				if name != "" {
					prefix = "[tool_result:" + name + "]"
				}
				result := compactGeminiJSON(part.FunctionResponse.Response)
				if result != "" {
					toolInput.WriteString(prefix + " " + result)
				}
			}
			if part.ExecutableCode != nil && strings.TrimSpace(part.ExecutableCode.Code) != "" {
				toolInput.WriteString("[executable_code:" + strings.TrimSpace(part.ExecutableCode.Language) + "] " + strings.TrimSpace(part.ExecutableCode.Code))
			}
			if part.CodeExecutionResult != nil {
				output := strings.TrimSpace(part.CodeExecutionResult.Output)
				if output == "" {
					output = strings.TrimSpace(part.CodeExecutionResult.Outcome)
				}
				if output != "" {
					toolInput.WriteString("[code_execution_result] " + output)
				}
			}
			if part.FileData != nil {
				mimeType := strings.TrimSpace(part.FileData.MimeType)
				if mimeType == "" {
					mimeType = "application/octet-stream"
				}
				toolInput.WriteString("[file_data mime=" + mimeType + "]")
			}
			if part.InlineData != nil && strings.TrimSpace(part.InlineData.Data) != "" {
				data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(part.InlineData.Data))
				if err == nil {
					mimeType := strings.TrimSpace(part.InlineData.MimeType)
					if mimeType == "" {
						mimeType = "application/octet-stream"
					}
					*attachments = append(*attachments, attachmentFromBytes("gemini_inline_data", "candidates.content.parts.inlineData", "", mimeType, data))
				}
			}
		}
	}
}

func buildGeminiResponseExtracted(answer, reasoning, toolInput string, attachments []ExtractedAttachment, model, contentType string) (ExtractedContent, bool) {
	var parts []string
	if text := strings.TrimSpace(reasoning); text != "" {
		for _, line := range strings.Split(text, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				parts = append(parts, "[reasoning] "+line)
			}
		}
	}
	if text := strings.TrimSpace(answer); text != "" {
		parts = append(parts, text)
	}
	if text := strings.TrimSpace(toolInput); text != "" {
		parts = append(parts, "[tool] "+text)
	}
	if len(parts) == 0 && len(attachments) == 0 {
		return ExtractedContent{}, false
	}
	content := buildExtracted(parts, attachments, contentType)
	content.Model = model
	content.VisibleText = strings.TrimSpace(answer)
	content.VisibleTextKnown = true
	return content, true
}

func compactGeminiJSON(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return strings.TrimSpace(string(raw))
	}
	compact, err := json.Marshal(value)
	if err != nil {
		return strings.TrimSpace(string(raw))
	}
	return string(compact)
}

func geminiModelFromPath(path string) string {
	lower := strings.ToLower(path)
	const marker = "/models/"
	index := strings.LastIndex(lower, marker)
	if index < 0 {
		return ""
	}
	model := path[index+len(marker):]
	if end := strings.IndexAny(model, ":/"); end >= 0 {
		model = model[:end]
	}
	model, err := url.PathUnescape(model)
	if err != nil {
		return strings.TrimSpace(model)
	}
	return strings.TrimSpace(model)
}
