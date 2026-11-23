package aimsg

import (
	"encoding/json"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

// Native Gemini GenerateContent is shared by Google AI Studio and Vertex AI.
// Vertex-specific project/location/model values live in the URL.
type geminiGenerateContentRequest struct {
	Model             string          `json:"model"`
	SystemInstruction geminiContent   `json:"systemInstruction"`
	Contents          []geminiContent `json:"contents"`
	Tools             []geminiTool    `json:"tools"`
}

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text                string                     `json:"text"`
	Thought             bool                       `json:"thought"`
	InlineData          *geminiBlob                `json:"inlineData"`
	FileData            *geminiFileData            `json:"fileData"`
	FunctionCall        *geminiFunctionCall        `json:"functionCall"`
	FunctionResponse    *geminiFunctionResponse    `json:"functionResponse"`
	ExecutableCode      *geminiExecutableCode      `json:"executableCode"`
	CodeExecutionResult *geminiCodeExecutionResult `json:"codeExecutionResult"`
}

type geminiBlob struct {
	MimeType string `json:"mimeType"`
	Data     string `json:"data"`
}

type geminiFileData struct {
	MimeType string `json:"mimeType"`
	FileURI  string `json:"fileUri"`
}

type geminiFunctionCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

type geminiFunctionResponse struct {
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response"`
}

type geminiExecutableCode struct {
	Language string `json:"language"`
	Code     string `json:"code"`
}

type geminiCodeExecutionResult struct {
	Outcome string `json:"outcome"`
	Output  string `json:"output"`
}

type geminiTool struct {
	FunctionDeclarations []geminiFunctionDeclaration `json:"functionDeclarations"`
}

type geminiFunctionDeclaration struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// ParseGeminiGenerateContentRequest parses native Gemini/Vertex requests into
// the shared structured-message representation used by detection and audit.
func ParseGeminiGenerateContentRequest(body []byte) (ParsedChat, bool) {
	var req geminiGenerateContentRequest
	if err := json.Unmarshal(body, &req); err != nil || len(req.Contents) == 0 {
		return ParsedChat{}, false
	}

	out := ParsedChat{Model: strings.TrimSpace(req.Model)}
	if systemText := geminiContentText(req.SystemInstruction.Parts); systemText != "" {
		out.SystemText = systemText
		out.Messages = append(out.Messages, newConvMessage("system", SourceSystemPrompt, systemText))
	}

	for _, tool := range req.Tools {
		for _, declaration := range tool.FunctionDeclarations {
			name := strings.TrimSpace(declaration.Name)
			if name == "" {
				continue
			}
			content := "[tool_def:" + name + "]"
			if description := strings.TrimSpace(declaration.Description); description != "" {
				content += " " + description
			}
			if len(declaration.Parameters) > 0 && string(declaration.Parameters) != "null" {
				content += "\n" + compactJSON(declaration.Parameters)
			}
			out.Messages = append(out.Messages, newConvMessage("tool", SourceToolDef, content))
		}
	}

	for messageIndex, content := range req.Contents {
		start := len(out.Messages)
		role := strings.ToLower(strings.TrimSpace(content.Role))
		if role == "" {
			role = "user"
		}
		source := SourceUnknown
		switch role {
		case "user":
			source = SourceUser
		case "model", "assistant":
			source = SourceAssistantHistory
		}

		var textParts []string
		var toolResults []string
		var ownParts, resultParts []geminiPart
		hasMedia := false
		for _, part := range content.Parts {
			if part.FunctionResponse != nil {
				resultParts = append(resultParts, part)
				name := strings.TrimSpace(part.FunctionResponse.Name)
				prefix := "[tool_result]"
				if name != "" {
					prefix = "[tool_result:" + name + "]"
				}
				result := compactJSON(part.FunctionResponse.Response)
				if result == "" {
					result = strings.TrimSpace(string(part.FunctionResponse.Response))
				}
				if result != "" {
					toolResults = append(toolResults, prefix+" "+result)
				}
				continue
			}
			ownParts = append(ownParts, part)
			if part.InlineData != nil || part.FileData != nil {
				hasMedia = true
			}
			if part.InlineData != nil {
				if data := strings.TrimSpace(part.InlineData.Data); data != "" {
					mimeType := strings.TrimSpace(part.InlineData.MimeType)
					// §3.8：inlineData 按 MIME 分流——image/* 进 Images；
					// functionResponse 旁的 pdf 等文档 inlineData 抽成附件（文件 DLP/留证可见）。
					if strings.HasPrefix(strings.ToLower(mimeType), "image/") {
						out.Images = append(out.Images, InlineImage{
							MediaType:  mimeType,
							DataBase64: data,
						})
					} else {
						name := geminiInlineDataName(mimeType)
						if candidate, ok := artifactCandidateFromBase64(data, retentionartifact.DirectionInput, retentionartifact.KindFile, name, mimeType); ok {
							candidate.Ordinal = len(out.Artifacts)
							out.Artifacts = append(out.Artifacts, candidate)
						}
					}
				}
				continue
			}
			if text := geminiPartText(part); text != "" {
				textParts = append(textParts, text)
			}
		}
		if len(textParts) > 0 || hasMedia {
			out.Messages = append(out.Messages, newConvMessage(role, source, strings.Join(textParts, "\n")))
			out.Messages[len(out.Messages)-1].HasAttachments = hasMedia
		}
		if len(toolResults) > 0 {
			out.Messages = append(out.Messages, newConvMessage("tool", SourceToolResult, strings.Join(toolResults, "\n")))
		}
		anchorMessages(out.Messages[start:], messageIndex, "contents")
		for i := start; i < len(out.Messages); i++ {
			parts := ownParts
			if out.Messages[i].Source == SourceToolResult {
				parts = resultParts
			}
			out.Messages[i].RawContent, _ = json.Marshal(parts)
		}
	}

	if len(out.Messages) == 0 && len(out.Images) == 0 {
		return ParsedChat{}, false
	}
	finalizeParsedChat(&out)
	return out, true
}

func geminiContentText(parts []geminiPart) string {
	var textParts []string
	for _, part := range parts {
		if text := strings.TrimSpace(part.Text); text != "" {
			if part.Thought {
				textParts = append(textParts, "[reasoning] "+text)
			} else {
				textParts = append(textParts, text)
			}
		}
	}
	return strings.Join(textParts, "\n")
}

func geminiPartText(part geminiPart) string {
	if text := strings.TrimSpace(part.Text); text != "" {
		if part.Thought {
			return "[reasoning] " + text
		}
		return text
	}
	if part.FunctionCall != nil {
		name := strings.TrimSpace(part.FunctionCall.Name)
		prefix := "[tool_use]"
		if name != "" {
			prefix = "[tool_use:" + name + "]"
		}
		args := compactJSON(part.FunctionCall.Args)
		if args == "" {
			return prefix
		}
		return prefix + " " + args
	}
	if part.ExecutableCode != nil {
		code := strings.TrimSpace(part.ExecutableCode.Code)
		if code == "" {
			return ""
		}
		language := strings.TrimSpace(part.ExecutableCode.Language)
		if language == "" {
			return "[executable_code] " + code
		}
		return "[executable_code:" + language + "] " + code
	}
	if part.CodeExecutionResult != nil {
		output := strings.TrimSpace(part.CodeExecutionResult.Output)
		if output == "" {
			output = strings.TrimSpace(part.CodeExecutionResult.Outcome)
		}
		if output != "" {
			return "[code_execution_result] " + output
		}
	}
	if part.FileData != nil {
		mimeType := strings.TrimSpace(part.FileData.MimeType)
		if mimeType != "" {
			return "[file_data mime=" + mimeType + "]"
		}
		return "[file_data]"
	}
	return ""
}

// geminiInlineDataName 为无名 inlineData 文档生成占位名。
func geminiInlineDataName(mimeType string) string {
	ext := "bin"
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "application/pdf":
		ext = "pdf"
	case "application/msword":
		ext = "doc"
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		ext = "docx"
	case "application/vnd.ms-excel":
		ext = "xls"
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		ext = "xlsx"
	case "text/plain":
		ext = "txt"
	}
	return "inline_data." + ext
}
