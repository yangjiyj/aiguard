package handler

import (
	"bufio"
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"strings"
)

func decodeCodeBuddyWebRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	if !isCodeBuddyWebStreamRequest(req) {
		return ExtractedContent{}, false
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	var payload struct {
		Parameters []struct {
			Content string `json:"Content"`
		} `json:"Parameters"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ExtractedContent{}, false
	}
	parts := make([]string, 0, len(payload.Parameters))
	for _, parameter := range payload.Parameters {
		if text := strings.TrimSpace(parameter.Content); text != "" {
			parts = append(parts, text)
		}
	}
	if len(parts) == 0 {
		return ExtractedContent{}, false
	}
	return buildExtracted(parts, nil, "json"), true
}

func decodeCodeBuddyWebResponse(body []byte, contentType string) (ExtractedContent, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), maxTextFragmentBytes)
	seenNonEmpty := false
	lastAIContent := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var payload struct {
			Type     string `json:"Type"`
			Snapshot *struct {
				Messages []struct {
					Type    string `json:"Type"`
					Content string `json:"Content"`
				} `json:"Messages"`
			} `json:"Snapshot"`
			Message *struct {
				Type    string `json:"Type"`
				Content string `json:"Content"`
			} `json:"Message"`
		}
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			return ExtractedContent{}, false
		}
		if !seenNonEmpty {
			seenNonEmpty = true
			if !strings.Contains(payload.Type, "Thread") {
				return ExtractedContent{}, false
			}
		}
		switch payload.Type {
		case "ThreadSnapshot":
			if payload.Snapshot == nil {
				continue
			}
			for _, message := range payload.Snapshot.Messages {
				if message.Type != "AIMessageDto" {
					continue
				}
				if content := strings.TrimSpace(message.Content); content != "" {
					lastAIContent = content
				}
			}
		case "ThreadMessageAppended":
			if payload.Message == nil || payload.Message.Type != "AIMessageDto" {
				continue
			}
			if content := strings.TrimSpace(payload.Message.Content); content != "" {
				lastAIContent = content
			}
		}
	}
	if !seenNonEmpty || lastAIContent == "" {
		return ExtractedContent{}, false
	}
	return buildExtracted([]string{lastAIContent}, nil, "json"), true
}

func isCodeBuddyWebStreamRequest(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	host := normalizeHost(req.URL.Host)
	if host == "" {
		host = normalizeHost(req.Host)
	}
	if host != "ride-3-live-webapp.azurewebsites.net" {
		return false
	}
	path := strings.ToLower(req.URL.Path)
	return strings.Contains(path, "/api/stream")
}
