package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type parsedChatRequest struct {
	raw     []byte
	request ChatCompletionRequest
}

type chatRequestParseFailure string

const (
	chatRequestReadFailed   chatRequestParseFailure = "read_failed"
	chatRequestInvalidJSON  chatRequestParseFailure = "invalid_json"
	chatRequestBodyTooLarge chatRequestParseFailure = "body_too_large"
)

type chatRequestParseError struct {
	failure chatRequestParseFailure
	err     error
}

func (e *chatRequestParseError) Error() string {
	if e == nil || e.err == nil {
		return "chat request parse error"
	}
	return e.err.Error()
}

func (e *chatRequestParseError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func readChatCompletionRequest(r *http.Request, limitBytes int64) (parsedChatRequest, error) {
	reader := http.MaxBytesReader(nil, r.Body, limitBytes)
	raw, err := io.ReadAll(reader)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return parsedChatRequest{}, &chatRequestParseError{failure: chatRequestBodyTooLarge, err: fmt.Errorf("request body exceeds %d bytes", limitBytes)}
		}
		return parsedChatRequest{}, &chatRequestParseError{failure: chatRequestReadFailed, err: err}
	}
	return parseChatCompletionRequest(raw)
}

func parseChatCompletionRequest(raw []byte) (parsedChatRequest, error) {
	parsed := parsedChatRequest{raw: raw}
	if err := json.Unmarshal(raw, &parsed.request); err != nil {
		return parsed, &chatRequestParseError{failure: chatRequestInvalidJSON, err: err}
	}
	return parsed, nil
}

// marshalChatProviderBody preserves provider-specific request extensions while
// letting the typed request carry security-redacted messages and control flags.
func marshalChatProviderBody(original []byte, request *ChatCompletionRequest) ([]byte, error) {
	encodedRequest, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(original, &merged); err != nil || merged == nil {
		merged = make(map[string]json.RawMessage)
	}
	var typed map[string]json.RawMessage
	if err := json.Unmarshal(encodedRequest, &typed); err != nil {
		return nil, err
	}
	for key, value := range typed {
		merged[key] = value
	}
	// The stream flag is omitted by encoding/json when false. Buffered
	// streaming therefore has to overwrite an original stream=true explicitly.
	if request != nil && !request.Stream {
		merged["stream"] = json.RawMessage("false")
	}
	return json.Marshal(merged)
}
