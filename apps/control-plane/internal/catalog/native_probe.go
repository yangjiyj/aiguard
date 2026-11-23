package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func nativeProbeProvider(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "gemini", "vertex", "bedrock":
		return true
	}
	return false
}

// Native probes establish the gateway's normalized chat capability by making a
// bounded request to the actual provider contract. They do not prove native
// OpenAI Responses or Anthropic Messages support.
func (p *httpModelProber) probeNative(ctx context.Context, probe ModelProbeRequest) (result ModelProbeResult) {
	started := time.Now()
	defer func() { result.LatencyMS = time.Since(started).Milliseconds() }()
	if protocol := strings.ToLower(strings.TrimSpace(probe.Protocol)); protocol != "" && protocol != "chat" && protocol != "chat_completions" {
		return modelProbeFailure(ModelProbeErrorInvalidRequest)
	}
	typ := strings.ToLower(strings.TrimSpace(probe.ProviderType))
	credential := strings.TrimSpace(probe.APIKey)
	var aws nativeBedrockCredential
	var account *nativeGoogleServiceAccount
	var err error
	if typ == "bedrock" {
		aws, err = parseNativeBedrockCredential(credential)
		if err != nil {
			return modelProbeFailure(ModelProbeErrorInvalidRequest)
		}
		if probe.BaseURL == "" {
			probe.BaseURL = "https://bedrock-runtime." + aws.Region + ".amazonaws.com"
		}
	} else if strings.HasPrefix(credential, "{") {
		account, err = parseNativeGoogleAccount(credential)
		if err != nil {
			return modelProbeFailure(ModelProbeErrorInvalidRequest)
		}
	} else if typ == "vertex" {
		return modelProbeFailure(ModelProbeErrorInvalidRequest)
	} else if probe.BaseURL == "" {
		probe.BaseURL = "https://generativelanguage.googleapis.com"
	}
	validation := probe
	validation.AuthMode = "bearer"
	validation.Protocol = "chat"
	if _, _, _, err = validateModelProbeRequest(validation); err != nil {
		return modelProbeFailure(ModelProbeErrorInvalidRequest)
	}
	timeout := modelProbeTimeout
	if probe.Timeout > 0 {
		timeout = probe.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	endpoint, err := nativeGenerationEndpoint(probe, account, aws)
	if err != nil {
		return modelProbeFailure(ModelProbeErrorInvalidRequest)
	}
	client, err := p.clientFor(ctx, endpoint, false)
	if err != nil {
		return classifyModelProbeError(ctx, err)
	}
	client.Timeout = timeout
	budget := modelProbeMaxCompletionTokens
	if typ == "bedrock" {
		budget = 128
	}
	if probe.MaxOutputTokens > 0 {
		budget = probe.MaxOutputTokens
	}
	fields := map[string]any{"contents": []any{map[string]any{"role": "user", "parts": []any{map[string]string{"text": "Reply OK."}}}}, "generationConfig": map[string]int{"maxOutputTokens": budget}}
	if typ == "bedrock" {
		fields = map[string]any{"messages": []any{map[string]any{"role": "user", "content": []any{map[string]string{"text": "Reply OK."}}}}, "inferenceConfig": map[string]int{"maxTokens": budget}}
	}
	body, _ := json.Marshal(fields)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return modelProbeFailure(ModelProbeErrorInvalidRequest)
	}
	request.Header.Set("Content-Type", "application/json")
	switch {
	case typ == "bedrock":
		if err = signNativeBedrockRequest(request, aws, time.Now().UTC()); err != nil {
			return modelProbeFailure(ModelProbeErrorInvalidRequest)
		}
	case account != nil:
		token, status, tokenErr := p.nativeGoogleToken(ctx, account)
		if tokenErr != nil {
			result = classifyModelProbeError(ctx, tokenErr)
			result.HTTPStatus = status
			if status == 401 || status == 403 {
				result = modelProbeFailure(ModelProbeErrorUnauthorized)
				result.HTTPStatus = status
			}
			return result
		}
		request.Header.Set("Authorization", "Bearer "+token)
	default:
		request.Header.Set("X-Goog-Api-Key", credential)
	}
	response, err := client.Do(request)
	if err != nil {
		return classifyModelProbeError(ctx, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		kind := ModelProbeErrorUpstream
		switch response.StatusCode {
		case 401, 403:
			kind = ModelProbeErrorUnauthorized
		case 404:
			kind = ModelProbeErrorNotDeployed
		case 429:
			kind = ModelProbeErrorRateLimited
		}
		result = modelProbeFailure(kind)
		result.HTTPStatus = response.StatusCode
		return result
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, modelProbeResponseBodyLimit+1))
	if readErr != nil {
		result = classifyModelProbeError(ctx, readErr)
	} else if len(raw) > modelProbeResponseBodyLimit || !validNativeGeneration(raw, typ) {
		result = modelProbeFailure(ModelProbeErrorUpstream)
	} else {
		result = ModelProbeResult{OK: true, PayloadValidated: true, Message: "部署探测成功"}
	}
	result.HTTPStatus = response.StatusCode
	return result
}

var nativeRegionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func nativeGenerationEndpoint(probe ModelProbeRequest, account *nativeGoogleServiceAccount, aws nativeBedrockCredential) (string, error) {
	parsed, err := url.Parse(probe.BaseURL)
	if err != nil {
		return "", err
	}
	model := strings.TrimSpace(probe.DeploymentName)
	if model == "" || strings.ContainsAny(model, "\r\n\t?#\\") {
		return "", errors.New("invalid native deployment")
	}
	basePath := strings.TrimRight(parsed.Path, "/")
	if strings.EqualFold(strings.TrimSpace(probe.ProviderType), "bedrock") {
		if !nativeRegionPattern.MatchString(aws.Region) {
			return "", errors.New("invalid AWS region")
		}
		if host := parsed.Hostname(); strings.HasPrefix(host, "bedrock-runtime.") && strings.HasSuffix(host, ".amazonaws.com") {
			parsed.Host = "bedrock-runtime." + aws.Region + ".amazonaws.com"
		}
		baseEscaped := strings.TrimRight(parsed.EscapedPath(), "/")
		parsed.Path = basePath + "/model/" + model + "/converse"
		parsed.RawPath = baseEscaped + "/model/" + url.PathEscape(model) + "/converse"
	} else {
		model = strings.TrimPrefix(strings.TrimPrefix(model, "publishers/google/models/"), "models/")
		if model == "" || strings.Contains(model, "/") {
			return "", errors.New("invalid Google model")
		}
		if account != nil {
			basePath = strings.TrimSuffix(strings.TrimSuffix(basePath, "/v1beta1"), "/v1")
			location := "global"
			host := strings.ToLower(parsed.Hostname())
			if strings.HasSuffix(host, "-aiplatform.googleapis.com") {
				location = strings.TrimSuffix(host, "-aiplatform.googleapis.com")
			}
			parsed.Path = basePath + "/v1/projects/" + account.ProjectID + "/locations/" + location + "/publishers/google/models/" + model + ":generateContent"
		} else {
			if strings.HasSuffix(strings.ToLower(parsed.Hostname()), "aiplatform.googleapis.com") {
				return "", errors.New("Vertex requires service account")
			}
			if !strings.HasSuffix(basePath, "/v1") && !strings.HasSuffix(basePath, "/v1beta") {
				basePath += "/v1beta"
			}
			parsed.Path = basePath + "/models/" + model + ":generateContent"
		}
		parsed.RawPath = ""
	}
	parsed.RawQuery = ""
	return parsed.String(), nil
}

func validNativeGeneration(raw []byte, typ string) bool {
	var body struct {
		Error      json.RawMessage `json:"error"`
		Candidates []struct {
			Content struct {
				Role  string `json:"role"`
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			Finish string `json:"finishReason"`
		} `json:"candidates"`
		Output struct {
			Message struct {
				Role    string `json:"role"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"message"`
		} `json:"output"`
		Stop string `json:"stopReason"`
	}
	if json.Unmarshal(raw, &body) != nil || (len(body.Error) > 0 && string(body.Error) != "null") {
		return false
	}
	if typ == "bedrock" {
		if body.Output.Message.Role != "assistant" || (body.Stop != "end_turn" && body.Stop != "stop_sequence" && body.Stop != "max_tokens") {
			return false
		}
		for _, part := range body.Output.Message.Content {
			if strings.TrimSpace(part.Text) != "" {
				return true
			}
		}
		return false
	}
	for _, candidate := range body.Candidates {
		if candidate.Content.Role != "model" || (candidate.Finish != "STOP" && candidate.Finish != "MAX_TOKENS") {
			continue
		}
		for _, part := range candidate.Content.Parts {
			if strings.TrimSpace(part.Text) != "" {
				return true
			}
		}
	}
	return false
}
