package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

const anthropicCatalogBodyLimit = 2 << 20
const anthropicCatalogModelLimit = 5000

// AnthropicClient supports the native Models API and Anthropic-compatible relays.
// A test transport is package-private; production always validates and pins DNS.
type AnthropicClient struct{ testHTTPClient *http.Client }

func NewAnthropicClient() *AnthropicClient { return &AnthropicClient{} }

func (c *AnthropicClient) FetchModels(ctx context.Context, baseURL, apiKey string) ([]types.ProviderCatalogModel, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}
	endpoint, err := anthropicCatalogEndpoint(baseURL)
	if err != nil {
		return nil, errors.New("anthropic_catalog_invalid_target")
	}
	var target safetarget.Target
	var client *http.Client
	if c != nil && c.testHTTPClient != nil {
		copyClient := *c.testHTTPClient
		client = &copyClient
	} else {
		var err error
		target, err = safetarget.Resolve(ctx, endpoint.String(), false, nil)
		if err != nil {
			return nil, errors.New("anthropic_catalog_invalid_target")
		}
		client = safetarget.Client(&http.Client{Timeout: 30 * time.Second}, target, false)
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return safetarget.ErrRedirectNotAllowed }
	if proxyURL := outboundProxyURL(ctx); proxyURL != "" {
		if c == nil || c.testHTTPClient == nil {
			client, err = anthropicPinnedProxyClient(nil, target, proxyURL)
		} else {
			client, err = httpClientWithOutboundProxy(client, proxyURL)
		}
		if err != nil {
			return nil, errors.New("anthropic_catalog_invalid_proxy")
		}
	}
	models := make([]types.ProviderCatalogModel, 0)
	seen := make(map[string]types.ProviderCatalogModel)
	cursors := make(map[string]bool)
	totalBytes := 0
	for page := 0; page < 100; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, errors.New("anthropic_catalog_invalid_target")
		}
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")
		response, err := client.Do(req)
		if err != nil {
			return nil, errors.New("anthropic_catalog_connection_failed")
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			kind := "upstream_error"
			switch response.StatusCode {
			case 401, 403:
				kind = "unauthorized"
			case 404, 405:
				kind = "unsupported_endpoint"
			case 429:
				kind = "rate_limited"
			}
			return nil, fmt.Errorf("anthropic_catalog_%s (HTTP %d)", kind, response.StatusCode)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, anthropicCatalogBodyLimit+1))
		response.Body.Close()
		totalBytes += len(body)
		if readErr != nil || len(body) > anthropicCatalogBodyLimit || totalBytes > 8<<20 {
			return nil, errors.New("anthropic_catalog_response_too_large_or_unreadable")
		}
		items, more, cursor, err := parseAnthropicCatalogPage(body)
		if err != nil {
			return nil, err
		}
		for _, model := range items {
			if old, ok := seen[model.ID]; ok {
				if !reflect.DeepEqual(old, model) {
					return nil, errors.New("anthropic_catalog_conflicting_model")
				}
				continue
			}
			seen[model.ID] = model
			models = append(models, model)
			if len(models) > anthropicCatalogModelLimit {
				return nil, errors.New("anthropic_catalog_too_many_models")
			}
		}
		if !more {
			return models, nil
		}
		if cursor == "" || len(items) == 0 || cursor != items[len(items)-1].ID || cursors[cursor] {
			return nil, errors.New("anthropic_catalog_invalid_pagination")
		}
		cursors[cursor] = true
		q := endpoint.Query()
		q.Set("after_id", cursor)
		endpoint.RawQuery = q.Encode()
	}
	return nil, errors.New("anthropic_catalog_page_limit_exceeded")
}

func anthropicCatalogEndpoint(baseURL string) (*url.URL, error) {
	if baseURL != strings.TrimSpace(baseURL) || strings.IndexFunc(baseURL, unicode.IsControl) >= 0 {
		return nil, errors.New("invalid target")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Opaque != "" || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.ForceQuery {
		return nil, errors.New("invalid target")
	}
	path := strings.TrimRight(parsed.Path, "/")
	if strings.HasSuffix(path, "/v1") {
		parsed.Path = path + "/models"
	} else {
		parsed.Path = path + "/v1/models"
	}
	parsed.RawPath = ""
	return parsed, nil
}

func parseAnthropicCatalogPage(body []byte) ([]types.ProviderCatalogModel, bool, string, error) {
	invalid := errors.New("anthropic_catalog_invalid_response")
	var envelope map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	if dec.Decode(&envelope) != nil {
		return nil, false, "", invalid
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return nil, false, "", invalid
	}
	data, ok := envelope["data"]
	data = bytes.TrimSpace(data)
	if !ok || len(data) == 0 || data[0] != '[' {
		return nil, false, "", invalid
	}
	if v := bytes.TrimSpace(envelope["error"]); len(v) > 0 && string(v) != "null" {
		return nil, false, "", invalid
	}
	if v, ok := envelope["object"]; ok {
		var object string
		if json.Unmarshal(v, &object) != nil || object != "list" {
			return nil, false, "", invalid
		}
	}
	for _, key := range []string{"success", "ok"} {
		if v, ok := envelope[key]; ok {
			var success bool
			if json.Unmarshal(v, &success) != nil || !success {
				return nil, false, "", invalid
			}
		}
	}
	if v, ok := envelope["code"]; ok {
		var code int
		if json.Unmarshal(v, &code) != nil || code != 0 && code != 200 {
			return nil, false, "", invalid
		}
	}
	for _, key := range []string{"has_next", "incomplete", "truncated"} {
		if v, ok := envelope[key]; ok {
			var flag bool
			if json.Unmarshal(v, &flag) != nil || flag {
				return nil, false, "", invalid
			}
		}
	}
	for _, key := range []string{"next", "next_page", "next_cursor", "next_page_token", "pagination", "links"} {
		if v := bytes.TrimSpace(envelope[key]); len(v) > 0 && string(v) != "null" && string(v) != `""` {
			return nil, false, "", invalid
		}
	}
	var rawModels []struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		Object      string `json:"object"`
		DisplayName string `json:"display_name"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if json.Unmarshal(data, &rawModels) != nil {
		return nil, false, "", invalid
	}
	for _, key := range []string{"total", "total_count"} {
		if v, ok := envelope[key]; ok {
			var total int
			if json.Unmarshal(v, &total) != nil || total != len(rawModels) {
				return nil, false, "", invalid
			}
		}
	}
	nativePage := false
	if _, ok := envelope["first_id"]; ok {
		nativePage = true
	}
	if _, ok := envelope["last_id"]; ok {
		nativePage = true
	}
	models := make([]types.ProviderCatalogModel, 0, len(rawModels))
	for _, raw := range rawModels {
		if raw.Type != "" || raw.DisplayName != "" {
			nativePage = true
		}
		if raw.ID == "" || raw.ID != strings.TrimSpace(raw.ID) || len(raw.ID) > 255 || strings.IndexFunc(raw.ID, unicode.IsControl) >= 0 || raw.Type != "" && raw.Type != "model" || raw.Object != "" && raw.Object != "model" {
			return nil, false, "", invalid
		}
		name := raw.DisplayName
		if name == "" {
			name = raw.Name
		}
		models = append(models, types.ProviderCatalogModel{ID: raw.ID, Object: "model", Name: name, Description: raw.Description})
	}
	if nativePage {
		if _, ok := envelope["has_more"]; !ok {
			return nil, false, "", invalid
		}
		if _, ok := envelope["last_id"]; !ok {
			return nil, false, "", invalid
		}
	}
	more := false
	if v, ok := envelope["has_more"]; ok {
		if string(bytes.TrimSpace(v)) != "true" && string(bytes.TrimSpace(v)) != "false" {
			return nil, false, "", invalid
		}
		if json.Unmarshal(v, &more) != nil {
			return nil, false, "", invalid
		}
	}
	cursor := ""
	if v, ok := envelope["last_id"]; ok {
		if json.Unmarshal(v, &cursor) != nil {
			return nil, false, "", invalid
		}
	}
	if nativePage && len(models) > 0 && cursor != models[len(models)-1].ID {
		return nil, false, "", invalid
	}
	return models, more, cursor, nil
}
