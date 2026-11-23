package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/providercompat"
)

// ErrProviderUnsupported is returned when a provider type doesn't support catalog fetch
var ErrProviderUnsupported = fmt.Errorf("provider does not support model catalog")

// IsProviderUnsupported checks if an error indicates provider unsupported
func IsProviderUnsupported(err error) bool {
	return err == ErrProviderUnsupported
}

// Client defines the interface for fetching provider model catalogs
type Client interface {
	FetchModels(ctx context.Context, baseURL, apiKey string) ([]types.ProviderCatalogModel, error)
}

// OpenAIClient fetches models from OpenAI-compatible providers
type OpenAIClient struct {
	httpClient *http.Client
}

// NewOpenAIClient creates a new OpenAI catalog client
func NewOpenAIClient() *OpenAIClient {
	return &OpenAIClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// FetchModels fetches the model list from an OpenAI-compatible provider
func (c *OpenAIClient) FetchModels(ctx context.Context, baseURL, apiKey string) ([]types.ProviderCatalogModel, error) {
	if baseURL == "" {
		baseURL = "https://api.openai.com"
	}

	baseURL = strings.TrimRight(baseURL, "/")
	url := baseURL + "/v1/models"
	if strings.HasSuffix(baseURL, "/v1") {
		url = baseURL + "/models"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)

	client, err := httpClientWithOutboundProxy(c.httpClient, outboundProxyURL(ctx))
	if err != nil {
		return nil, fmt.Errorf("invalid outbound proxy configuration")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch models: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider returned status %d", resp.StatusCode)
	}

	// Only an explicit, bounded, complete list can drive removal. Never
	// interpret an error envelope, absent/null data, or unfinished pagination
	// as an empty inventory. Pagination is deliberately fail-closed until a
	// connector can prove completion of every page.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024+1))
	if err != nil || len(raw) > 8*1024*1024 {
		return nil, fmt.Errorf("catalog response unreadable or exceeds limit")
	}
	var envelope map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("invalid catalog JSON")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("catalog has trailing content")
	}
	data, ok := envelope["data"]
	if !ok || len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '[' {
		return nil, fmt.Errorf("catalog requires an explicit data array")
	}
	if v := envelope["error"]; len(v) > 0 && string(v) != "null" {
		return nil, fmt.Errorf("catalog returned an error envelope")
	}
	if v, ok := envelope["object"]; ok {
		var object string
		if json.Unmarshal(v, &object) != nil || object != "list" {
			return nil, fmt.Errorf("catalog is not a list envelope")
		}
	}
	for _, key := range []string{"success", "ok"} {
		if v, ok := envelope[key]; ok {
			var success bool
			if json.Unmarshal(v, &success) != nil || !success {
				return nil, fmt.Errorf("catalog returned a failure envelope")
			}
		}
	}
	if v, ok := envelope["code"]; ok {
		var code int
		if json.Unmarshal(v, &code) != nil || code != 0 && code != 200 {
			return nil, fmt.Errorf("catalog returned a failure code")
		}
	}
	for _, key := range []string{"has_more", "has_next", "incomplete", "truncated"} {
		if v, ok := envelope[key]; ok {
			var more bool
			if json.Unmarshal(v, &more) != nil || more {
				return nil, fmt.Errorf("catalog is incomplete: %s", key)
			}
		}
	}
	for _, key := range []string{"next", "next_page", "next_cursor", "next_page_token", "pagination", "links"} {
		if v := envelope[key]; len(v) > 0 && string(v) != "null" && string(v) != `""` {
			return nil, fmt.Errorf("catalog pagination completion is unverified")
		}
	}
	var models []types.ProviderCatalogModel
	if err := json.Unmarshal(data, &models); err != nil {
		return nil, fmt.Errorf("invalid catalog data")
	}
	if models == nil {
		return nil, fmt.Errorf("null catalog data")
	}
	for _, key := range []string{"total", "total_count"} {
		if v, ok := envelope[key]; ok {
			var total int
			if json.Unmarshal(v, &total) != nil || total != len(models) {
				return nil, fmt.Errorf("catalog total does not match complete snapshot")
			}
		}
	}
	seen := map[string]types.ProviderCatalogModel{}
	canonical := make([]types.ProviderCatalogModel, 0, len(models))
	for _, model := range models {
		if strings.TrimSpace(model.ID) == "" || strings.TrimSpace(model.ID) != model.ID || len(model.ID) > 255 || strings.ContainsAny(model.ID, "\x00\r\n") || (model.Object != "" && model.Object != "model") {
			return nil, fmt.Errorf("catalog contains invalid model identity")
		}
		if previous, ok := seen[model.ID]; ok {
			if !reflect.DeepEqual(previous, model) {
				return nil, fmt.Errorf("catalog contains conflicting duplicate identities")
			}
			continue
		}
		seen[model.ID] = model
		canonical = append(canonical, model)
	}
	return canonical, nil
}

// UnsupportedCatalogClient makes an explicit provider boundary visible when a
// provider has no catalog endpoint. It must not be confused with an
// OpenAI-compatible catalog client or with a runtime protocol adapter.
type UnsupportedCatalogClient struct {
	ProviderType string
}

func (c *UnsupportedCatalogClient) FetchModels(ctx context.Context, baseURL, apiKey string) ([]types.ProviderCatalogModel, error) {
	return nil, ErrProviderUnsupported
}

// Factory creates catalog clients by provider type
type Factory struct {
	openaiClient    Client
	anthropicClient Client
	azureClient     Client
}

// NewFactory creates a catalog client factory
func NewFactory() *Factory {
	return &Factory{
		openaiClient:    NewOpenAIClient(),
		anthropicClient: NewAnthropicClient(),
		azureClient:     newAzureClient(),
	}
}

// GetClient returns the appropriate catalog client for a provider type
func (f *Factory) GetClient(providerType string) (Client, error) {
	switch providerType {
	case "azure":
		return f.azureClient, nil
	case "anthropic":
		return f.anthropicClient, nil
	case "bedrock", "gemini", "vertex":
		return &UnsupportedCatalogClient{ProviderType: providerType}, nil
	default:
		if providercompat.SupportsOpenAICatalog(providerType) {
			return f.openaiClient, nil
		}
		return nil, ErrProviderUnsupported
	}
}
