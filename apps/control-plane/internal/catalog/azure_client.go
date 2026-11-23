package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

const (
	azureCatalogBodyMaxBytes  = 2 << 20
	azureCatalogModelMaxItems = 5000
	azureCatalogTimeout       = 30 * time.Second
)

var (
	errAzureCatalogInvalidTarget = errors.New("azure_catalog_invalid_target")
	errAzureCatalogUnavailable   = errors.New("azure_catalog_unavailable")
	errAzureCatalogTooLarge      = errors.New("azure_catalog_response_too_large")
	errAzureCatalogTooManyModels = errors.New("azure_catalog_too_many_models")
)

// azureClient is the Azure-only catalog boundary. Production requests always
// pass through safetarget resolution and an IP-pinned, proxy-free client.
type azureClient struct {
	testHTTPClient *http.Client
}

func newAzureClient() *azureClient {
	return &azureClient{}
}

// newAzureClientWithHTTPClient is intentionally unexported and exists only so
// package tests can exercise response handling without weakening production DNS policy.
func newAzureClientWithHTTPClient(client *http.Client) *azureClient {
	return &azureClient{testHTTPClient: client}
}

func (c *azureClient) FetchModels(ctx context.Context, baseURL, apiKey string) ([]types.ProviderCatalogModel, error) {
	endpoint, err := azureCatalogEndpoint(baseURL)
	if err != nil {
		return nil, errAzureCatalogInvalidTarget
	}

	proxyURL := outboundProxyURL(ctx)
	client := c.testClient()
	if client == nil {
		target, resolveErr := safetarget.Resolve(ctx, endpoint.String(), false, nil)
		if resolveErr != nil {
			return nil, errAzureCatalogInvalidTarget
		}
		if proxyURL == "" {
			client = safetarget.Client(&http.Client{Timeout: azureCatalogTimeout}, target, false)
		} else {
			client, err = httpClientWithOutboundProxy(&http.Client{
				Timeout: azureCatalogTimeout,
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
					return safetarget.ErrRedirectNotAllowed
				},
			}, proxyURL)
			if err != nil {
				return nil, errAzureCatalogInvalidTarget
			}
		}
	} else if proxyURL != "" {
		client, err = httpClientWithOutboundProxy(client, proxyURL)
		if err != nil {
			return nil, errAzureCatalogInvalidTarget
		}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errAzureCatalogInvalidTarget
	}
	request.Header.Set("Authorization", "Bearer "+apiKey)
	response, err := client.Do(request)
	if err != nil {
		return nil, errAzureCatalogUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errAzureCatalogUnavailable
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, azureCatalogBodyMaxBytes+1))
	if err != nil {
		return nil, errAzureCatalogUnavailable
	}
	if len(body) > azureCatalogBodyMaxBytes {
		return nil, errAzureCatalogTooLarge
	}
	var payload struct {
		Data []types.ProviderCatalogModel `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, errAzureCatalogUnavailable
	}
	if len(payload.Data) > azureCatalogModelMaxItems {
		return nil, errAzureCatalogTooManyModels
	}
	if payload.Data == nil {
		payload.Data = []types.ProviderCatalogModel{}
	}
	return payload.Data, nil
}

func (c *azureClient) testClient() *http.Client {
	if c == nil || c.testHTTPClient == nil {
		return nil
	}
	copyClient := *c.testHTTPClient
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return safetarget.ErrRedirectNotAllowed
	}
	if copyClient.Timeout == 0 {
		copyClient.Timeout = azureCatalogTimeout
	}
	return &copyClient
}

func azureCatalogEndpoint(baseURL string) (*url.URL, error) {
	if baseURL == "" || baseURL != strings.TrimSpace(baseURL) || strings.IndexFunc(baseURL, unicode.IsControl) >= 0 {
		return nil, errAzureCatalogInvalidTarget
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Opaque != "" || !parsed.IsAbs() || parsed.Host == "" {
		return nil, errAzureCatalogInvalidTarget
	}
	if parsed.Scheme != "https" {
		return nil, errAzureCatalogInvalidTarget
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.RawQuery != "" || parsed.ForceQuery {
		return nil, errAzureCatalogInvalidTarget
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
