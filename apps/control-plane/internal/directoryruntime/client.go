package directoryruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const RealmName = "jjdguard"

type clientOptions struct {
	RuntimeURL   string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

type Client struct {
	runtimeURL   *url.URL
	clientID     string
	clientSecret string
	httpClient   *http.Client

	mu    sync.Mutex
	token string
}

func newClient(options clientOptions) (*Client, error) {
	runtimeURL, err := url.Parse(strings.TrimSpace(options.RuntimeURL))
	if err != nil || runtimeURL.Hostname() == "" ||
		(runtimeURL.Scheme != "http" && runtimeURL.Scheme != "https") ||
		runtimeURL.User != nil || runtimeURL.RawQuery != "" || runtimeURL.Fragment != "" {
		return nil, ErrRuntimeUnavailable
	}
	if strings.TrimSpace(options.ClientID) == "" || strings.TrimSpace(options.ClientSecret) == "" {
		return nil, ErrRuntimeUnavailable
	}
	if options.HTTPClient == nil {
		options.HTTPClient = http.DefaultClient
	}
	return &Client{
		runtimeURL: runtimeURL, clientID: options.ClientID, clientSecret: options.ClientSecret,
		httpClient: options.HTTPClient,
	}, nil
}

func (client *Client) Apply(ctx context.Context, config DirectoryConfig, digest string) error {
	provider, err := DesiredProvider(config)
	if err != nil {
		return err
	}
	realmID, err := client.realmID(ctx)
	if err != nil {
		return err
	}
	provider.ParentID = realmID
	components, err := client.components(ctx, realmID)
	if err != nil {
		return err
	}
	for _, component := range components {
		if component.Name == ProviderName && component.ProviderID == ProviderID && component.ProviderType == ProviderType {
			provider.ID = component.ID
			if err := client.authorizedJSON(ctx, http.MethodPut, "/admin/realms/"+RealmName+"/components/"+url.PathEscape(component.ID), provider, http.StatusNoContent, http.StatusOK); err != nil {
				return err
			}
			return client.reconcileProviderMappers(ctx, component.ID, config.Kind)
		}
	}
	if err := client.authorizedJSON(ctx, http.MethodPost, "/admin/realms/"+RealmName+"/components", provider, http.StatusCreated, http.StatusNoContent); err != nil {
		return err
	}
	components, err = client.components(ctx, realmID)
	if err != nil {
		return err
	}
	for _, component := range components {
		if component.Name == ProviderName && component.ProviderID == ProviderID && component.ProviderType == ProviderType {
			return client.reconcileProviderMappers(ctx, component.ID, config.Kind)
		}
	}
	return ErrRuntimeUnavailable
}

func (client *Client) reconcileProviderMappers(ctx context.Context, providerID string, kind DirectoryKind) error {
	components, err := client.components(ctx, providerID)
	if err != nil {
		return err
	}
	for _, desired := range DesiredStandardLDAPMappers(providerID, kind) {
		var existing *ComponentRepresentation
		for index := range components {
			if components[index].Name == desired.Name && components[index].ProviderType == LDAPMapperType {
				existing = &components[index]
				break
			}
		}
		if existing == nil {
			if err := client.authorizedJSON(ctx, http.MethodPost, "/admin/realms/"+RealmName+"/components", desired, http.StatusCreated, http.StatusNoContent); err != nil {
				return err
			}
			continue
		}
		desired.ID = existing.ID
		if err := client.authorizedJSON(ctx, http.MethodPut, "/admin/realms/"+RealmName+"/components/"+url.PathEscape(existing.ID), desired, http.StatusNoContent, http.StatusOK); err != nil {
			return err
		}
	}
	return client.reconcileADBinaryMapper(ctx, providerID, kind == KindActiveDirectory)
}

func (client *Client) reconcileADBinaryMapper(ctx context.Context, providerID string, enabled bool) error {
	components, err := client.components(ctx, providerID)
	if err != nil {
		return err
	}
	var existing *ComponentRepresentation
	for index := range components {
		if components[index].Name == ADBinaryMapperName &&
			components[index].ProviderID == "user-attribute-ldap-mapper" &&
			components[index].ProviderType == LDAPMapperType {
			existing = &components[index]
			break
		}
	}
	if !enabled {
		if existing == nil {
			return nil
		}
		return client.authorizedJSON(ctx, http.MethodDelete, "/admin/realms/"+RealmName+"/components/"+url.PathEscape(existing.ID), nil, http.StatusNoContent, http.StatusOK)
	}
	mapper := DesiredADBinaryMapper(providerID)
	if existing == nil {
		return client.authorizedJSON(ctx, http.MethodPost, "/admin/realms/"+RealmName+"/components", mapper, http.StatusCreated, http.StatusNoContent)
	}
	mapper.ID = existing.ID
	return client.authorizedJSON(ctx, http.MethodPut, "/admin/realms/"+RealmName+"/components/"+url.PathEscape(existing.ID), mapper, http.StatusNoContent, http.StatusOK)
}

func (client *Client) Status(ctx context.Context) (RuntimeStatus, error) {
	snapshot, err := client.Snapshot(ctx)
	if err != nil {
		return RuntimeStatus{}, err
	}
	if !snapshot.Exists {
		return RuntimeStatus{}, nil
	}
	digest, err := ComputeComponentDigest(snapshot.Component)
	if err != nil {
		return RuntimeStatus{Exists: true, Drifted: true}, nil
	}
	enabled := len(snapshot.Component.Config["enabled"]) == 0 || snapshot.Component.Config["enabled"][0] == "true"
	return RuntimeStatus{Exists: true, Enabled: enabled, Digest: digest}, nil
}

func (client *Client) Snapshot(ctx context.Context) (RuntimeSnapshot, error) {
	realmID, err := client.realmID(ctx)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	components, err := client.components(ctx, realmID)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	for _, component := range components {
		if component.Name == ProviderName && component.ProviderID == ProviderID && component.ProviderType == ProviderType {
			return RuntimeSnapshot{Exists: true, Component: component}, nil
		}
	}
	return RuntimeSnapshot{}, nil
}

func (client *Client) Restore(ctx context.Context, snapshot RuntimeSnapshot) error {
	if !snapshot.Exists {
		current, err := client.Snapshot(ctx)
		if err != nil || !current.Exists {
			return err

		}
		return client.authorizedJSON(ctx, http.MethodDelete, "/admin/realms/"+RealmName+"/components/"+url.PathEscape(current.Component.ID), nil, http.StatusNoContent, http.StatusOK)
	}
	return client.authorizedJSON(ctx, http.MethodPut, "/admin/realms/"+RealmName+"/components/"+url.PathEscape(snapshot.Component.ID), snapshot.Component, http.StatusNoContent, http.StatusOK)
}

func (client *Client) realmID(ctx context.Context) (string, error) {
	var realm struct {
		ID string `json:"id"`
	}
	if err := client.authorizedJSON(ctx, http.MethodGet, "/admin/realms/"+RealmName, nil, http.StatusOK, &realm); err != nil {
		return "", err
	}
	if realm.ID == "" {
		return "", ErrRuntimeUnavailable
	}
	return realm.ID, nil
}

func (client *Client) components(ctx context.Context, parentID string) ([]ComponentRepresentation, error) {
	target := "/admin/realms/" + RealmName + "/components?parent=" + url.QueryEscape(parentID)
	var components []ComponentRepresentation
	if err := client.authorizedJSON(ctx, http.MethodGet, target, nil, http.StatusOK, &components); err != nil {
		return nil, err
	}
	return components, nil
}

func (client *Client) FullSync(ctx context.Context) error {
	snapshot, err := client.Snapshot(ctx)
	if err != nil || !snapshot.Exists || snapshot.Component.ID == "" {
		return ErrRuntimeUnavailable
	}
	var result map[string]any
	return client.authorizedJSON(ctx, http.MethodPost,
		"/admin/realms/"+RealmName+"/user-storage/"+url.PathEscape(snapshot.Component.ID)+"/sync?action=triggerFullSync",
		nil, http.StatusOK, &result)
}
func (client *Client) authorizedJSON(ctx context.Context, method, path string, input any, expected ...any) error {
	var output any
	statuses := make([]int, 0, len(expected))
	for _, item := range expected {
		if value, ok := item.(int); ok {
			statuses = append(statuses, value)
		} else {
			output = item
		}
	}
	token, err := client.accessToken(ctx)
	if err != nil {
		return err
	}
	var body []byte
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return ErrRuntimeUnavailable
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		request, requestErr := client.newRequest(ctx, method, path, body)
		if requestErr != nil {
			return requestErr
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response, requestErr := client.httpClient.Do(request)
		if requestErr != nil {
			return ErrRuntimeUnavailable
		}
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 {
			response.Body.Close()
			client.invalidateToken(token)
			token, requestErr = client.accessToken(ctx)
			if requestErr != nil {
				return requestErr
			}
			continue
		}
		defer response.Body.Close()
		if !hasStatus(response.StatusCode, statuses) {
			log.Printf("directory runtime request failed method=%s path=%s status=%d", method, path, response.StatusCode)
			return ErrRuntimeUnavailable
		}
		if output != nil {
			return json.NewDecoder(response.Body).Decode(output)
		}
		return nil
	}
	return ErrRuntimeUnavailable
}

func (client *Client) invalidateToken(token string) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.token == token {
		client.token = ""
	}
}

func (client *Client) accessToken(ctx context.Context) (string, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.token != "" {
		return client.token, nil
	}
	values := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.clientID},
		"client_secret": {client.clientSecret},
	}
	request, err := client.newRequest(ctx, http.MethodPost, "/realms/"+RealmName+"/protocol/openid-connect/token", []byte(values.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.httpClient.Do(request)
	if err != nil {
		log.Printf("directory runtime token request transport failure")
		return "", ErrRuntimeUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Printf("directory runtime token request failed status=%d", response.StatusCode)
		return "", ErrRuntimeUnavailable
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil || token.AccessToken == "" {
		log.Printf("directory runtime token response invalid")
		return "", ErrRuntimeUnavailable
	}
	client.token = token.AccessToken
	return client.token, nil
}

func (client *Client) newRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	target := *client.runtimeURL
	target.Path = strings.TrimSuffix(target.Path, "/") + path
	target.RawQuery = ""
	if split := strings.SplitN(target.Path, "?", 2); len(split) == 2 {
		target.Path = split[0]
		target.RawQuery = split[1]
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrRuntimeUnavailable
	}
	return request, nil
}

func hasStatus(status int, expected []int) bool {
	for _, value := range expected {
		if status == value {
			return true
		}
	}
	return false
}

var _ RuntimeClient = (*Client)(nil)
