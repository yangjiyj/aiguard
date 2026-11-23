package identityruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultRequestTimeout  = 10 * time.Second
	defaultMaxResponseSize = int64(1 << 20)
)

type clientOptions struct {
	RuntimeURL       string
	ClientID         string
	ClientSecret     string
	HTTPClient       *http.Client
	Logger           *log.Logger
	RequestTimeout   time.Duration
	MaxResponseBytes int64
	Now              func() time.Time
}

type Client struct {
	runtimeURL       *url.URL
	clientID         string
	clientSecret     string
	httpClient       *http.Client
	logger           *log.Logger
	requestTimeout   time.Duration
	maxResponseBytes int64
	now              func() time.Time

	tokenMu        sync.Mutex
	accessToken    string
	tokenExpiresAt time.Time
}

func (c *Client) String() string {
	if c == nil {
		return "identityruntime.Client<nil>"
	}
	return fmt.Sprintf("identityruntime.Client{RuntimeURL:%q ClientID:%q Credentials:[redacted] Token:[redacted]}",
		c.runtimeURL.String(), c.clientID)
}

func (c *Client) GoString() string {
	return c.String()
}

func NewClient(cfg Config, logger *log.Logger) (*Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return newClient(clientOptions{
		RuntimeURL: cfg.RuntimeURL, ClientID: cfg.clientID, ClientSecret: cfg.clientSecret,
		HTTPClient: &http.Client{Transport: transport, Timeout: defaultRequestTimeout},
		Logger:     logger, RequestTimeout: defaultRequestTimeout, MaxResponseBytes: defaultMaxResponseSize,
	})
}

func newClient(options clientOptions) (*Client, error) {
	runtimeURL, err := url.Parse(strings.TrimSpace(options.RuntimeURL))
	if err != nil || runtimeURL.Hostname() == "" || (runtimeURL.Scheme != "http" && runtimeURL.Scheme != "https") ||
		runtimeURL.User != nil || runtimeURL.RawQuery != "" || runtimeURL.Fragment != "" {
		return nil, ErrInvalidRuntimeTarget
	}
	if strings.TrimSpace(options.ClientID) == "" || strings.TrimSpace(options.ClientSecret) == "" {
		return nil, ErrRuntimeCredentialsRequired
	}
	if options.RequestTimeout <= 0 {
		options.RequestTimeout = defaultRequestTimeout
	}
	if options.MaxResponseBytes <= 0 {
		options.MaxResponseBytes = defaultMaxResponseSize
	}
	if options.HTTPClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		options.HTTPClient = &http.Client{Transport: transport}
	}
	httpClient := *options.HTTPClient
	httpClient.Timeout = options.RequestTimeout
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if options.Logger == nil {
		options.Logger = log.New(io.Discard, "", 0)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Client{
		runtimeURL: runtimeURL, clientID: options.ClientID, clientSecret: options.ClientSecret,
		httpClient: &httpClient, logger: options.Logger, requestTimeout: options.RequestTimeout,
		maxResponseBytes: options.MaxResponseBytes, now: options.Now,
	}, nil
}

func joinRuntimePath(base *url.URL, relative string) (string, error) {
	if base == nil || base.Hostname() == "" || strings.Contains(relative, "..") {
		return "", ErrInvalidRuntimeTarget
	}
	joined := *base
	basePath := strings.TrimSuffix(base.EscapedPath(), "/")
	relativePath := strings.TrimPrefix(relative, "/")
	if relativePath == "" {
		return "", ErrInvalidRuntimeTarget
	}
	joined.RawPath = ""
	joined.Path = strings.TrimSuffix(base.Path, "/") + "/" + relativePath
	if !strings.HasPrefix(joined.EscapedPath(), basePath+"/") {
		return "", ErrInvalidRuntimeTarget
	}
	return joined.String(), nil
}

func (c *Client) tokenPath() string {
	return "/realms/" + RealmName + "/protocol/openid-connect/token"
}

func providerCollectionPath() string {
	return "/admin/realms/" + RealmName + "/identity-provider/instances"
}

func providerPath(alias string) string {
	return providerCollectionPath() + "/" + alias
}

func mapperCollectionPath(alias string) string {
	return providerPath(alias) + "/mappers"
}

func (c *Client) getAccessToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.accessToken != "" && c.now().Before(c.tokenExpiresAt) {
		return c.accessToken, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	body, err := c.do(ctx, http.MethodPost, c.tokenPath(), []byte(form.Encode()),
		"application/x-www-form-urlencoded", "", false, http.StatusOK)
	if err != nil {
		return "", err
	}
	var response struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &response); err != nil || response.AccessToken == "" {
		return "", ErrRuntimeUnauthorized
	}
	ttl := time.Duration(response.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Minute
	}
	refreshBefore := 30 * time.Second
	if ttl <= refreshBefore {
		refreshBefore = ttl / 2
	}
	c.accessToken = response.AccessToken
	c.tokenExpiresAt = c.now().Add(ttl - refreshBefore)
	return c.accessToken, nil
}

func (c *Client) invalidateToken() {
	c.tokenMu.Lock()
	c.accessToken = ""
	c.tokenExpiresAt = time.Time{}
	c.tokenMu.Unlock()
}

func (c *Client) doAuthorized(ctx context.Context, method, path string, payload []byte, contentType string, expected ...int) ([]byte, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	body, err := c.do(ctx, method, path, payload, contentType, token, method == http.MethodGet, expected...)
	if errors.Is(err, ErrRuntimeUnauthorized) {
		c.invalidateToken()
	}
	return body, err
}

func (c *Client) doJSON(ctx context.Context, method, path string, input any, output any, expected ...int) error {
	var payload []byte
	var err error
	if input != nil {
		payload, err = json.Marshal(input)
		if err != nil {
			return ErrRuntimeRejected
		}
	}
	body, err := c.doAuthorized(ctx, method, path, payload, "application/json", expected...)
	if err != nil {
		return err
	}
	if output == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, output); err != nil {
		return ErrRuntimeRejected
	}
	return nil
}

func (c *Client) do(
	ctx context.Context,
	method, path string,
	payload []byte,
	contentType, token string,
	retryRead bool,
	expected ...int,
) ([]byte, error) {
	target, err := joinRuntimePath(c.runtimeURL, path)
	if err != nil {
		return nil, err
	}
	attempts := 1
	if retryRead {
		attempts = 2
	}
	for attempt := 0; attempt < attempts; attempt++ {
		requestCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
		req, requestErr := http.NewRequestWithContext(requestCtx, method, target, bytes.NewReader(payload))
		if requestErr != nil {
			cancel()
			return nil, ErrRuntimeUnavailable
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Accept", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, requestErr := c.httpClient.Do(req)
		if requestErr != nil {
			cancel()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if attempt+1 < attempts {
				continue
			}
			c.logFailure(ErrRuntimeUnavailable, 0)
			return nil, ErrRuntimeUnavailable
		}
		body, readErr := readLimited(resp.Body, c.maxResponseBytes)
		_ = resp.Body.Close()
		cancel()
		if readErr != nil {
			c.logFailure(readErr, resp.StatusCode)
			return nil, readErr
		}
		if statusExpected(resp.StatusCode, expected) {
			return body, nil
		}
		mapped := mapRuntimeStatus(resp.StatusCode)
		if retryRead && errors.Is(mapped, ErrRuntimeUnavailable) && attempt+1 < attempts {
			continue
		}
		c.logFailure(mapped, resp.StatusCode)
		return nil, mapped
	}
	return nil, ErrRuntimeUnavailable
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, ErrRuntimeUnavailable
	}
	if int64(len(body)) > limit {
		return nil, ErrRuntimeResponseTooLarge
	}
	return body, nil
}

func statusExpected(status int, expected []int) bool {
	for _, allowed := range expected {
		if status == allowed {
			return true
		}
	}
	return false
}

func mapRuntimeStatus(status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return ErrRuntimeUnauthorized
	case status == http.StatusNotFound:
		return ErrRuntimeNotFound
	case status == http.StatusConflict:
		return ErrPublishConflict
	case status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500:
		return ErrRuntimeUnavailable
	default:
		return ErrRuntimeRejected
	}
}

func (c *Client) logFailure(err error, status int) {
	code := "rejected"
	switch {
	case errors.Is(err, ErrRuntimeUnauthorized):
		code = "unauthorized"
	case errors.Is(err, ErrRuntimeUnavailable):
		code = "unavailable"
	case errors.Is(err, ErrRuntimeResponseTooLarge):
		code = "response_too_large"
	case errors.Is(err, ErrPublishConflict):
		code = "conflict"
	case errors.Is(err, ErrRuntimeNotFound):
		code = "not_found"
	}
	c.logger.Printf("identity runtime request failed code=%s status=%d", code, status)
}

func (c *Client) Snapshot(ctx context.Context, realm, alias string) (RuntimeSnapshot, error) {
	if err := validateRuntimeCoordinates(realm, alias); err != nil {
		return RuntimeSnapshot{}, err
	}
	var provider ProviderRepresentation
	err := c.doJSON(ctx, http.MethodGet, providerPath(alias), nil, &provider, http.StatusOK)
	if errors.Is(err, ErrRuntimeNotFound) {
		return RuntimeSnapshot{Realm: RealmName, Alias: alias, Exists: false}, nil
	}
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	var mappers []MapperRepresentation
	if err := c.doJSON(ctx, http.MethodGet, mapperCollectionPath(alias), nil, &mappers, http.StatusOK); err != nil {
		return RuntimeSnapshot{}, err
	}
	digest := ""
	structureDrifted := true
	if provider.Config != nil {
		digest = provider.Config[digestConfigKey]
		expectedStructure := provider.Config[structureDigestConfigKey]
		actualStructure, structureErr := computeRuntimeStructureDigest(provider, mappers)
		if structureErr != nil {
			return RuntimeSnapshot{}, structureErr
		}
		structureDrifted = expectedStructure == "" || actualStructure != expectedStructure
		if !structureDrifted && provider.Config[skipProfileMarkerKey] == "true" {
			// 该身份源声明了「首登不弹资料页」：同时核对 realm 级的实际状态。
			state, stateErr := c.readProfileState(ctx, provider.FirstBrokerLoginFlowAlias)
			if stateErr != nil {
				return RuntimeSnapshot{}, stateErr
			}
			structureDrifted = !state.skipSatisfied()
		}
	}
	return RuntimeSnapshot{
		Realm: RealmName, Alias: alias, Exists: true, Digest: digest,
		StructureDrifted: structureDrifted, Provider: provider, Mappers: mappers,
	}, nil
}

func (c *Client) Apply(ctx context.Context, desired DesiredIdentitySource) error {
	digest, err := verifyDesiredDigest(desired)
	if err != nil {
		return err
	}
	provider := desiredProvider(desired, digest)
	var existing ProviderRepresentation
	err = c.doJSON(ctx, http.MethodGet, providerPath(desired.Alias), nil, &existing, http.StatusOK)
	switch {
	case errors.Is(err, ErrRuntimeNotFound):
		err = c.doJSON(ctx, http.MethodPost, providerCollectionPath(), provider, nil,
			http.StatusCreated, http.StatusNoContent)
	case err == nil:
		err = c.doJSON(ctx, http.MethodPut, providerPath(desired.Alias), provider, nil,
			http.StatusOK, http.StatusNoContent)
	}
	if err != nil {
		return err
	}
	if err := c.syncManagedMappers(ctx, desired.Alias, desired.ClaimMappings); err != nil {
		return err
	}
	if desired.SkipProfileReview {
		// realm 级共享设置：只在开启时写入，关闭该选项不会回滚（别的身份源可能依赖）。
		return c.applySkipProfileReview(ctx, provider.FirstBrokerLoginFlowAlias)
	}
	return nil
}

func desiredProvider(desired DesiredIdentitySource, digest string) ProviderRepresentation {
	config := map[string]string{
		"issuer":            desired.Endpoints.Issuer,
		"authorizationUrl":  desired.Endpoints.Authorization,
		"tokenUrl":          desired.Endpoints.Token,
		"jwksUrl":           desired.Endpoints.JWKS,
		"clientId":          desired.ClientID,
		"clientSecret":      desired.ClientSecret,
		"defaultScope":      strings.Join(normalizedScopes(desired.Scopes), " "),
		"useJwksUrl":        "true",
		"validateSignature": "true",
		"syncMode":          "IMPORT",
		"pkceEnabled":       "true",
		"pkceMethod":        "S256",
		digestConfigKey:     digest,
	}
	if NormalizeSignatureMode(desired.SignatureMode) == SignatureModeNone {
		// 不校验 id_token 签名（HS256/无 kid 等 Keycloak 无法按 JWKS 验签的 IdP）。
		config["validateSignature"] = "false"
		if desired.Endpoints.JWKS == "" {
			config["useJwksUrl"] = "false"
			delete(config, "jwksUrl")
		}
	}
	if desired.SkipProfileReview {
		config[skipProfileMarkerKey] = "true"
	}
	if desired.Endpoints.UserInfo != "" {
		config["userInfoUrl"] = desired.Endpoints.UserInfo
	}
	if desired.Endpoints.EndSession != "" {
		config["logoutUrl"] = desired.Endpoints.EndSession
	}
	provider := ProviderRepresentation{
		Alias: desired.Alias, DisplayName: strings.TrimSpace(desired.DisplayName), ProviderID: "oidc",
		Enabled: true, TrustEmail: false, StoreToken: false, AddReadTokenRoleOnCreate: false,
		LinkOnly: false, HideOnLogin: false, Config: config,
	}
	mappers := make([]MapperRepresentation, 0, len(desired.ClaimMappings))
	for _, mapping := range desired.ClaimMappings {
		mappers = append(mappers, managedMapper(desired.Alias, mapping))
	}
	structureDigest, _ := computeRuntimeStructureDigest(provider, mappers)
	provider.Config[structureDigestConfigKey] = structureDigest
	return provider
}

func normalizedScopes(scopes []string) []string {
	unique := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			unique[scope] = struct{}{}
		}
	}
	out := make([]string, 0, len(unique))
	for scope := range unique {
		out = append(out, scope)
	}
	sort.Strings(out)
	return out
}

func managedMapper(alias string, mapping ClaimMapping) MapperRepresentation {
	return MapperRepresentation{
		Name:                   managedMapperPrefix + mapping.UserAttribute,
		IdentityProviderAlias:  alias,
		IdentityProviderMapper: "oidc-user-attribute-idp-mapper",
		Config: map[string]string{
			"claim":          mapping.Claim,
			"user.attribute": mapping.UserAttribute,
			"syncMode":       "INHERIT",
		},
	}
}

func (c *Client) syncManagedMappers(ctx context.Context, alias string, mappings []ClaimMapping) error {
	var existing []MapperRepresentation
	if err := c.doJSON(ctx, http.MethodGet, mapperCollectionPath(alias), nil, &existing, http.StatusOK); err != nil {
		return err
	}
	existingByName := make(map[string]MapperRepresentation, len(existing))
	duplicates := make([]MapperRepresentation, 0)
	for _, mapper := range existing {
		if !strings.HasPrefix(mapper.Name, managedMapperPrefix) {
			continue
		}
		if previous, exists := existingByName[mapper.Name]; exists {
			duplicates = append(duplicates, previous)
		}
		existingByName[mapper.Name] = mapper
	}
	desired := make([]MapperRepresentation, 0, len(mappings))
	for _, mapping := range mappings {
		desired = append(desired, managedMapper(alias, mapping))
	}
	sort.Slice(desired, func(i, j int) bool { return desired[i].Name < desired[j].Name })
	for _, mapper := range desired {
		current, exists := existingByName[mapper.Name]
		if !exists {
			if err := c.doJSON(ctx, http.MethodPost, mapperCollectionPath(alias), mapper, nil,
				http.StatusOK, http.StatusCreated, http.StatusNoContent); err != nil {
				return err
			}
			continue
		}
		if !validRuntimeObjectID(current.ID) {
			return ErrRuntimeRejected
		}
		mapper.ID = current.ID
		path := mapperCollectionPath(alias) + "/" + url.PathEscape(current.ID)
		if err := c.doJSON(ctx, http.MethodPut, path, mapper, nil, http.StatusOK, http.StatusNoContent); err != nil {
			return err
		}
		delete(existingByName, mapper.Name)
	}
	staleMappers := make([]MapperRepresentation, 0, len(existingByName)+len(duplicates))
	for _, stale := range existingByName {
		staleMappers = append(staleMappers, stale)
	}
	staleMappers = append(staleMappers, duplicates...)
	for _, stale := range staleMappers {
		if !validRuntimeObjectID(stale.ID) {
			return ErrRuntimeRejected
		}
		path := mapperCollectionPath(alias) + "/" + url.PathEscape(stale.ID)
		if err := c.doJSON(ctx, http.MethodDelete, path, nil, nil, http.StatusOK, http.StatusNoContent); err != nil {
			return err
		}
	}
	return nil
}

func validRuntimeObjectID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func (c *Client) Restore(ctx context.Context, snapshot RuntimeSnapshot) error {
	if err := validateRuntimeCoordinates(snapshot.Realm, snapshot.Alias); err != nil {
		return err
	}
	if !snapshot.Exists {
		err := c.doJSON(ctx, http.MethodDelete, providerPath(snapshot.Alias), nil, nil, http.StatusOK, http.StatusNoContent)
		if errors.Is(err, ErrRuntimeNotFound) {
			return nil
		}
		return err
	}
	if snapshot.Provider.Alias != snapshot.Alias || snapshot.Provider.ProviderID != "oidc" {
		return ErrInvalidDesiredSource
	}
	var current ProviderRepresentation
	err := c.doJSON(ctx, http.MethodGet, providerPath(snapshot.Alias), nil, &current, http.StatusOK)
	if errors.Is(err, ErrRuntimeNotFound) {
		err = c.doJSON(ctx, http.MethodPost, providerCollectionPath(), snapshot.Provider, nil,
			http.StatusCreated, http.StatusNoContent)
	} else if err == nil {
		err = c.doJSON(ctx, http.MethodPut, providerPath(snapshot.Alias), snapshot.Provider, nil,
			http.StatusOK, http.StatusNoContent)
	}
	if err != nil {
		return err
	}
	return c.replaceAllMappers(ctx, snapshot.Alias, snapshot.Mappers)
}

func (c *Client) replaceAllMappers(ctx context.Context, alias string, desired []MapperRepresentation) error {
	var current []MapperRepresentation
	if err := c.doJSON(ctx, http.MethodGet, mapperCollectionPath(alias), nil, &current, http.StatusOK); err != nil {
		return err
	}
	for _, mapper := range current {
		if !validRuntimeObjectID(mapper.ID) {
			return ErrRuntimeRejected
		}
		path := mapperCollectionPath(alias) + "/" + url.PathEscape(mapper.ID)
		if err := c.doJSON(ctx, http.MethodDelete, path, nil, nil, http.StatusOK, http.StatusNoContent); err != nil {
			return err
		}
	}
	for _, mapper := range desired {
		if mapper.IdentityProviderAlias != alias {
			return ErrInvalidDesiredSource
		}
		mapper.ID = ""
		if err := c.doJSON(ctx, http.MethodPost, mapperCollectionPath(alias), mapper, nil,
			http.StatusOK, http.StatusCreated, http.StatusNoContent); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) Disable(ctx context.Context, realm, alias string) error {
	if err := validateRuntimeCoordinates(realm, alias); err != nil {
		return err
	}
	var provider ProviderRepresentation
	if err := c.doJSON(ctx, http.MethodGet, providerPath(alias), nil, &provider, http.StatusOK); err != nil {
		return err
	}
	provider.Enabled = false
	return c.doJSON(ctx, http.MethodPut, providerPath(alias), provider, nil, http.StatusOK, http.StatusNoContent)
}

func (c *Client) Status(ctx context.Context, realm, alias string) (RuntimeStatus, error) {
	snapshot, err := c.Snapshot(ctx, realm, alias)
	if err != nil {
		return RuntimeStatus{}, err
	}
	return RuntimeStatus{
		Exists: snapshot.Exists, Enabled: snapshot.Provider.Enabled,
		Digest: snapshot.Digest, Drifted: snapshot.StructureDrifted,
	}, nil
}
