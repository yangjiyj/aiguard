package localidentity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	defaultRequestTimeout  = 10 * time.Second
	defaultMaxResponseSize = int64(1 << 20)
)

var (
	ErrInvalidConfig          = errors.New("invalid local identity configuration")
	ErrInvalidInput           = errors.New("invalid local identity input")
	ErrUnavailable            = errors.New("local identity service unavailable")
	ErrUnauthorized           = errors.New("local identity service unauthorized")
	ErrRejected               = errors.New("local identity service rejected request")
	ErrConflict               = errors.New("local identity user conflict")
	ErrNotFound               = errors.New("local identity object not found")
	ErrReconciliationRequired = errors.New("local identity synchronization incomplete")
	ErrResponseTooLarge       = errors.New("local identity response too large")
)

type Client interface {
	CreateUser(ctx context.Context, in CreateUserInput) (externalSubject string, err error)
	SetEnabled(ctx context.Context, externalSubject string, enabled bool) error
	ResetPassword(ctx context.Context, externalSubject, password string, temporary bool) error
	DeleteUser(ctx context.Context, externalSubject string) error
}

type CreateUserInput struct {
	Username  string
	Email     string
	Password  string
	Temporary bool
}

type ProvisionInput struct {
	ID                 string
	TenantID           string
	Username           string
	Email              string
	Phone              string
	PasswordHash       string
	MustChangePassword bool
	Role               string
	Status             string
	DepartmentID       string
	DepartmentName     string
	AssignmentMode     string
	AssignmentSource   string
	ExternalSubject    string
	ActorID            string
}

type EmergencyDemotionInput struct {
	TenantID        string
	UserID          string
	ExternalSubject string
	PasswordHash    string
	Role            string
	DepartmentID    string
	ActorID         string
}

type StatusTransitionInput struct {
	TenantID string
	UserID   string
	Status   string
	ActorID  string
}

type ReconciliationInput struct {
	ID                 string
	TenantID           string
	UserID             string
	ActorID            string
	Reason             string
	SubjectFingerprint string
	Operation          string
	Stage              string
	Provider           string
	Source             string
}

type Provisioner interface {
	Provision(context.Context, ProvisionInput) error
	Activate(ctx context.Context, tenantID, userID string) error
	MarkReconciliationRequired(context.Context, ReconciliationInput) error
	DeleteProvisioned(ctx context.Context, tenantID, userID string) error
	ExternalSubject(ctx context.Context, tenantID, userID string) (string, error)
	UpdatePasswordHash(
		ctx context.Context,
		tenantID, userID, passwordHash string,
		mustChangePassword bool,
	) error
}

type Config struct {
	BaseURL          string
	Realm            string
	ClientID         string
	ClientSecret     string
	HTTPClient       *http.Client
	RequestTimeout   time.Duration
	MaxResponseBytes int64
}

type HTTPClient struct {
	baseURL          *url.URL
	realm            string
	clientID         string
	clientSecret     string
	httpClient       *http.Client
	requestTimeout   time.Duration
	maxResponseBytes int64
}

var _ Client = (*HTTPClient)(nil)

var realmPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func NewClient(cfg Config) (*HTTPClient, error) {
	baseURL, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil || baseURL.Hostname() == "" ||
		(baseURL.Scheme != "http" && baseURL.Scheme != "https") ||
		baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" ||
		!realmPattern.MatchString(strings.TrimSpace(cfg.Realm)) ||
		strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, ErrInvalidConfig
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = defaultMaxResponseSize
	}
	if cfg.HTTPClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		cfg.HTTPClient = &http.Client{Transport: transport}
	}
	httpClient := *cfg.HTTPClient
	httpClient.Timeout = cfg.RequestTimeout
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/")
	return &HTTPClient{
		baseURL: baseURL, realm: strings.TrimSpace(cfg.Realm),
		clientID: cfg.ClientID, clientSecret: cfg.ClientSecret,
		httpClient: &httpClient, requestTimeout: cfg.RequestTimeout,
		maxResponseBytes: cfg.MaxResponseBytes,
	}, nil
}

func (c *HTTPClient) CreateUser(ctx context.Context, in CreateUserInput) (string, error) {
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.TrimSpace(in.Email)
	if in.Username == "" || in.Password == "" {
		return "", ErrInvalidInput
	}
	payload := struct {
		Username    string               `json:"username"`
		Email       string               `json:"email,omitempty"`
		Enabled     bool                 `json:"enabled"`
		Credentials []passwordCredential `json:"credentials"`
	}{
		Username: in.Username,
		Email:    in.Email,
		Enabled:  false,
		Credentials: []passwordCredential{{
			Type: "password", Value: in.Password, Temporary: in.Temporary,
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", ErrRejected
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return "", err
	}
	resp, _, location, err := c.do(ctx, http.MethodPost, c.usersPath(), body, "application/json", token, http.StatusCreated)
	if err != nil {
		return "", err
	}
	_ = resp
	externalSubject, err := c.subjectFromLocation(location)
	if err != nil {
		return "", err
	}
	return externalSubject, nil
}

func (c *HTTPClient) SetEnabled(ctx context.Context, externalSubject string, enabled bool) error {
	userPath, err := c.userPath(externalSubject)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		Enabled bool `json:"enabled"`
	}{Enabled: enabled})
	if err != nil {
		return ErrRejected
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	_, _, _, err = c.do(ctx, http.MethodPut, userPath, payload, "application/json", token, http.StatusNoContent)
	return err
}

func (c *HTTPClient) ResetPassword(
	ctx context.Context,
	externalSubject, password string,
	temporary bool,
) error {
	userPath, err := c.userPath(externalSubject)
	if err != nil || password == "" {
		return ErrInvalidInput
	}
	payload, err := json.Marshal(passwordCredential{
		Type: "password", Value: password, Temporary: temporary,
	})
	if err != nil {
		return ErrRejected
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	_, _, _, err = c.do(
		ctx, http.MethodPut, userPath+"/reset-password", payload,
		"application/json", token, http.StatusNoContent,
	)
	return err
}

func (c *HTTPClient) DeleteUser(ctx context.Context, externalSubject string) error {
	userPath, err := c.userPath(externalSubject)
	if err != nil {
		return err
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	_, _, _, err = c.do(ctx, http.MethodDelete, userPath, nil, "", token, http.StatusNoContent)
	// 删除已不存在的 subject 视为成功（幂等）：调用方据此判定补偿完成，
	// 不再误标 reconciliation_required 污染状态。
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

type passwordCredential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

func (c *HTTPClient) accessToken(ctx context.Context) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	body, _, _, err := c.do(
		ctx,
		http.MethodPost,
		"/realms/"+url.PathEscape(c.realm)+"/protocol/openid-connect/token",
		[]byte(form.Encode()),
		"application/x-www-form-urlencoded",
		"",
		http.StatusOK,
	)
	if err != nil {
		return "", err
	}
	var response struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &response); err != nil || strings.TrimSpace(response.AccessToken) == "" {
		return "", ErrUnauthorized
	}
	return response.AccessToken, nil
}

func (c *HTTPClient) usersPath() string {
	return "/admin/realms/" + url.PathEscape(c.realm) + "/users"
}

func (c *HTTPClient) userPath(externalSubject string) (string, error) {
	externalSubject = strings.TrimSpace(externalSubject)
	if externalSubject == "" {
		return "", ErrInvalidInput
	}
	return c.usersPath() + "/" + url.PathEscape(externalSubject), nil
}

func (c *HTTPClient) subjectFromLocation(rawLocation string) (string, error) {
	location, err := url.Parse(strings.TrimSpace(rawLocation))
	if err != nil || location.RawQuery != "" || location.Fragment != "" {
		return "", ErrRejected
	}
	if location.IsAbs() && (location.Scheme != c.baseURL.Scheme || location.Host != c.baseURL.Host) {
		return "", ErrRejected
	}
	prefix := strings.TrimSuffix(c.baseURL.Path, "/") + c.usersPath() + "/"
	if !strings.HasPrefix(location.EscapedPath(), prefix) {
		return "", ErrRejected
	}
	externalSubject, err := url.PathUnescape(path.Base(location.EscapedPath()))
	if err != nil || strings.TrimSpace(externalSubject) == "" || externalSubject == "." || externalSubject == "/" {
		return "", ErrRejected
	}
	return externalSubject, nil
}

func (c *HTTPClient) do(
	ctx context.Context,
	method, relativePath string,
	payload []byte,
	contentType, token string,
	expectedStatus int,
) ([]byte, int, string, error) {
	target := *c.baseURL
	escapedPath := strings.TrimSuffix(c.baseURL.EscapedPath(), "/") + "/" + strings.TrimPrefix(relativePath, "/")
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return nil, 0, "", ErrInvalidInput
	}
	target.Path = decodedPath
	target.RawPath = escapedPath
	requestCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, target.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, 0, "", ErrUnavailable
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, "", ctx.Err()
		}
		return nil, 0, "", ErrUnavailable
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, "", ErrUnavailable
	}
	if int64(len(body)) > c.maxResponseBytes {
		return nil, resp.StatusCode, "", ErrResponseTooLarge
	}
	if resp.StatusCode != expectedStatus {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, resp.StatusCode, "", ErrNotFound
		case http.StatusUnauthorized, http.StatusForbidden:
			return nil, resp.StatusCode, "", ErrUnauthorized
		case http.StatusConflict:
			return nil, resp.StatusCode, "", ErrConflict
		default:
			return nil, resp.StatusCode, "", ErrRejected
		}
	}
	return body, resp.StatusCode, resp.Header.Get("Location"), nil
}

func (c *HTTPClient) String() string {
	if c == nil {
		return "localidentity.HTTPClient<nil>"
	}
	return fmt.Sprintf("localidentity.HTTPClient{BaseURL:%q Realm:%q ClientID:%q Credentials:[redacted]}",
		c.baseURL.String(), c.realm, c.clientID)
}

func (c *HTTPClient) GoString() string {
	return c.String()
}
