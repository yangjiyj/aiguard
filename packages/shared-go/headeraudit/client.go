package headeraudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const InternalTokenHeader = "X-JJDGuard-Internal-Token"

var ErrAuditUnavailable = errors.New("header conflict audit unavailable")

type Client struct {
	baseURL string
	secret  string
	http    *http.Client
}

func NewClient(baseURL, secret string) *Client {
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		secret:  strings.TrimSpace(secret),
		http:    &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *Client) WithHTTPClient(client *http.Client) *Client {
	if client != nil {
		c.http = client
	}
	return c
}

func (c *Client) AppendCritical(ctx context.Context, event Event) error {
	if c == nil || c.baseURL == "" || c.secret == "" || c.http == nil {
		return ErrAuditUnavailable
	}
	if err := event.Validate(); err != nil {
		return ErrAuditUnavailable
	}
	body, err := json.Marshal(event)
	if err != nil {
		return ErrAuditUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/internal/v1/header-contract-conflicts", bytes.NewReader(body))
	if err != nil {
		return ErrAuditUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(InternalTokenHeader, c.secret)
	resp, err := c.http.Do(req)
	if err != nil {
		return ErrAuditUnavailable
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusNoContent {
		return ErrAuditUnavailable
	}
	return nil
}
