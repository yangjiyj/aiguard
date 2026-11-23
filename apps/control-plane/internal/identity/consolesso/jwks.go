package consolesso

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	jwksTTL          = 10 * time.Minute
	jwksMinRefresh   = 30 * time.Second
	maxJWKSBytes     = 1 << 20
	minRSAKeyBits    = 2048
	jwksFetchTimeout = 10 * time.Second
)

// ErrUnknownKey：id_token 的 kid 不在 IdP 当前 JWKS 中。
var ErrUnknownKey = errors.New("console sso: signing key not found")

type keySource interface {
	key(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// jwksCache 缓存 IdP 签名公钥。遇到未知 kid 时重新拉取（IdP 轮换密钥），
// 但两次拉取至少间隔 jwksMinRefresh，防止伪造 kid 把请求放大到 IdP。
type jwksCache struct {
	url    string
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

func newJWKSCache(url string, client *http.Client, now func() time.Time) *jwksCache {
	return &jwksCache{url: url, client: client, now: now}
}

func (c *jwksCache) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	age := now.Sub(c.fetchedAt)
	if k, ok := c.keys[kid]; ok && c.keys != nil && age < jwksTTL {
		return k, nil
	}
	if c.keys != nil && age < jwksMinRefresh {
		if k, ok := c.keys[kid]; ok {
			return k, nil
		}
		return nil, ErrUnknownKey
	}
	keys, err := c.fetch(ctx)
	if err != nil {
		// IdP 暂时不可达时，已缓存的同 kid 公钥仍可用；未知 kid 一律拒绝。
		if k, ok := c.keys[kid]; ok {
			return k, nil
		}
		return nil, err
	}
	c.keys, c.fetchedAt = keys, now
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, ErrUnknownKey
}

type jwkDocument struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (c *jwksCache) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("console sso: build jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("console sso: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("console sso: fetch jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("console sso: read jwks: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, errors.New("console sso: jwks too large")
	}
	var doc jwkDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("console sso: parse jwks: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		pub, err := parseRSAKey(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	return keys, nil
}

func parseRSAKey(n64, e64 string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(n64)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(e64)
	if err != nil {
		return nil, err
	}
	if len(eb) == 0 || len(eb) > 4 {
		return nil, errors.New("invalid rsa exponent")
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	n := new(big.Int).SetBytes(nb)
	if e < 3 || e%2 == 0 || n.BitLen() < minRSAKeyBits {
		return nil, errors.New("weak rsa key")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}
