package consolesso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxTokenResponseBytes = 64 << 10
	tokenTimeout          = 10 * time.Second
)

var (
	errAccountNotLinked = errors.New("console sso: identity not linked to a console account")
	errAccountAmbiguous = errors.New("console sso: identity linked to multiple accounts")
)

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("console sso: crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorizeURL 构造授权码 + PKCE(S256) 请求。
func (c Config) authorizeURL(state, nonce, verifier string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", c.RedirectURL)
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", pkceChallenge(verifier))
	q.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(c.AuthorizeURL, "?") {
		sep = "&"
	}
	return c.AuthorizeURL + sep + q.Encode()
}

// exchangeCode 用授权码换 id_token（client_secret_basic）。不跟随重定向。
func exchangeCode(ctx context.Context, client *http.Client, c Config, code, verifier string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, tokenTimeout)
	defer cancel()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.RedirectURL)
	form.Set("code_verifier", verifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("console sso: token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil || len(body) > maxTokenResponseBytes {
		return "", errors.New("console sso: token response unreadable")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("console sso: token endpoint status %d", resp.StatusCode)
	}
	var tok struct {
		IDToken   string `json:"id_token"`
		TokenType string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		return "", errors.New("console sso: token response has no id_token")
	}
	return tok.IDToken, nil
}

// newHTTPClient：有超时、不跟随重定向（防止 token/JWKS 请求被 30x 引到别处）。
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: tokenTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// SubjectResolver 把 IdP 主体映射到已存在的控制台账号。只查绑定关系，
// 绝不按 email/用户名匹配（可被 IdP 侧改写），也不自动建号。
type SubjectResolver interface {
	ResolveConsoleSubject(ctx context.Context, issuer, subject string) (tenantID, userID string, err error)
}

// ProviderSubjectResolver（W9 9.3）按协议类型查绑定：CAS/企业微信主体只在
// user_identity_links.source_type = 'cas' / 'wecom' 的绑定里查，不会与 OIDC 主体混用。
type ProviderSubjectResolver interface {
	ResolveProviderSubject(ctx context.Context, sourceType, issuer, subject string) (tenantID, userID string, err error)
}

type pgSubjectResolver struct{ db *pgxpool.Pool }

func (r *pgSubjectResolver) ResolveProviderSubject(ctx context.Context, sourceType, issuer, subject string) (string, string, error) {
	if sourceType != ProviderCAS && sourceType != ProviderWeCom {
		return "", "", errAccountNotLinked
	}
	return r.resolve(ctx, `
		SELECT DISTINCT tenant_id, user_id
		FROM user_identity_links
		WHERE issuer=$1 AND source_type=$3 AND external_subject=$2
		LIMIT 2
	`, strings.TrimSuffix(issuer, "/"), subject, sourceType)
}

// NewPGSubjectResolver 按 user_identity_links(issuer, source_type in local/oidc, external_subject) 查找。
func NewPGSubjectResolver(db *pgxpool.Pool) SubjectResolver { return &pgSubjectResolver{db: db} }

func (r *pgSubjectResolver) ResolveConsoleSubject(ctx context.Context, issuer, subject string) (string, string, error) {
	return r.resolve(ctx, `
		SELECT DISTINCT tenant_id, user_id
		FROM user_identity_links
		WHERE issuer=$1 AND source_type IN ('local','oidc') AND external_subject=$2
		LIMIT 2
	`, strings.TrimSuffix(issuer, "/"), subject)
}

func (r *pgSubjectResolver) resolve(ctx context.Context, query string, args ...any) (string, string, error) {
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return "", "", fmt.Errorf("console sso: resolve subject: %w", err)
	}
	defer rows.Close()
	var tenantID, userID string
	n := 0
	for rows.Next() {
		if err := rows.Scan(&tenantID, &userID); err != nil {
			return "", "", err
		}
		n++
	}
	if err := rows.Err(); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", "", err
	}
	switch n {
	case 0:
		return "", "", errAccountNotLinked
	case 1:
		return tenantID, userID, nil
	default:
		return "", "", errAccountAmbiguous
	}
}
