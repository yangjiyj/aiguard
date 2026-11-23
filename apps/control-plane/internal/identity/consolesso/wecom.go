package consolesso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// W9 9.3：企业微信（WeCom）扫码/网页授权登录控制台。
//
// 流程：/wecom/login 生成 state 并绑定浏览器 → 302 到企业微信登录页（CorpApp 扫码）
// → 回调 /wecom/callback?code=…&state=… → 服务端用 corpid+secret 取 access_token（缓存，
// 失效自动重取一次）→ /cgi-bin/auth/getuserinfo 换 userid（非企业成员只有 openid，拒绝）
// → 按 user_identity_links(wecom, "wecom:<corpid>", userid) 查已绑定的控制台账号。
//
// userid 在企业内唯一且由企业管理员分配，不按手机号/邮箱/姓名匹配账号。
const (
	WeComLoginPath    = "/admin/v1/auth/sso/wecom/login"
	WeComCallbackPath = "/admin/v1/auth/sso/wecom/callback"

	defaultWeComAuthorizeURL = "https://login.work.weixin.qq.com/wwlogin/sso/login"
	defaultWeComAPIBaseURL   = "https://qyapi.weixin.qq.com"

	maxWeComResponse = 16 << 10
	// access_token 官方有效期 7200s；提前 5 分钟刷新，避免临界过期。
	weComTokenMargin = 5 * time.Minute
)

var (
	weComCorpIDPattern  = regexp.MustCompile(`^[A-Za-z0-9]{6,64}$`)
	weComAgentIDPattern = regexp.MustCompile(`^[0-9]{1,20}$`)
	weComUserIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
)

type WeComConfig struct {
	CorpID  string
	AgentID string
	Secret  string
	// RedirectURL 指向 /admin/v1/auth/sso/wecom/callback；其域名须登记为应用的"可信域名/授权回调域"。
	RedirectURL string
	// AuthorizeURL / APIBaseURL 默认是企业微信公网地址；私有化部署或测试时可覆盖。
	AuthorizeURL string
	APIBaseURL   string
}

func (c WeComConfig) String() string {
	return "consolesso.WeComConfig{CorpID:" + c.CorpID + " AgentID:" + c.AgentID + " Secret:[redacted]}"
}

func (c WeComConfig) GoString() string { return c.String() }

func (c WeComConfig) authorizeBase() string {
	if v := strings.TrimSpace(c.AuthorizeURL); v != "" {
		return v
	}
	return defaultWeComAuthorizeURL
}

func (c WeComConfig) apiBase() string {
	if v := strings.TrimSuffix(strings.TrimSpace(c.APIBaseURL), "/"); v != "" {
		return v
	}
	return defaultWeComAPIBaseURL
}

// Issuer 是绑定关系里的 issuer：userid 只在同一企业内唯一，故以 corpid 区分。
func (c WeComConfig) Issuer() string { return "wecom:" + c.CorpID }

var errWeComNotConfigured = errors.New("console sso: wecom not configured")

// Validate：secret 走 API 调用，API 地址在 secure 模式下必须 https。
func (c WeComConfig) Validate(secure bool) error {
	if !weComCorpIDPattern.MatchString(c.CorpID) || !weComAgentIDPattern.MatchString(c.AgentID) ||
		strings.TrimSpace(c.Secret) == "" {
		return errWeComNotConfigured
	}
	for _, raw := range []string{c.RedirectURL, c.authorizeBase(), c.apiBase()} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" ||
			(u.Scheme != "https" && u.Scheme != "http") || (secure && u.Scheme != "https") {
			return errWeComNotConfigured
		}
	}
	return nil
}

func (c WeComConfig) loginURL(state string) string {
	q := url.Values{}
	q.Set("login_type", "CorpApp")
	q.Set("appid", c.CorpID)
	q.Set("agentid", c.AgentID)
	q.Set("redirect_uri", c.RedirectURL)
	q.Set("state", state)
	sep := "?"
	if strings.Contains(c.authorizeBase(), "?") {
		sep = "&"
	}
	return c.authorizeBase() + sep + q.Encode()
}

type weComClient struct {
	cfg  WeComConfig
	http *http.Client
	now  func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newWeComClient(c WeComConfig, client *http.Client, now func() time.Time) *weComClient {
	return &weComClient{cfg: c, http: client, now: now}
}

var (
	errWeComRejected  = errors.New("console sso: wecom code rejected")
	errWeComNotMember = errors.New("console sso: wecom user is not a corp member")
)

// 企业微信 access_token 失效类错误码：40014 不合法、42001 过期、40001 secret 错/失效。
func weComTokenInvalid(code int) bool { return code == 40014 || code == 42001 || code == 40001 }

func (c *weComClient) getJSON(ctx context.Context, endpoint string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, tokenTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("console sso: wecom request: %w", unwrapURLError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWeComResponse+1))
	if err != nil || len(body) > maxWeComResponse {
		return errors.New("console sso: wecom response unreadable")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("console sso: wecom status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return errors.New("console sso: wecom response malformed")
	}
	return nil
}

func (c *weComClient) accessToken(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && c.now().Before(c.expires) {
		return c.token, nil
	}
	var out struct {
		ErrCode     int    `json:"errcode"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	endpoint := c.cfg.apiBase() + "/cgi-bin/gettoken?" + url.Values{
		"corpid": {c.cfg.CorpID}, "corpsecret": {c.cfg.Secret},
	}.Encode()
	if err := c.getJSON(ctx, endpoint, &out); err != nil {
		return "", err
	}
	if out.ErrCode != 0 || out.AccessToken == "" {
		c.token = ""
		return "", fmt.Errorf("console sso: wecom gettoken errcode=%d", out.ErrCode)
	}
	ttl := time.Duration(out.ExpiresIn)*time.Second - weComTokenMargin
	if ttl < time.Minute {
		ttl = time.Minute
	}
	c.token, c.expires = out.AccessToken, c.now().Add(ttl)
	return c.token, nil
}

// userID 用 code 换企业成员 userid；access_token 失效时强制重取一次后重试。
func (c *weComClient) userID(ctx context.Context, code string) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := c.accessToken(ctx, attempt > 0)
		if err != nil {
			return "", err
		}
		var out struct {
			ErrCode int    `json:"errcode"`
			UserID  string `json:"userid"`
			// 旧接口 /cgi-bin/user/getuserinfo 字段名为 UserId。
			LegacyUserID string `json:"UserId"`
			OpenID       string `json:"openid"`
		}
		endpoint := c.cfg.apiBase() + "/cgi-bin/auth/getuserinfo?" + url.Values{
			"access_token": {tok}, "code": {code},
		}.Encode()
		if err := c.getJSON(ctx, endpoint, &out); err != nil {
			return "", err
		}
		if weComTokenInvalid(out.ErrCode) && attempt == 0 {
			continue
		}
		if out.ErrCode != 0 {
			return "", fmt.Errorf("%w: errcode=%d", errWeComRejected, out.ErrCode)
		}
		uid := out.UserID
		if uid == "" {
			uid = out.LegacyUserID
		}
		if uid == "" {
			return "", errWeComNotMember
		}
		if !weComUserIDPattern.MatchString(uid) {
			return "", fmt.Errorf("%w: malformed userid", errWeComRejected)
		}
		return uid, nil
	}
	return "", fmt.Errorf("%w: access token rejected", errWeComRejected)
}

// WeComLogin GET /admin/v1/auth/sso/wecom/login
func (s *Service) WeComLogin(w http.ResponseWriter, r *http.Request) {
	if s.wecom == nil {
		http.NotFound(w, r)
		return
	}
	state, binding := randomToken(), randomToken()
	if err := s.store.putState(r.Context(), state, flowState{
		Provider: ProviderWeCom, BindingHash: hashHex(binding),
	}); err != nil {
		s.fail(w, r, "unavailable")
		return
	}
	s.setBinding(w, binding)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, s.wecom.cfg.loginURL(state), http.StatusFound)
}

// WeComCallback GET /admin/v1/auth/sso/wecom/callback?code=…&state=…[&appid=…]
func (s *Service) WeComCallback(w http.ResponseWriter, r *http.Request) {
	if s.wecom == nil {
		http.NotFound(w, r)
		return
	}
	s.clearBinding(w)
	q := r.URL.Query()
	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" || len(state) > 256 || len(code) > 512 {
		s.fail(w, r, "invalid_request")
		return
	}
	// 回调带 appid 时必须是本企业（防止别家企业应用的 code 被引到这里）。
	if appid := q.Get("appid"); appid != "" && appid != s.wecom.cfg.CorpID {
		s.fail(w, r, "invalid_request")
		return
	}
	if !s.takeBoundState(w, r, state, ProviderWeCom) {
		return
	}
	uid, err := s.wecom.userID(r.Context(), code)
	if err != nil {
		log.Printf("component=console_sso provider=wecom stage=userinfo error_code=code_invalid err=%v", err)
		switch {
		case errors.Is(err, errWeComNotMember):
			s.fail(w, r, "not_console_user")
		case errors.Is(err, errWeComRejected):
			s.fail(w, r, "invalid_token")
		default:
			s.fail(w, r, "idp_unavailable")
		}
		return
	}
	s.completeLogin(w, r, ProviderWeCom, s.wecom.cfg.Issuer(), uid)
}
