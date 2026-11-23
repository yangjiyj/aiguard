package consolesso

import (
	"errors"
	"net/url"
	"strings"
)

// Config 描述控制台 SSO 的协议坐标。
//
// AuthorizeURL 面向浏览器（公网 /sso 入口）；TokenURL、JWKSURL 由 control-plane
// 服务端访问（可以是容器内网地址）。Issuer 必须与 id_token 的 iss 完全一致。
type Config struct {
	Issuer       string
	AuthorizeURL string
	TokenURL     string
	JWKSURL      string
	ClientID     string
	ClientSecret string
	// RedirectURL 是登记在 IdP 客户端上的回调，指向 /admin/v1/auth/sso/callback。
	RedirectURL string
	// LoginPagePath 是控制台登录页；回调成功/失败都带参数跳回这里。
	LoginPagePath string
	CookieSecure  bool
}

var ErrNotConfigured = errors.New("console sso: not configured")

func (c Config) String() string {
	return "consolesso.Config{Issuer:" + c.Issuer + " ClientID:" + c.ClientID + " Credentials:[redacted]}"
}

func (c Config) GoString() string { return c.String() }

// Validate 失败时控制台 SSO 整体关闭（status 返回 enabled=false），本地管理员登录不受影响。
func (c Config) Validate() error {
	if strings.TrimSpace(c.ClientID) == "" || strings.TrimSpace(c.ClientSecret) == "" {
		return ErrNotConfigured
	}
	for _, raw := range []string{c.Issuer, c.AuthorizeURL, c.TokenURL, c.JWKSURL, c.RedirectURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" ||
			(u.Scheme != "https" && u.Scheme != "http") {
			return ErrNotConfigured
		}
	}
	// 浏览器侧地址必须 https，除非部署显式允许明文（与 JJD_SSO_ALLOW_INSECURE_PUBLIC_URL 一致）。
	if c.CookieSecure {
		for _, raw := range []string{c.Issuer, c.AuthorizeURL, c.RedirectURL} {
			if u, _ := url.Parse(raw); u.Scheme != "https" {
				return ErrNotConfigured
			}
		}
	}
	if !strings.HasPrefix(c.loginPage(), "/") || strings.HasPrefix(c.loginPage(), "//") {
		return ErrNotConfigured
	}
	return nil
}

func (c Config) loginPage() string {
	if strings.TrimSpace(c.LoginPagePath) == "" {
		return "/login"
	}
	return c.LoginPagePath
}

// ConfigFromEnv 从部署环境读取配置。IdP 客户端 jjdguard-console 需在 realm 中登记
// （realm 模板归 W3）；未登记或未配置 secret 时 SSO 关闭。
func ConfigFromEnv(getenv func(string) string, publicIssuer, runtimeBaseURL string, allowInsecure bool) Config {
	issuer := strings.TrimSuffix(strings.TrimSpace(publicIssuer), "/")
	runtimeRealm := strings.TrimSuffix(strings.TrimSpace(runtimeBaseURL), "/") + "/realms/" + realmFromIssuer(issuer)
	clientID := strings.TrimSpace(getenv("JJD_CONSOLE_SSO_CLIENT_ID"))
	if clientID == "" {
		clientID = "jjdguard-console"
	}
	return Config{
		Issuer:        issuer,
		AuthorizeURL:  issuer + "/protocol/openid-connect/auth",
		TokenURL:      runtimeRealm + "/protocol/openid-connect/token",
		JWKSURL:       runtimeRealm + "/protocol/openid-connect/certs",
		ClientID:      clientID,
		ClientSecret:  strings.TrimSpace(getenv("JJD_CONSOLE_SSO_CLIENT_SECRET")),
		RedirectURL:   strings.TrimSpace(getenv("JJD_CONSOLE_SSO_REDIRECT_URL")),
		LoginPagePath: strings.TrimSpace(getenv("JJD_CONSOLE_SSO_LOGIN_PATH")),
		CookieSecure:  !allowInsecure && getenv("SESSION_COOKIE_SECURE") != "false",
	}
}

func realmFromIssuer(issuer string) string {
	if i := strings.LastIndex(issuer, "/realms/"); i >= 0 {
		return issuer[i+len("/realms/"):]
	}
	return ""
}

// CASConfigFromEnv（W9 9.3）。JJD_CONSOLE_CAS_BASE_URL 与 JJD_CONSOLE_CAS_SERVICE_URL 都配置时启用。
func CASConfigFromEnv(getenv func(string) string) CASConfig {
	return CASConfig{
		BaseURL:         strings.TrimSpace(getenv("JJD_CONSOLE_CAS_BASE_URL")),
		ValidateBaseURL: strings.TrimSpace(getenv("JJD_CONSOLE_CAS_VALIDATE_URL")),
		ServiceURL:      strings.TrimSpace(getenv("JJD_CONSOLE_CAS_SERVICE_URL")),
		DisplayName:     strings.TrimSpace(getenv("JJD_CONSOLE_CAS_DISPLAY_NAME")),
	}
}

// WeComConfigFromEnv（W9 9.3）。corpid/agentid/secret/回调都配置时启用。
func WeComConfigFromEnv(getenv func(string) string) WeComConfig {
	return WeComConfig{
		CorpID:       strings.TrimSpace(getenv("JJD_CONSOLE_WECOM_CORP_ID")),
		AgentID:      strings.TrimSpace(getenv("JJD_CONSOLE_WECOM_AGENT_ID")),
		Secret:       strings.TrimSpace(getenv("JJD_CONSOLE_WECOM_SECRET")),
		RedirectURL:  strings.TrimSpace(getenv("JJD_CONSOLE_WECOM_REDIRECT_URL")),
		AuthorizeURL: strings.TrimSpace(getenv("JJD_CONSOLE_WECOM_AUTHORIZE_URL")),
		APIBaseURL:   strings.TrimSpace(getenv("JJD_CONSOLE_WECOM_API_BASE_URL")),
	}
}
