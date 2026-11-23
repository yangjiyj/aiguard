package portalbaseline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 门户登录安全基线（W3 3.8，决策 D7）：新装由 realm 模板直接生效；已装客户升级不自动改，
// 这里只读比对并给出提示，收紧由部署侧脚本 portal-login-baseline.sh apply 执行（需要身份引擎管理员）。
//
// 读取使用身份运行态服务账号（bootstrap 授予 view-realm），不申请额外权限。

// Target 与 deploy/docker-compose/chat/keycloak-realm/realm-jjdguard.json 保持一致（有契约测试）。
var Target = map[string]any{
	"sslRequired":           "external",
	"bruteForceProtected":   true,
	"permanentLockout":      false,
	"failureFactor":         float64(5),
	"waitIncrementSeconds":  float64(1800),
	"maxFailureWaitSeconds": float64(1800),
	"maxDeltaTimeSeconds":   float64(1800),
	"passwordPolicy":        "length(12) and upperCase(1) and lowerCase(1) and digits(1) and notUsername(undefined) and passwordHistory(5)",
	"ssoSessionIdleTimeout": float64(1800),
	"ssoSessionMaxLifespan": float64(43200),
}

// Keys 固定输出顺序。
var Keys = []string{
	"sslRequired", "bruteForceProtected", "permanentLockout", "failureFactor", "waitIncrementSeconds",
	"maxFailureWaitSeconds", "maxDeltaTimeSeconds", "passwordPolicy", "ssoSessionIdleTimeout", "ssoSessionMaxLifespan",
}

type Item struct {
	Key       string `json:"key"`
	Current   any    `json:"current"`
	Target    any    `json:"target"`
	Compliant bool   `json:"compliant"`
}

type Report struct {
	Status    string `json:"status"` // compliant | not_compliant | unavailable
	Items     []Item `json:"items,omitempty"`
	CheckedAt string `json:"checked_at"`
	Message   string `json:"message,omitempty"`
	ApplyHint string `json:"apply_hint,omitempty"`
}

const ApplyHint = "sudo bash <安装目录>/deploy/docker-compose/chat/portal-login-baseline.sh check 查看冲突后，确认执行 apply --yes"

// Evaluate 比对 realm 表示与目标值。缺失字段按 Keycloak 默认值处理（未设置 passwordPolicy = 空）。
func Evaluate(realm map[string]any, now time.Time) Report {
	report := Report{Status: "compliant", CheckedAt: now.UTC().Format(time.RFC3339)}
	for _, key := range Keys {
		target := Target[key]
		current, ok := realm[key]
		if !ok {
			current = nil
		}
		compliant := valuesEqual(key, current, target)
		if !compliant {
			report.Status = "not_compliant"
		}
		report.Items = append(report.Items, Item{Key: key, Current: current, Target: target, Compliant: compliant})
	}
	if report.Status != "compliant" {
		report.Message = "门户登录安全基线未达标"
		report.ApplyHint = ApplyHint
	}
	return report
}

func valuesEqual(key string, current, target any) bool {
	switch t := target.(type) {
	case string:
		c, _ := current.(string)
		if key == "passwordPolicy" {
			return normalizePolicy(c) == normalizePolicy(t)
		}
		return c == t
	case bool:
		c, ok := current.(bool)
		return ok && c == t
	case float64:
		c, ok := current.(float64)
		if !ok {
			return false
		}
		// 更严格也算达标：会话/锁定窗口越短、失败阈值越低越严；等待时长越长越严。
		switch key {
		case "failureFactor", "ssoSessionIdleTimeout", "ssoSessionMaxLifespan":
			return c > 0 && c <= t
		case "waitIncrementSeconds", "maxFailureWaitSeconds", "maxDeltaTimeSeconds":
			return c >= t
		}
		return c == t
	}
	return false
}

// normalizePolicy 忽略子句顺序与空白，要求包含全部目标子句（额外子句视为更严格）。
func normalizePolicy(p string) string {
	parts := strings.Split(p, " and ")
	set := map[string]bool{}
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			set[part] = true
		}
	}
	var required []string
	for _, part := range strings.Split(Target["passwordPolicy"].(string), " and ") {
		if set[part] {
			required = append(required, part)
		}
	}
	return strings.Join(required, " and ")
}

// Fetcher 读取 realm 表示。
type Fetcher interface {
	FetchRealm(ctx context.Context) (map[string]any, error)
}

var ErrUnavailable = errors.New("portal identity runtime unavailable")

// HTTPFetcher 使用 client_credentials 调 Keycloak admin REST 读取 realm。
type HTTPFetcher struct {
	BaseURL      string // 如 http://chat-idp:8180/sso
	Realm        string
	ClientID     string
	ClientSecret string
	HTTP         *http.Client
}

func (f *HTTPFetcher) client() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return &http.Client{Timeout: 5 * time.Second}
}

func (f *HTTPFetcher) FetchRealm(ctx context.Context) (map[string]any, error) {
	if f == nil || f.BaseURL == "" || f.ClientID == "" || f.ClientSecret == "" {
		return nil, ErrUnavailable
	}
	base := strings.TrimRight(f.BaseURL, "/")
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {f.ClientID}, "client_secret": {f.ClientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/realms/"+url.PathEscape(f.Realm)+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&token)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || token.AccessToken == "" {
		return nil, ErrUnavailable
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, base+"/admin/realms/"+url.PathEscape(f.Realm), nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err = f.client().Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	}
	var realm map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&realm); err != nil {
		return nil, ErrUnavailable
	}
	return realm, nil
}
