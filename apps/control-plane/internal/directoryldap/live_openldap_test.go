package directoryldap

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveOpenLDAPTransports（W9 9.4，opt-in）：对真实 OpenLDAP 验证
// ldap://+StartTLS、ldaps:// 默认端口与自定义端口均能 bind + 搜索用户，且证书不可信时 StartTLS 失败。
// 环境变量：
//
//	DIRECTORY_LDAP_LIVE_URLS         逗号分隔的连接地址
//	DIRECTORY_LDAP_LIVE_CA_FILE      私有 CA（PEM）
//	DIRECTORY_LDAP_LIVE_WRONG_CA_FILE 与服务端无关的 CA（PEM），用于负向断言
//	DIRECTORY_LDAP_LIVE_BIND_DN / _BIND_PASSWORD / _USERS_DN
//	DIRECTORY_LDAP_TARGET_ALLOWLIST / DIRECTORY_LDAP_ALLOWED_CIDRS（部署批准策略）
func TestLiveOpenLDAPTransports(t *testing.T) {
	rawURLs := os.Getenv("DIRECTORY_LDAP_LIVE_URLS")
	if rawURLs == "" {
		t.Skip("DIRECTORY_LDAP_LIVE_URLS is not set")
	}
	caPEM, err := os.ReadFile(os.Getenv("DIRECTORY_LDAP_LIVE_CA_FILE"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	wrongCAPEM, err := os.ReadFile(os.Getenv("DIRECTORY_LDAP_LIVE_WRONG_CA_FILE"))
	if err != nil {
		t.Fatalf("read wrong CA: %v", err)
	}
	policy, err := LoadTargetPolicyFromEnvironment()
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	client := Client{Policy: policy}
	for _, url := range strings.Split(rawURLs, ",") {
		url = strings.TrimSpace(url)
		t.Run(url, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			request := TestRequest{
				ConnectionURL: url,
				BindDN:        os.Getenv("DIRECTORY_LDAP_LIVE_BIND_DN"),
				BindPassword:  os.Getenv("DIRECTORY_LDAP_LIVE_BIND_PASSWORD"),
				CACertPEM:     string(caPEM),
			}
			result, err := client.TestConnection(ctx, request)
			if err != nil || !result.Connected || !result.Bound || !result.RootDSE {
				t.Fatalf("TestConnection = %+v, %v", result, err)
			}
			users, err := client.ListUsers(ctx, SyncRequest{
				TestRequest:       request,
				UsersDN:           os.Getenv("DIRECTORY_LDAP_LIVE_USERS_DN"),
				UserFilter:        "(objectClass=inetOrgPerson)",
				StableIDAttribute: "entryUUID",
				UsernameAttribute: "uid",
				EmailAttribute:    "mail",
				NameAttribute:     "cn",
			})
			if err != nil {
				t.Fatalf("ListUsers: %v", err)
			}
			if len(users) < 2 {
				t.Fatalf("expected >=2 users, got %d", len(users))
			}

			wrong := request
			wrong.CACertPEM = string(wrongCAPEM)
			if _, err := client.TestConnection(ctx, wrong); !errors.Is(err, ErrConnectionFailed) {
				t.Fatalf("untrusted CA accepted: %v", err)
			}
		})
	}
}
