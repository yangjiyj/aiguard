package main

import (
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity/consolesso"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
)

// loadConsoleSSOConfig（W9 9.1）复用身份运行时的公网 issuer 与内网运行时地址：
// 浏览器走公网 /sso，control-plane 换码与取 JWKS 走内网。运行时配置不可用时
// 返回空配置，控制台 SSO 关闭，本地管理员登录不受影响。
func loadConsoleSSOConfig(getenv func(string) string) consolesso.Config {
	allowInsecure := strings.EqualFold(strings.TrimSpace(getenv("JJD_SSO_ALLOW_INSECURE_PUBLIC_URL")), "true")
	cfg, err := identityruntime.LoadConfig(identityruntime.ConfigInput{
		PublicURL:              getenv("JJD_SSO_PUBLIC_URL"),
		RuntimeURL:             getenv("JJD_IDENTITY_RUNTIME_URL"),
		AllowedRuntimeURLs:     getenv("JJD_IDENTITY_RUNTIME_ALLOWED_URLS"),
		ClientID:               getenv("JJD_IDENTITY_RUNTIME_CLIENT_ID"),
		ClientSecret:           getenv("JJD_IDENTITY_RUNTIME_CLIENT_SECRET"),
		AllowInsecurePublicURL: allowInsecure,
	})
	if err != nil {
		return consolesso.Config{}
	}
	return consolesso.ConfigFromEnv(getenv, cfg.IssuerURL, cfg.RuntimeURL, allowInsecure)
}
