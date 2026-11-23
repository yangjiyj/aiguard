package config

import (
	"os"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

type Config struct {
	ListenAddr             string
	DatabaseURL            string
	RedisAddr              string
	SecurityEngineURL      string
	ControlPlaneURL        string
	InternalAPISecret      string
	RetentionStorePath     string
	EnvironmentScope       string
	ProxyDefaultTenantID   string
	ProxyWhitelistFailMode string
	// UpstreamEgressProxy 是客户侧出网代理（双层代理第二跳）。空 = 不启用。
	UpstreamEgressProxy string
}

func Load() (*Config, error) {
	return &Config{
		ListenAddr:             getEnv("LISTEN_ADDR", ":3128"),
		DatabaseURL:            getEnv("DATABASE_URL", "postgres://jjdguard:jjdguard@postgres:5432/jjdguard?sslmode=disable"),
		RedisAddr:              getEnv("REDIS_ADDR", "redis:6379"),
		SecurityEngineURL:      getEnv("SECURITY_ENGINE_URL", "http://security-engine:8000"),
		ControlPlaneURL:        getEnv("CONTROL_PLANE_URL", "http://control-plane:8081"),
		InternalAPISecret:      getEnv("JJD_INTERNAL_API_SECRET", getEnv("JJD_PROVIDER_SECRET_KEY", "")),
		RetentionStorePath:     getEnv("RETENTION_STORE_PATH", ""),
		EnvironmentScope:       retentionartifact.NormalizeEnvironmentScope(getEnv("GATEWAY_ENVIRONMENT_SCOPE", retentionartifact.LegacyEnvironmentScope)),
		ProxyDefaultTenantID:   getEnv("PROXY_DEFAULT_TENANT_ID", "tenant_default"),
		ProxyWhitelistFailMode: getEnv("PROXY_WHITELIST_FAIL_MODE", "closed"),
		// 双层代理：客户 PC -> 本代理 -> 客户出网代理 -> 互联网。
		// 默认空 = 不启用，SSRF 防线维持原样。写成 http://host:port。
		UpstreamEgressProxy: getEnv("UPSTREAM_EGRESS_PROXY", ""),
	}, nil
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
