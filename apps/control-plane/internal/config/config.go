package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/buildinfo"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

type Config struct {
	ProductProfile                string
	ProductName                   string
	ProductVersion                string
	ListenAddr                    string
	DatabaseURL                   string
	RedisAddr                     string
	RedisURL                      string
	SecurityEngineURL             string
	GatewayCoreURL                string
	InternalAPISecret             string
	SemanticGatewayAttestationKey string
	MCPConfirmationScopeSecret    string
	PortalAPISecret               string
	LogLevel                      string
	ShutdownTimeout               time.Duration
	BootstrapAdminUsername        string
	BootstrapAdminEmail           string
	BootstrapAdminPassword        string
	BillingEnabled                bool
	BillingMode                   string
	EnvironmentScope              string
	AgentEndpointEnabled          bool
}

const (
	BillingModeOff      = "off"
	BillingModeMetering = "metering"
	BillingModePrepaid  = "prepaid"
)

func Load() (*Config, error) {
	productProfile, err := resolveProductProfile(os.Getenv("PRODUCT_PROFILE"))
	if err != nil {
		return nil, err
	}
	agentEndpointDefault := "false"
	if productProfile == "agent-platform" {
		agentEndpointDefault = "true"
	}
	productName := "JJDGuard"
	productVersion := buildinfo.Current().Version
	if productProfile == "agent-platform" {
		productName = getEnv("PRODUCT_NAME", "JJDGuard Agent Platform")
		productVersion = getEnv("PRODUCT_VERSION", "1.0.0")
	}
	redisURL := getEnv("REDIS_URL", "redis://localhost:6379/0")
	redisAddr := extractRedisAddr(redisURL)
	billingMode, err := resolveBillingMode(
		os.Getenv("BILLING_MODE"),
		strings.EqualFold(strings.TrimSpace(os.Getenv("BILLING_ENABLED")), "true"),
	)
	if err != nil {
		return nil, err
	}

	return &Config{
		ProductProfile:                productProfile,
		ProductName:                   productName,
		ProductVersion:                productVersion,
		ListenAddr:                    getEnv("LISTEN_ADDR", ":8081"),
		DatabaseURL:                   getEnv("DATABASE_URL", "postgres://jjdguard:jjdguard@localhost:5432/jjdguard?sslmode=disable"),
		RedisURL:                      redisURL,
		RedisAddr:                     redisAddr,
		SecurityEngineURL:             getEnv("SECURITY_ENGINE_URL", "http://localhost:8000"),
		GatewayCoreURL:                getEnv("GATEWAY_CORE_URL", "http://gateway-core:8080"),
		InternalAPISecret:             getEnv("JJD_INTERNAL_API_SECRET", getEnv("JJD_PROVIDER_SECRET_KEY", "")),
		SemanticGatewayAttestationKey: getEnv("JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY", ""),
		MCPConfirmationScopeSecret:    getEnv("MCP_CONFIRMATION_SCOPE_SECRET", ""),
		// chat-portal 专用密钥：刻意不 fallback 到 InternalAPISecret——门户密钥泄漏时
		// 不波及 internal/eval 通道；未配置时路由组 503 fail-closed（见 internalSharedSecretMiddleware）。
		PortalAPISecret:        getEnv("JJD_PORTAL_API_SECRET", ""),
		LogLevel:               getEnv("LOG_LEVEL", "info"),
		ShutdownTimeout:        30 * time.Second,
		BootstrapAdminUsername: getEnv("BOOTSTRAP_ADMIN_USERNAME", "admin"),
		BootstrapAdminEmail:    getEnv("BOOTSTRAP_ADMIN_EMAIL", "admin@local"),
		BootstrapAdminPassword: os.Getenv("BOOTSTRAP_ADMIN_PASSWORD"),
		BillingEnabled:         billingMode != BillingModeOff,
		BillingMode:            billingMode,
		EnvironmentScope:       retentionartifact.NormalizeEnvironmentScope(os.Getenv("GATEWAY_ENVIRONMENT_SCOPE")),
		AgentEndpointEnabled:   strings.EqualFold(getEnv("AGENT_ENDPOINT_ENABLED", agentEndpointDefault), "true"),
	}, nil
}

func resolveProductProfile(value string) (string, error) {
	if value == "" {
		return "gateway", nil
	}
	if value != "gateway" && value != "agent-platform" {
		return "", fmt.Errorf("PRODUCT_PROFILE must be gateway or agent-platform")
	}
	return value, nil
}

func resolveBillingMode(value string, legacyEnabled bool) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		if legacyEnabled {
			return BillingModePrepaid, nil
		}
		return BillingModeOff, nil
	}
	switch value {
	case BillingModeOff, BillingModeMetering, BillingModePrepaid:
		return value, nil
	default:
		return "", fmt.Errorf("BILLING_MODE must be off, metering, or prepaid")
	}
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func extractRedisAddr(redisURL string) string {
	// Parse redis://host:port/db format
	if strings.HasPrefix(redisURL, "redis://") {
		addr := strings.TrimPrefix(redisURL, "redis://")
		// Remove database number if present
		parts := strings.Split(addr, "/")
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return redisURL
}
