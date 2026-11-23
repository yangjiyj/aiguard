package directoryruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func ComputeDigest(config DirectoryConfig) (string, error) {
	if err := validateDirectoryConfig(config); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(struct {
		Kind          DirectoryKind
		ConnectionURL string
		BindDN        string
		UsersDN       string
	}{
		Kind: config.Kind, ConnectionURL: config.ConnectionURL, BindDN: config.BindDN,
		UsersDN: config.UsersDN,
	})
	if err != nil {
		return "", ErrInvalidDirectoryConfig
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func ComputeComponentDigest(component ComponentRepresentation) (string, error) {
	value := func(key string) (string, bool) {
		values := component.Config[key]
		if len(values) != 1 || values[0] == "" {
			return "", false
		}
		return values[0], true
	}
	vendor, ok := value("vendor")
	if !ok {
		return "", ErrInvalidDirectoryConfig
	}
	kind := KindLDAP
	if vendor == "ad" {
		kind = KindActiveDirectory
	} else if vendor != "other" {
		return "", ErrInvalidDirectoryConfig
	}
	connectionURL, okURL := value("connectionUrl")
	bindDN, okBindDN := value("bindDn")
	usersDN, okUsersDN := value("usersDn")
	if !okURL || !okBindDN || !okUsersDN {
		return "", ErrInvalidDirectoryConfig
	}
	// W9 9.4：ldap:// 目录若在 Keycloak 侧被关掉 startTls（明文 bind），按漂移处理。
	if usesStartTLS(connectionURL) {
		if startTLS, ok := value("startTls"); !ok || startTLS != "true" {
			return "", ErrInvalidDirectoryConfig
		}
	}
	return ComputeDigest(DirectoryConfig{Kind: kind, ConnectionURL: connectionURL, BindDN: bindDN, BindPassword: "not-disclosed", UsersDN: usersDN})
}
