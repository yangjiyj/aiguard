package directoryldap

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
)

var (
	ErrInsecureTransport = errors.New("directory connection must use ldaps or ldap with StartTLS")
	ErrInvalidTarget     = errors.New("directory connection target is invalid")
)

// Transport 由连接地址的 scheme 决定，不存在明文模式：
//   - ldaps://  隐式 TLS（默认端口 636；AD 全局编录 3269）
//   - ldap://   先 StartTLS 升级并校验证书，之后才发送 bind 凭据（默认端口 389；AD 全局编录 3268）
//
// 原 Config.UseStartTLS 字段从未被读取（死字段），已移除：加密方式只看 scheme，
// 避免出现「ldap:// + UseStartTLS=false」这种明文组合。
type Transport string

const (
	TransportLDAPS    Transport = "ldaps"
	TransportStartTLS Transport = "starttls"
)

const (
	defaultLDAPSPort = "636"
	defaultLDAPPort  = "389"
)

type Config struct {
	ConnectionURL string
}

// TransportFor 返回连接地址对应的加密方式；非 ldap/ldaps 返回 ErrInsecureTransport。
func TransportFor(connectionURL string) (Transport, error) {
	parsed, err := url.Parse(strings.TrimSpace(connectionURL))
	if err != nil {
		return "", ErrInvalidTarget
	}
	switch parsed.Scheme {
	case "ldaps":
		return TransportLDAPS, nil
	case "ldap":
		return TransportStartTLS, nil
	default:
		return "", ErrInsecureTransport
	}
}

// UsesStartTLS 供 Keycloak LDAP provider 组装使用：ldap:// 必须同时下发 startTls=true，
// 否则 Keycloak 会以明文连接并发送 bind 凭据。
func UsesStartTLS(connectionURL string) bool {
	transport, err := TransportFor(connectionURL)
	return err == nil && transport == TransportStartTLS
}

func defaultPortFor(transport Transport) string {
	if transport == TransportStartTLS {
		return defaultLDAPPort
	}
	return defaultLDAPSPort
}

// validPort：十进制、无前导零、1-65535。
func validPort(port string) bool {
	if port == "" || strings.TrimLeft(port, "0123456789") != "" || (len(port) > 1 && port[0] == '0') {
		return false
	}
	value, err := strconv.Atoi(port)
	return err == nil && value >= 1 && value <= 65535
}

func ValidateConfig(config Config) error {
	parsed, err := url.Parse(strings.TrimSpace(config.ConnectionURL))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ErrInvalidTarget
	}
	if _, err := TransportFor(config.ConnectionURL); err != nil {
		return err
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if host == "" || strings.EqualFold(host, "localhost") ||
		egresspolicy.IsMetadataHostname(host) ||
		(ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast())) {
		return ErrInvalidTarget
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return ErrInvalidTarget
	}
	if port := parsed.Port(); port != "" && !validPort(port) {
		return ErrInvalidTarget
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return ErrInvalidTarget
	}
	return nil
}
