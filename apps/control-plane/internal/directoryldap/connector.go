package directoryldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	ErrConnectionFailed = errors.New("directory connection failed")
	ErrBindFailed       = errors.New("directory bind failed")
	ErrRootDSEFailed    = errors.New("directory root dse query failed")
	ErrInvalidCACert    = errors.New("directory CA certificate is invalid")
)

const ldapOperationTimeout = 15 * time.Second

type TestRequest struct {
	ConnectionURL string
	BindDN        string
	BindPassword  string
	CACertPEM     string
	TLSConfig     *tls.Config
}

type TestResult struct {
	Connected bool
	Bound     bool
	RootDSE   bool
}

type SyncRequest struct {
	TestRequest
	UsersDN           string
	UserFilter        string
	StableIDAttribute string
	UsernameAttribute string
	EmailAttribute    string
	NameAttribute     string
}

type DirectoryUser struct {
	ObjectID string
	DN       string
	Username string
	Email    string
	Name     string
}

type Client struct {
	Policy TargetPolicy
	// PolicySource 返回当前生效的策略（控制台改了 LDAP 目标名单后即时生效）；nil 用 Policy。
	PolicySource func(context.Context) TargetPolicy
}

// policy 返回本次连接用的目标策略：有 PolicySource 用它（库内名单），否则用 Policy。
func (client Client) policy(ctx context.Context) TargetPolicy {
	if client.PolicySource != nil {
		return client.PolicySource(ctx)
	}
	return client.Policy
}

func (client Client) TestConnection(ctx context.Context, request TestRequest) (TestResult, error) {
	return TestConnectionWithPolicy(ctx, request, client.policy(ctx))
}

func TestConnection(ctx context.Context, request TestRequest) (TestResult, error) {
	policy, err := LoadTargetPolicyFromEnvironment()
	if err != nil {
		return TestResult{}, ErrInvalidTarget
	}
	return TestConnectionWithPolicy(ctx, request, policy)
}

func TestConnectionWithPolicy(ctx context.Context, request TestRequest, policy TargetPolicy) (TestResult, error) {
	target, err := ValidateConfigWithPolicy(ctx, Config{ConnectionURL: request.ConnectionURL}, policy)
	if err != nil {
		return TestResult{}, err
	}
	if strings.TrimSpace(request.BindDN) == "" || request.BindPassword == "" {
		return TestResult{}, ErrBindFailed
	}
	if err := ctx.Err(); err != nil {
		return TestResult{}, err
	}
	tlsConfig, err := directoryTLSConfig(request, target.Hostname)
	if err != nil {
		return TestResult{}, err
	}
	connection, err := dialPinnedDirectory(ctx, target, tlsConfig)
	if err != nil {
		return TestResult{}, ErrConnectionFailed
	}
	defer connection.Close()
	connection.SetTimeout(ldapOperationTimeout)
	stopCancellation := closeConnectionOnContextCancellation(ctx, connection)
	defer stopCancellation()
	result := TestResult{Connected: true}
	if err := connection.Bind(request.BindDN, request.BindPassword); err != nil {
		return result, ErrBindFailed
	}
	result.Bound = true
	search := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{"supportedLDAPVersion"}, nil)
	if _, err := connection.Search(search); err != nil {
		return result, ErrRootDSEFailed
	}
	result.RootDSE = true
	return result, nil
}

func (client Client) ListUsers(ctx context.Context, request SyncRequest) ([]DirectoryUser, error) {
	if err := ValidateUserFilter(request.UserFilter); err != nil {
		return nil, err
	}
	policy := client.policy(ctx)
	if _, err := TestConnectionWithPolicy(ctx, request.TestRequest, policy); err != nil {
		return nil, err
	}
	if strings.TrimSpace(request.UsersDN) == "" || strings.TrimSpace(request.StableIDAttribute) == "" || strings.TrimSpace(request.UsernameAttribute) == "" {
		return nil, ErrConnectionFailed
	}
	target, err := ValidateConfigWithPolicy(ctx, Config{ConnectionURL: request.ConnectionURL}, policy)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := directoryTLSConfig(request.TestRequest, target.Hostname)
	if err != nil {
		return nil, err
	}
	connection, err := dialPinnedDirectory(ctx, target, tlsConfig)
	if err != nil {
		return nil, ErrConnectionFailed
	}
	defer connection.Close()
	connection.SetTimeout(ldapOperationTimeout)
	stopCancellation := closeConnectionOnContextCancellation(ctx, connection)
	defer stopCancellation()
	if err := connection.Bind(request.BindDN, request.BindPassword); err != nil {
		return nil, ErrBindFailed
	}
	filter := strings.TrimSpace(request.UserFilter)
	if filter == "" {
		filter = "(objectClass=person)"
	}
	attributes := []string{request.StableIDAttribute, request.UsernameAttribute, request.EmailAttribute, request.NameAttribute}
	search := ldap.NewSearchRequest(request.UsersDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false, filter, attributes, nil)
	result, err := connection.Search(search)
	if err != nil {
		return nil, ErrRootDSEFailed
	}
	users := make([]DirectoryUser, 0, len(result.Entries))
	for _, entry := range result.Entries {
		objectID, username := stableIDValue(entry, request.StableIDAttribute), entry.GetAttributeValue(request.UsernameAttribute)
		if strings.TrimSpace(objectID) == "" || strings.TrimSpace(username) == "" {
			continue
		}
		users = append(users, DirectoryUser{ObjectID: objectID, DN: entry.DN, Username: username, Email: entry.GetAttributeValue(request.EmailAttribute), Name: entry.GetAttributeValue(request.NameAttribute)})
	}
	return users, nil
}

func stableIDValue(entry *ldap.Entry, attribute string) string {
	raw := entry.GetRawAttributeValue(attribute)
	if strings.EqualFold(strings.TrimSpace(attribute), "objectGUID") && len(raw) == 16 {
		guidBytes := []byte{
			raw[3], raw[2], raw[1], raw[0],
			raw[5], raw[4],
			raw[7], raw[6],
			raw[8], raw[9],
			raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
		}
		encoded := hex.EncodeToString(guidBytes)
		return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
	}
	return entry.GetAttributeValue(attribute)
}

func directoryTLSConfig(request TestRequest, serverName string) (*tls.Config, error) {
	tlsConfig := request.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
		if tlsConfig.MinVersion < tls.VersionTLS12 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	// 自定义信任根有两条来源，必须并存：
	//   1) 每个目录源自带的 ca_cert_pem（控制台里填的）
	//   2) 共享信任目录（容器内与 Keycloak 的 truststores 是同一份挂载）
	// 只认其中一条就会出现「预览通过、激活时 FullSync 报 PKIX path building
	// failed」——现场就是这么炸的。
	//
	// RootCAs 一旦赋值就完全替换系统根，所以只在确实存在自定义根时才建池；
	// 否则保持 nil 用系统根，避免「补一个根」变成「砍掉所有公共根」。
	sharedAnchors := loadSharedTrustAnchors(os.Getenv(directoryTrustDirEnv))
	if strings.TrimSpace(request.CACertPEM) != "" || len(sharedAnchors) > 0 {
		roots := x509.NewCertPool()
		if strings.TrimSpace(request.CACertPEM) != "" {
			if !roots.AppendCertsFromPEM([]byte(request.CACertPEM)) {
				return nil, ErrInvalidCACert
			}
		}
		for _, anchor := range sharedAnchors {
			roots.AddCert(anchor)
		}
		tlsConfig.RootCAs = roots
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = serverName
	}
	return tlsConfig, nil
}

// ErrStartTLSFailed：服务端拒绝 StartTLS 或升级后的 TLS 握手/证书校验失败。
// 失败即断开，绝不回退为明文继续 bind。
var ErrStartTLSFailed = errors.New("directory StartTLS negotiation failed")

// dialPinnedDirectory 连到已固定的批准地址，并保证在返回前链路已加密且证书已校验：
//   - ldaps：TCP 后立即 TLS 握手；
//   - starttls：TCP 后发送 StartTLS 扩展操作，升级成功才返回（此前不发送任何凭据）。
func dialPinnedDirectory(ctx context.Context, target Target, tlsConfig *tls.Config) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConnection, err := dialer.DialContext(ctx, "tcp", target.DialAddress)
	if err != nil {
		return nil, err
	}
	if target.Transport == TransportStartTLS {
		return upgradeWithStartTLS(ctx, rawConnection, tlsConfig)
	}
	tlsConnection := tls.Client(rawConnection, tlsConfig)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = rawConnection.Close()
		return nil, err
	}
	connection := ldap.NewConn(tlsConnection, true)
	connection.Start()
	return connection, nil
}

func upgradeWithStartTLS(ctx context.Context, rawConnection net.Conn, tlsConfig *tls.Config) (*ldap.Conn, error) {
	// StartTLS 的 TLS 握手在库内部不接收 ctx：用连接截止时间兜底，避免对端卡住握手。
	deadline := time.Now().Add(ldapOperationTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := rawConnection.SetDeadline(deadline); err != nil {
		_ = rawConnection.Close()
		return nil, err
	}
	connection := ldap.NewConn(rawConnection, false)
	connection.Start()
	connection.SetTimeout(ldapOperationTimeout)
	stopCancellation := closeConnectionOnContextCancellation(ctx, connection)
	err := connection.StartTLS(tlsConfig)
	stopCancellation()
	if err != nil {
		connection.Close()
		return nil, ErrStartTLSFailed
	}
	if state, ok := connection.TLSConnectionState(); !ok || !state.HandshakeComplete {
		connection.Close()
		return nil, ErrStartTLSFailed
	}
	if err := rawConnection.SetDeadline(time.Time{}); err != nil {
		connection.Close()
		return nil, err
	}
	return connection, nil
}

func neturlHost(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return "", ErrConnectionFailed
	}
	return parsed.Hostname(), nil
}

type ldapConnectionCloser interface{ Close() error }

func closeConnectionOnContextCancellation(ctx context.Context, connection ldapConnectionCloser) func() {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-done:
		}
	}()
	return func() {
		once.Do(func() { close(done) })
	}
}
