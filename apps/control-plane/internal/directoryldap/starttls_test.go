package directoryldap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// W9 9.4：ldap:// + StartTLS。核心不变量——任何 bind 凭据只在已校验的 TLS 通道上发送；
// StartTLS 被拒或证书不可信时直接断开，绝不回退明文。

func TestValidateConfigAcceptsStartTLSAndCustomPorts(t *testing.T) {
	for _, raw := range []string{
		"ldap://dc.corp.test",
		"ldap://dc.corp.test:389",
		"ldap://dc.corp.test:3268",
		"ldaps://dc.corp.test:3269",
		"ldaps://ldap.corp.test:10636",
	} {
		if err := ValidateConfig(Config{ConnectionURL: raw}); err != nil {
			t.Fatalf("%s rejected: %v", raw, err)
		}
	}
}

func TestValidateConfigRejectsNonLDAPSchemesAndBadPorts(t *testing.T) {
	for raw, want := range map[string]error{
		"http://dc.corp.test:389":    ErrInsecureTransport,
		"cldap://dc.corp.test":       ErrInsecureTransport,
		"ldap://dc.corp.test:0":      ErrInvalidTarget,
		"ldap://dc.corp.test:65536":  ErrInvalidTarget,
		"ldap://dc.corp.test:0389":   ErrInvalidTarget,
		"ldap://dc.corp.test:":       ErrInvalidTarget,
		"ldap://dc.corp.test:38a":    ErrInvalidTarget,
		"ldap://127.0.0.1:389":       ErrInvalidTarget,
		"ldap://dc.corp.test/x":      ErrInvalidTarget,
		"ldap://u:p@dc.corp.test":    ErrInvalidTarget,
		"ldap://dc.corp.test?x=1":    ErrInvalidTarget,
		"ldaps://dc.corp.test:99999": ErrInvalidTarget,
	} {
		if err := ValidateConfig(Config{ConnectionURL: raw}); !errors.Is(err, want) {
			t.Fatalf("%s: got %v, want %v", raw, err, want)
		}
	}
}

func TestTransportFor(t *testing.T) {
	if tr, err := TransportFor("ldap://dc.corp.test"); err != nil || tr != TransportStartTLS {
		t.Fatalf("ldap:// => %q, %v", tr, err)
	}
	if tr, err := TransportFor("ldaps://dc.corp.test"); err != nil || tr != TransportLDAPS {
		t.Fatalf("ldaps:// => %q, %v", tr, err)
	}
	if !UsesStartTLS("ldap://dc.corp.test:389") || UsesStartTLS("ldaps://dc.corp.test") || UsesStartTLS("http://x") {
		t.Fatal("UsesStartTLS mismatch")
	}
}

func TestPolicyRequiresExactApprovedPortPerTransport(t *testing.T) {
	resolver := staticTargetResolver{"dc.corp.test": resolvedAddresses("10.20.30.40")}
	// 旧写法（省略端口 = 636）保持兼容
	legacy := mustTargetPolicy(t, "dc.corp.test", "10.20.0.0/16").WithResolver(resolver)
	if _, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: "ldaps://dc.corp.test"}, legacy); err != nil {
		t.Fatalf("legacy ldaps default port rejected: %v", err)
	}
	// ldap:// 默认 389，未显式批准 → 拒
	if _, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: "ldap://dc.corp.test"}, legacy); !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("unapproved 389 accepted: %v", err)
	}
	policy := mustTargetPolicy(t, "dc.corp.test:389,dc.corp.test:3269", "10.20.0.0/16").WithResolver(resolver)
	cases := map[string]struct {
		port      string
		transport Transport
	}{
		"ldap://dc.corp.test":       {"389", TransportStartTLS},
		"ldap://dc.corp.test:389":   {"389", TransportStartTLS},
		"ldaps://dc.corp.test:3269": {"3269", TransportLDAPS},
	}
	for raw, want := range cases {
		target, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: raw}, policy)
		if err != nil {
			t.Fatalf("%s rejected: %v", raw, err)
		}
		if target.Port != want.port || target.Transport != want.transport || target.DialAddress != net.JoinHostPort("10.20.30.40", want.port) {
			t.Fatalf("%s => %+v", raw, target)
		}
	}
	for _, raw := range []string{"ldaps://dc.corp.test", "ldap://dc.corp.test:3268"} {
		if _, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: raw}, policy); !errors.Is(err, ErrTargetNotAllowed) {
			t.Fatalf("%s: expected ErrTargetNotAllowed, got %v", raw, err)
		}
	}
	if _, err := ParseTargetPolicy("dc.corp.test:0", ""); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("port 0 allowlist accepted: %v", err)
	}
}

// ---- 进程内假 LDAP 服务器：支持 StartTLS 扩展操作 / Bind / RootDSE Search ----

type fakeLDAPServer struct {
	listener  net.Listener
	tlsConfig *tls.Config
	// refuseStartTLS：以 protocolError 拒绝 StartTLS
	refuseStartTLS bool

	mu  sync.Mutex
	ops []string // 形如 "plain:bind"、"tls:bind"
}

func (s *fakeLDAPServer) record(op string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ops = append(s.ops, op)
}

func (s *fakeLDAPServer) observed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ops...)
}

func ldapResponse(messageID int64, tag ber.Tag, code int64) *ber.Packet {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "Response")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	envelope.AppendChild(op)
	return envelope
}

func (s *fakeLDAPServer) serve(conn net.Conn) {
	defer conn.Close()
	var stream net.Conn = conn
	mode := "plain"
	for {
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		packet, err := ber.ReadPacket(stream)
		if err != nil || len(packet.Children) < 2 {
			return
		}
		messageID, _ := packet.Children[0].Value.(int64)
		op := packet.Children[1]
		switch op.Tag {
		case ldap.ApplicationExtendedRequest:
			s.record(mode + ":starttls")
			if s.refuseStartTLS {
				_, _ = stream.Write(ldapResponse(messageID, ldap.ApplicationExtendedResponse, ldap.LDAPResultProtocolError).Bytes())
				continue
			}
			if _, err := stream.Write(ldapResponse(messageID, ldap.ApplicationExtendedResponse, ldap.LDAPResultSuccess).Bytes()); err != nil {
				return
			}
			tlsConn := tls.Server(conn, s.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				s.record("tls-handshake-failed")
				return
			}
			stream, mode = tlsConn, "tls"
		case ldap.ApplicationBindRequest:
			s.record(mode + ":bind")
			_, _ = stream.Write(ldapResponse(messageID, ldap.ApplicationBindResponse, ldap.LDAPResultSuccess).Bytes())
		case ldap.ApplicationSearchRequest:
			s.record(mode + ":search")
			_, _ = stream.Write(ldapResponse(messageID, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess).Bytes())
		case ldap.ApplicationUnbindRequest:
			return
		default:
			return
		}
	}
}

func startFakeLDAP(t *testing.T, cert tls.Certificate, refuse bool) *fakeLDAPServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &fakeLDAPServer{listener: listener, tlsConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, refuseStartTLS: refuse}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.serve(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return server
}

func newServerCertificate(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func starttlsTarget(server *fakeLDAPServer) Target {
	host, port, _ := net.SplitHostPort(server.listener.Addr().String())
	return Target{Hostname: "dc.example.test", Port: port, DialAddress: net.JoinHostPort(host, port), Transport: TransportStartTLS}
}

func TestStartTLSUpgradesBeforeBind(t *testing.T) {
	cert, roots := newServerCertificate(t, "dc.example.test")
	server := startFakeLDAP(t, cert, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := dialPinnedDirectory(ctx, starttlsTarget(server), &tls.Config{RootCAs: roots, ServerName: "dc.example.test", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("dialPinnedDirectory: %v", err)
	}
	defer connection.Close()
	if state, ok := connection.TLSConnectionState(); !ok || !state.HandshakeComplete {
		t.Fatal("connection not encrypted after StartTLS")
	}
	if err := connection.Bind("cn=reader,dc=example,dc=test", "directory-secret"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	ops := server.observed()
	if len(ops) < 2 || ops[0] != "plain:starttls" || ops[1] != "tls:bind" {
		t.Fatalf("unexpected op order %v", ops)
	}
}

func TestStartTLSRefusedNeverFallsBackToPlaintext(t *testing.T) {
	cert, roots := newServerCertificate(t, "dc.example.test")
	server := startFakeLDAP(t, cert, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := dialPinnedDirectory(ctx, starttlsTarget(server), &tls.Config{RootCAs: roots, ServerName: "dc.example.test", MinVersion: tls.VersionTLS12})
	if !errors.Is(err, ErrStartTLSFailed) {
		t.Fatalf("expected ErrStartTLSFailed, got %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	for _, op := range server.observed() {
		if op == "plain:bind" || op == "plain:search" {
			t.Fatalf("plaintext operation observed after StartTLS refusal: %v", server.observed())
		}
	}
}

func TestStartTLSUntrustedCertificateRejected(t *testing.T) {
	cert, _ := newServerCertificate(t, "dc.example.test")
	_, otherRoots := newServerCertificate(t, "dc.example.test")
	server := startFakeLDAP(t, cert, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := dialPinnedDirectory(ctx, starttlsTarget(server), &tls.Config{RootCAs: otherRoots, ServerName: "dc.example.test", MinVersion: tls.VersionTLS12})
	if !errors.Is(err, ErrStartTLSFailed) {
		t.Fatalf("expected ErrStartTLSFailed, got %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	for _, op := range server.observed() {
		if op == "plain:bind" || op == "tls:bind" {
			t.Fatalf("bind observed despite untrusted certificate: %v", server.observed())
		}
	}
}

func TestStartTLSHostnameMismatchRejected(t *testing.T) {
	cert, roots := newServerCertificate(t, "other.example.test")
	server := startFakeLDAP(t, cert, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := dialPinnedDirectory(ctx, starttlsTarget(server), &tls.Config{RootCAs: roots, ServerName: "dc.example.test", MinVersion: tls.VersionTLS12})
	if !errors.Is(err, ErrStartTLSFailed) {
		t.Fatalf("expected ErrStartTLSFailed, got %v", err)
	}
}
