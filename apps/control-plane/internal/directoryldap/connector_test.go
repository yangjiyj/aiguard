package directoryldap

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestNetURLHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "hostname and port", raw: "ldaps://directory.example.test:636", want: "directory.example.test"},
		{name: "ipv6", raw: "ldaps://[2001:db8::1]:636", want: "2001:db8::1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := neturlHost(test.raw)
			if err != nil {
				t.Fatalf("neturlHost() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("neturlHost() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestTestConnectionRejectsUnsafeOrIncompleteRequests(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		request TestRequest
		wantErr error
	}{
		{
			// W9 9.4：ldap:// 现为 StartTLS 模式，未批准时按目标未批准拒绝；非 LDAP 协议仍为不安全传输。
			name:    "non-ldap scheme",
			request: TestRequest{ConnectionURL: "http://directory.example.test:389", BindDN: "cn=sync", BindPassword: "secret"},
			wantErr: ErrInsecureTransport,
		},
		{
			name:    "starttls without deployment policy",
			request: TestRequest{ConnectionURL: "ldap://directory.example.test:389", BindDN: "cn=sync", BindPassword: "secret"},
			wantErr: ErrTargetNotAllowed,
		},
		{
			name:    "missing bind password without deployment policy",
			request: TestRequest{ConnectionURL: "ldaps://directory.example.test:636", BindDN: "cn=sync"},
			wantErr: ErrTargetNotAllowed,
		},
		{
			name:    "invalid custom CA without deployment policy",
			request: TestRequest{ConnectionURL: "ldaps://directory.example.test:636", BindDN: "cn=sync", BindPassword: "secret", CACertPEM: "not a certificate"},
			wantErr: ErrTargetNotAllowed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := TestConnection(context.Background(), test.request)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("TestConnection() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestListUsersRejectsInvalidFilterBeforeConnectionPreflight(t *testing.T) {
	_, err := (Client{}).ListUsers(context.Background(), SyncRequest{TestRequest: TestRequest{ConnectionURL: "ldaps://unapproved.example.test:636", BindDN: "cn=sync", BindPassword: "secret"}, UserFilter: "(uid=bad\x00)"})
	if !errors.Is(err, ErrInvalidUserFilter) {
		t.Fatalf("ListUsers error=%v, want invalid filter before target/connect preflight", err)
	}
}

func TestStableIDValueNormalizesBinaryActiveDirectoryObjectGUID(t *testing.T) {
	rawGUID := []byte{
		0xcb, 0x92, 0x96, 0xab,
		0x0e, 0x17,
		0xf8, 0x40,
		0x92, 0x0f, 0xd6, 0xec, 0xb0, 0x36, 0x3f, 0x1a,
	}
	entry := &ldap.Entry{
		Attributes: []*ldap.EntryAttribute{{
			Name:       "objectGUID",
			Values:     []string{string(rawGUID)},
			ByteValues: [][]byte{rawGUID},
		}},
	}

	got := stableIDValue(entry, "objectGUID")
	if got != "ab9692cb-170e-40f8-920f-d6ecb0363f1a" {
		t.Fatalf("stableIDValue() = %q, want canonical AD GUID", got)
	}
}

func TestCloseConnectionOnContextCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	stop := closeConnectionOnContextCancellation(ctx, client)
	defer stop()

	cancel()
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("context cancellation must close the LDAP connection")
	}
}

// ListUsers 与 TestConnection 一样走 PolicySource（库内名单），不再用启动时的静态 Policy。
func TestListUsersUsesPolicySourceTargets(t *testing.T) {
	resolver := staticTargetResolver{}
	stored := mustTargetPolicy(t, "a.corp.test:636", "10.20.0.0/16").WithResolver(resolver)
	static := mustTargetPolicy(t, "b.corp.test:636", "10.20.0.0/16").WithResolver(resolver)
	client := Client{Policy: static, PolicySource: func(context.Context) TargetPolicy { return stored }}
	request := func(host string) SyncRequest {
		return SyncRequest{
			TestRequest:       TestRequest{ConnectionURL: "ldaps://" + host + ":636", BindDN: "cn=sync", BindPassword: "secret"},
			UsersDN:           "ou=people,dc=corp,dc=test",
			StableIDAttribute: "entryUUID",
			UsernameAttribute: "uid",
		}
	}
	if _, err := client.ListUsers(context.Background(), request("b.corp.test")); !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("target only in the static policy: err=%v, want ErrTargetNotAllowed", err)
	}
	// a 在库内名单里：不因名单被拒，走到 DNS 解析（测试解析器查不到，按非法目标拒绝）。
	if _, err := client.ListUsers(context.Background(), request("a.corp.test")); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("target in the stored policy: err=%v, want it past the allowlist (ErrInvalidTarget from resolver)", err)
	}
}
