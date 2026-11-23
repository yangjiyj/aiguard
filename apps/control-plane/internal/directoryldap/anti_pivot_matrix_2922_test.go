package directoryldap

import (
	"context"
	"errors"
	"net"
	"testing"
)

type staticLDAPResolver map[string]string

func (r staticLDAPResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if ip, ok := r[host]; ok {
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	}
	return nil, errors.New("no such host")
}

// 行为矩阵 8.2（防跳板出站，不在防护项注册表里）：平台自身出站之 LDAP 目标。默认（名单为空）拒绝；
// 登记目标并放行网段后放行；元数据登记了也拒；全局观察留痕不影响（设计 D5、D6）。
func TestAntiPivotDirectoryLDAPEgressMatrix(t *testing.T) {
	resolver := staticLDAPResolver{"ldap.corp": "10.0.0.7", "meta.corp": "169.254.169.254"}
	policy := func(t *testing.T, targets, cidrs string) TargetPolicy {
		t.Helper()
		p, err := ParseTargetPolicy(targets, cidrs)
		if err != nil {
			t.Fatal(err)
		}
		return p.WithResolver(resolver)
	}
	for _, auditOnly := range []string{"false", "true"} {
		t.Setenv("SECURITY_AUDIT_ONLY", auditOnly)
		if _, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: "ldaps://ldap.corp:636"}, policy(t, "", "")); err == nil {
			t.Errorf("SECURITY_AUDIT_ONLY=%s: default must deny", auditOnly)
		}
		if _, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: "ldaps://ldap.corp:636"}, policy(t, "ldap.corp:636", "10.0.0.0/24")); err != nil {
			t.Errorf("SECURITY_AUDIT_ONLY=%s: a listed target in an allowed CIDR must be allowed: %v", auditOnly, err)
		}
		if _, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: "ldaps://meta.corp:636"}, policy(t, "meta.corp:636", "169.254.0.0/16")); err == nil {
			t.Errorf("SECURITY_AUDIT_ONLY=%s: a metadata address must stay denied even when listed", auditOnly)
		}
	}
}
