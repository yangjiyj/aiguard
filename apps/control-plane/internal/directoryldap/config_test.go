package directoryldap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

type staticTargetResolver map[string][]net.IPAddr

func (resolver staticTargetResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	answers, ok := resolver[host]
	if !ok {
		return nil, errors.New("name not found")
	}
	return answers, nil
}

func mustTargetPolicy(t *testing.T, targets, cidrs string) TargetPolicy {
	t.Helper()
	policy, err := ParseTargetPolicy(targets, cidrs)
	if err != nil {
		t.Fatalf("ParseTargetPolicy() error = %v", err)
	}
	return policy
}

// W9 9.4：ldap:// 不再被拒——它表示「StartTLS 后再认证」，不存在明文模式（见 starttls_test.go）。
// 非 LDAP 协议仍按不安全传输拒绝。
func TestValidateConfigRejectsNonLDAPTransport(t *testing.T) {
	err := ValidateConfig(Config{ConnectionURL: "http://dc.corp.test:389"})
	if !errors.Is(err, ErrInsecureTransport) {
		t.Fatalf("expected ErrInsecureTransport, got %v", err)
	}
}

func TestValidateConfigAcceptsLDAPS(t *testing.T) {
	if err := ValidateConfig(Config{ConnectionURL: "ldaps://dc.corp.test:636"}); err != nil {
		t.Fatalf("expected ldaps config to be valid, got %v", err)
	}
}

func TestValidateConfigRejectsLoopbackAndMetadataTargets(t *testing.T) {
	for _, connectionURL := range []string{
		"ldaps://127.0.0.1:636",
		"ldaps://[::1]:636",
		"ldaps://169.254.169.254:636",
		"ldaps://metadata.google.internal:636",
	} {
		t.Run(connectionURL, func(t *testing.T) {
			err := ValidateConfig(Config{ConnectionURL: connectionURL})
			if !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("expected ErrInvalidTarget, got %v", err)
			}
		})
	}
}

func TestValidateConfigWithPolicyPinsOnlyDeploymentApprovedAddress(t *testing.T) {
	policy := mustTargetPolicy(t, "dc.corp.test:636", "10.20.0.0/16")
	policy.resolver = staticTargetResolver{
		"dc.corp.test": {{IP: net.ParseIP("10.20.30.40")}},
	}
	target, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: "ldaps://dc.corp.test:636"}, policy)
	if err != nil {
		t.Fatalf("ValidateConfigWithPolicy() error = %v", err)
	}
	if target.DialAddress != "10.20.30.40:636" {
		t.Fatalf("DialAddress = %q, want pinned address", target.DialAddress)
	}
}

func TestValidateConfigWithPolicyRejectsUnsafeDNSAnswers(t *testing.T) {
	policy := mustTargetPolicy(t, "dc.corp.test", "10.0.0.0/8,fd12:3456::/48")
	for name, answers := range map[string][]net.IPAddr{
		"loopback": resolvedAddresses("127.0.0.1"),
		"metadata": resolvedAddresses("169.254.169.254"),
		"mixed":    resolvedAddresses("10.20.30.40", "192.168.1.2"),
	} {
		t.Run(name, func(t *testing.T) {
			candidate := policy
			candidate.resolver = staticTargetResolver{"dc.corp.test": answers}
			_, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: "ldaps://dc.corp.test:636"}, candidate)
			if !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("expected ErrInvalidTarget, got %v", err)
			}
		})
	}
}

func TestValidateConfigWithPolicyRejectsLiteralTargets(t *testing.T) {
	policy := mustTargetPolicy(t, "dc.corp.test", "10.0.0.0/8")
	for _, raw := range []string{"ldaps://10.20.30.40:636", "ldaps://[fd12:3456::1]:636", "ldaps://dc.corp.test:10636"} {
		t.Run(raw, func(t *testing.T) {
			_, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: raw}, policy)
			if !errors.Is(err, ErrTargetNotAllowed) && !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("expected rejected target, got %v", err)
			}
		})
	}
}

func resolvedAddresses(values ...string) []net.IPAddr {
	addresses := make([]net.IPAddr, 0, len(values))
	for _, value := range values {
		addresses = append(addresses, net.IPAddr{IP: net.ParseIP(value)})
	}
	return addresses
}

func TestValidateUserFilterRejectsMalformedControlAndOversizedInput(t *testing.T) {
	for name, filter := range map[string]string{
		"valid":        "(&(objectClass=person)(uid=alice))",
		"second root":  "(uid=alice)(|(objectClass=*))",
		"unterminated": "(&(objectClass=person)",
		"control":      "(uid=alice\x00)",
		"oversized":    "(" + string(make([]byte, maxUserFilterLength)) + ")",
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateUserFilter(filter)
			if name == "valid" {
				if err != nil {
					t.Fatalf("valid filter rejected: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidUserFilter) {
				t.Fatalf("expected ErrInvalidUserFilter, got %v", err)
			}
		})
	}
}

func TestValidateUserFilterEnforcesExactLengthLimit(t *testing.T) {
	for _, size := range []int{4095, 4096, 4097} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			filter := "(uid=" + strings.Repeat("a", size-6) + ")"
			err := ValidateUserFilter(filter)
			if size <= maxUserFilterLength {
				if err != nil {
					t.Fatalf("filter of %d bytes rejected: %v", size, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidUserFilter) {
				t.Fatalf("filter of %d bytes accepted: %v", size, err)
			}
		})
	}
}

func TestTargetPolicyWithAllowedTargetsReplacesDeploymentList(t *testing.T) {
	base, err := ParseTargetPolicy("dc.corp.test:636", "10.20.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := base.WithAllowedTargets([]string{"ldap.corp.test:389"})
	if err != nil {
		t.Fatal(err)
	}
	resolver := staticTargetResolver{"ldap.corp.test": {{IP: net.ParseIP("10.20.0.5")}}, "dc.corp.test": {{IP: net.ParseIP("10.20.0.6")}}}
	if _, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: "ldap://ldap.corp.test:389"}, policy.WithResolver(resolver)); err != nil {
		t.Fatalf("console-listed target rejected: %v", err)
	}
	if _, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: "ldaps://dc.corp.test:636"}, policy.WithResolver(resolver)); !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("deployment target must be replaced by the stored list: %v", err)
	}
	if _, err := base.WithAllowedTargets([]string{"127.0.0.1"}); err == nil {
		t.Fatal("IP literal targets stay invalid")
	}
}

// 目标不在名单只是配置问题，不记“防跳板拒绝”安全事件；解析出的地址不在批准网段才记。
// 改了包级 EgressDeniedRecorder，不能 t.Parallel。
func TestValidateConfigWithPolicyRecordsEgressDenialOnlyForUnapprovedAddress(t *testing.T) {
	var denied []string
	previous := EgressDeniedRecorder
	EgressDeniedRecorder = func(_ context.Context, host string) { denied = append(denied, host) }
	t.Cleanup(func() { EgressDeniedRecorder = previous })
	policy := mustTargetPolicy(t, "dc.corp.test", "10.20.0.0/16").WithResolver(staticTargetResolver{
		"dc.corp.test":    resolvedAddresses("192.168.1.2"),
		"other.corp.test": resolvedAddresses("10.20.0.5"),
	})

	if _, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: "ldaps://other.corp.test:636"}, policy); !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("unlisted target: err=%v, want ErrTargetNotAllowed", err)
	}
	if len(denied) != 0 {
		t.Fatalf("unlisted target must not record an egress denial event, recorded %v", denied)
	}
	if _, err := ValidateConfigWithPolicy(context.Background(), Config{ConnectionURL: "ldaps://dc.corp.test:636"}, policy); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("address outside approved CIDRs: err=%v, want ErrInvalidTarget", err)
	}
	if len(denied) != 1 || denied[0] != "dc.corp.test" {
		t.Fatalf("address outside approved CIDRs must record one egress denial, recorded %v", denied)
	}
}
