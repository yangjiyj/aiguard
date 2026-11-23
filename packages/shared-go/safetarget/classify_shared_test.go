package safetarget

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
)

// safetarget 只做“类别→开关”：默认选项下按 egresspolicy.Classify 的类别拒绝或放行。
func TestSafetargetFollowsSharedClassification(t *testing.T) {
	for _, raw := range []string{"169.254.169.254", "168.63.129.16", "fd00:ec2::254", "127.0.0.1", "169.254.1.1",
		"0.1.2.3", "240.0.0.1", "100::1", "10.0.0.1", "100.64.0.1", "198.18.0.1", "2001:2::1", "8.8.8.8"} {
		addr := netip.MustParseAddr(raw)
		host := raw
		if addr.Is6() {
			host = "[" + raw + "]"
		}
		_, err := ResolveWithOptions(context.Background(), "https://"+host+"/", Options{}, nil)
		switch egresspolicy.Classify(addr) {
		case egresspolicy.ClassPublic:
			if err != nil {
				t.Errorf("%s: public address rejected: %v", raw, err)
			}
		case egresspolicy.ClassPrivate:
			if !errors.Is(err, ErrPrivateAddress) {
				t.Errorf("%s: want ErrPrivateAddress, got %v", raw, err)
			}
		default:
			if !errors.Is(err, ErrForbiddenAddress) {
				t.Errorf("%s: want ErrForbiddenAddress, got %v", raw, err)
			}
		}
	}
	for _, host := range []string{"metadata", "instance-data.ec2.internal", "metadata.goog"} {
		if _, err := ResolveWithOptions(context.Background(), "http://"+host+"/", Options{}, nil); !errors.Is(err, ErrForbiddenAddress) {
			t.Errorf("metadata hostname %s must be rejected by name, got %v", host, err)
		}
	}
}
