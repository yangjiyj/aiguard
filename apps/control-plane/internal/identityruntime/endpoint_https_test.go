package identityruntime

import (
	"errors"
	"testing"
)

// 9.5：写入身份运行态的 IdP 端点默认必须是 https；token 端点走 http 会把 client_secret 明文发出去。
// 例外只在部署显式登记了私网 IdP（AllowPrivateHTTP，来源 JJD_IDP_ALLOW_CIDRS）时放开。
func TestValidateDesiredRejectsHTTPEndpointsByDefault(t *testing.T) {
	for _, field := range []string{"issuer", "authorization", "token", "jwks", "userinfo", "end_session"} {
		desired := testDesiredIdentitySource(t)
		desired.Digest = ""
		switch field {
		case "issuer":
			desired.Endpoints.Issuer = "http://idp.example.com"
		case "authorization":
			desired.Endpoints.Authorization = "http://idp.example.com/authorize"
		case "token":
			desired.Endpoints.Token = "http://idp.example.com/token"
		case "jwks":
			desired.Endpoints.JWKS = "http://idp.example.com/jwks"
		case "userinfo":
			desired.Endpoints.UserInfo = "http://idp.example.com/userinfo"
		case "end_session":
			desired.Endpoints.EndSession = "http://idp.example.com/logout"
		}
		if err := ValidateDesired(desired); !errors.Is(err, ErrInsecureEndpoint) {
			t.Fatalf("%s: http endpoint must be rejected with ErrInsecureEndpoint, got %v", field, err)
		}
		if _, err := ComputeDesiredDigest(desired); !errors.Is(err, ErrInsecureEndpoint) {
			t.Fatalf("%s: digest must refuse http endpoint, got %v", field, err)
		}
		desired.AllowPrivateHTTP = true
		if err := ValidateDesired(desired); err != nil {
			t.Fatalf("%s: explicit private-http exception must allow http, got %v", field, err)
		}
	}
}

func TestAllowPrivateHTTPDoesNotChangeDigest(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	withException := desired
	withException.Digest = ""
	withException.AllowPrivateHTTP = true
	digest, err := ComputeDesiredDigest(withException)
	if err != nil {
		t.Fatal(err)
	}
	if digest != desired.Digest {
		t.Fatal("the transport exception is deployment policy, not part of the published configuration digest")
	}
}

func TestValidateDesiredStillRejectsNonHTTPSchemesWithException(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	desired.Digest = ""
	desired.AllowPrivateHTTP = true
	desired.Endpoints.Token = "ftp://idp.example.com/token"
	if err := ValidateDesired(desired); err == nil {
		t.Fatal("non-http(s) schemes must stay rejected")
	}
}
