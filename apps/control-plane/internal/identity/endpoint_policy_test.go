package identity

import "testing"

func TestHTTPEndpointsExplicitlyAllowed(t *testing.T) {
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "")
	if HTTPEndpointsExplicitlyAllowed("https://idp.example.com/token") {
		t.Fatal("https-only endpoints need no exception")
	}
	if HTTPEndpointsExplicitlyAllowed("http://10.1.2.3/token") {
		t.Fatal("private http without JJD_IDP_ALLOW_CIDRS must be refused")
	}
	if HTTPEndpointsExplicitlyAllowed("http://8.8.8.8/token") {
		t.Fatal("public http must be refused")
	}

	t.Setenv("JJD_IDP_ALLOW_CIDRS", "10.0.0.0/8")
	if !HTTPEndpointsExplicitlyAllowed("https://idp.example.com/auth", "http://10.1.2.3/token") {
		t.Fatal("registered private http endpoint must be allowed")
	}
	if HTTPEndpointsExplicitlyAllowed("http://10.1.2.3/auth", "http://8.8.8.8/token") {
		t.Fatal("one public http endpoint must refuse the whole set")
	}
	if HTTPEndpointsExplicitlyAllowed("http://127.0.0.1/token") {
		t.Fatal("loopback is always blocked")
	}
}
