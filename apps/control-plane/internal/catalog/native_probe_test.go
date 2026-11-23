package catalog

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const nativeGoogleOK = `{"candidates":[{"content":{"role":"model","parts":[{"text":"OK"}]},"finishReason":"STOP"}]}`
const nativeBedrockOK = `{"output":{"message":{"role":"assistant","content":[{"text":"OK"}]}},"stopReason":"end_turn","usage":{"inputTokens":4,"outputTokens":1,"totalTokens":5}}`

func TestNativeGeminiAPIKeyHTTPContract(t *testing.T) {
	for _, suffix := range []string{"", "/v1", "/v1beta", "/relay"} {
		t.Run(suffix, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				path := suffix
				if !strings.HasSuffix(path, "/v1") && !strings.HasSuffix(path, "/v1beta") {
					path += "/v1beta"
				}
				path += "/models/gemini-fixture:generateContent"
				if r.URL.Path != path || r.Method != "POST" || r.Header.Get("X-Goog-Api-Key") != "fixture-secret" || r.Header.Get("Authorization") != "" {
					t.Errorf("native Gemini path/auth mismatch: %s", r.URL.Path)
				}
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("invalid JSON")
				}
				if body["model"] != nil || body["messages"] != nil || body["contents"] == nil {
					t.Errorf("not native contract: %#v", body)
				}
				if body["generationConfig"].(map[string]any)["maxOutputTokens"] != float64(32) {
					t.Error("budget lost")
				}
				io.WriteString(w, nativeGoogleOK)
			}))
			defer server.Close()
			result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), ModelProbeRequest{ProviderType: "gemini", BaseURL: server.URL + suffix, APIKey: "fixture-secret", DeploymentName: "models/gemini-fixture", Protocol: "chat", MaxOutputTokens: 32})
			if !result.OK || !result.PayloadValidated || result.HTTPStatus != 200 || calls != 1 {
				t.Fatalf("result=%+v calls=%d", result, calls)
			}
		})
	}
}
func TestNativeVertexOAuthAndGenerationHTTPContract(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	tokens, generations := 0, 0
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokens++
			r.ParseForm()
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
				t.Error("wrong grant")
			}
			parts := strings.Split(r.Form.Get("assertion"), ".")
			if len(parts) != 3 {
				t.Fatal("invalid JWT")
			}
			claimsRaw, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var claims map[string]any
			json.Unmarshal(claimsRaw, &claims)
			if claims["iss"] != "svc@fixture.test" || claims["aud"] != server.URL+"/token" || claims["scope"] != "https://www.googleapis.com/auth/cloud-platform" {
				t.Errorf("wrong JWT claims %#v", claims)
			}
			signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
			digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature) != nil {
				t.Error("JWT signature invalid")
			}
			io.WriteString(w, `{"access_token":"fixture-token","expires_in":3600}`)
			return
		}
		generations++
		if r.URL.Path != "/v1/projects/project-fixture/locations/global/publishers/google/models/gemini-fixture:generateContent" || r.Header.Get("Authorization") != "Bearer fixture-token" || r.Header.Get("X-Goog-Api-Key") != "" {
			t.Errorf("Vertex target/auth mismatch %s", r.URL.Path)
		}
		io.WriteString(w, nativeGoogleOK)
	}))
	defer server.Close()
	encoded, _ := json.Marshal(nativeGoogleServiceAccount{ProjectID: "project-fixture", ClientEmail: "svc@fixture.test", PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), TokenURI: server.URL + "/token"})
	for _, typ := range []string{"gemini", "vertex"} {
		result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), ModelProbeRequest{ProviderType: typ, BaseURL: server.URL + "/v1", APIKey: string(encoded), DeploymentName: "publishers/google/models/gemini-fixture", Protocol: "chat", MaxOutputTokens: 16})
		if !result.OK || !result.PayloadValidated || result.HTTPStatus != 200 {
			t.Fatalf("%s result=%+v", typ, result)
		}
	}
	if tokens != 2 || generations != 2 {
		t.Fatalf("OAuth/generation calls=%d/%d", tokens, generations)
	}
}
func TestNativeBedrockHTTPContractAndEscapedModel(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.EscapedPath() != "/relay/model/arn:aws:bedrock:us-east-1:123:inference-profile%2Ffixture/converse" {
			t.Errorf("wrong encoded path %s", r.URL.EscapedPath())
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKID/") || !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/bedrock/aws4_request") || r.Header.Get("X-Amz-Security-Token") != "SESSION" {
			t.Error("missing SigV4 credentials")
		}
		raw, _ := io.ReadAll(r.Body)
		if r.Header.Get("X-Amz-Content-Sha256") != bedrockSHA256Hex(raw) {
			t.Error("payload signature hash mismatch")
		}
		var body map[string]any
		json.Unmarshal(raw, &body)
		if body["inferenceConfig"].(map[string]any)["maxTokens"] != float64(17) || body["messages"] == nil || body["model"] != nil {
			t.Errorf("bad Converse payload %s", raw)
		}
		io.WriteString(w, nativeBedrockOK)
	}))
	defer server.Close()
	result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), ModelProbeRequest{ProviderType: "bedrock", BaseURL: server.URL + "/relay", APIKey: `{"aws_access_key_id":"AKID","aws_secret_access_key":"SECRET","aws_session_token":"SESSION","aws_region":"us-east-1"}`, DeploymentName: "arn:aws:bedrock:us-east-1:123:inference-profile/fixture", Protocol: "chat", MaxOutputTokens: 17})
	if !result.OK || !result.PayloadValidated || calls != 1 {
		t.Fatalf("result=%+v calls=%d", result, calls)
	}
}
func TestNativeProbeRequiresPayloadAndClassifiesFailures(t *testing.T) {
	for _, tc := range []struct {
		typ, body string
		status    int
		kind      string
	}{
		{"gemini", `{}`, 200, ModelProbeErrorUpstream}, {"gemini", `{"candidates":[{"content":{"role":"model","parts":[{"text":"OK"}]}}]}`, 200, ModelProbeErrorUpstream},
		{"gemini", `{"error":{"message":"private-secret"}}`, 200, ModelProbeErrorUpstream}, {"gemini", nativeGoogleOK, 401, ModelProbeErrorUnauthorized}, {"gemini", nativeGoogleOK, 403, ModelProbeErrorUnauthorized}, {"gemini", nativeGoogleOK, 404, ModelProbeErrorNotDeployed}, {"gemini", nativeGoogleOK, 429, ModelProbeErrorRateLimited}, {"gemini", nativeGoogleOK, 500, ModelProbeErrorUpstream},
		{"bedrock", `{"output":{"message":{"role":"assistant","content":[{"text":"OK"}]}}}`, 200, ModelProbeErrorUpstream}, {"bedrock", `{"stopReason":"end_turn","output":{"message":{"role":"assistant","content":[]}}}`, 200, ModelProbeErrorUpstream},
	} {
		t.Run(tc.typ+tc.kind+tc.body, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }))
			defer server.Close()
			key := "fixture-secret"
			if tc.typ == "bedrock" {
				key = `{"access_key_id":"AKID","secret_access_key":"SECRET","region":"us-east-1"}`
			}
			result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), ModelProbeRequest{ProviderType: tc.typ, BaseURL: server.URL, APIKey: key, DeploymentName: "fixture", Protocol: "chat"})
			if result.OK || result.PayloadValidated || result.HTTPStatus != tc.status || result.ErrorKind != tc.kind || strings.Contains(result.Message, "private-secret") {
				t.Fatalf("bad failure result=%+v", result)
			}
		})
	}
}
func TestNativeProbeRejectsUnsafeConfigurationAndRedirects(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", "https://169.254.169.254/latest/meta-data")
		w.WriteHeader(302)
	}))
	defer server.Close()
	result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), ModelProbeRequest{ProviderType: "gemini", BaseURL: server.URL, APIKey: "secret", DeploymentName: "fixture", Protocol: "chat"})
	if result.OK || result.HTTPStatus != 302 || hits.Load() != 1 {
		t.Fatalf("redirect followed %+v hits=%d", result, hits.Load())
	}
	for _, request := range []ModelProbeRequest{
		{ProviderType: "gemini", BaseURL: "https://169.254.169.254", APIKey: "secret", DeploymentName: "fixture"},
		{ProviderType: "gemini", BaseURL: server.URL, APIKey: "secret", DeploymentName: "fixture", MaxOutputTokens: 1025},
		{ProviderType: "gemini", BaseURL: server.URL, APIKey: "secret", DeploymentName: "fixture", Protocol: "responses"},
		{ProviderType: "vertex", BaseURL: server.URL, APIKey: "plain-key", DeploymentName: "fixture"},
		{ProviderType: "bedrock", BaseURL: server.URL, APIKey: `{"access_key_id":"a","secret_access_key":"s","region":"bad/region"}`, DeploymentName: "fixture"},
	} {
		got := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), request)
		if got.OK || got.ErrorKind != ModelProbeErrorInvalidRequest || got.HTTPStatus != 0 {
			t.Fatalf("unsafe configuration accepted %+v", got)
		}
	}
	got := NewHTTPModelProber().Probe(context.Background(), ModelProbeRequest{ProviderType: "gemini", BaseURL: server.URL, APIKey: "secret", DeploymentName: "fixture"})
	if got.OK || got.ErrorKind != ModelProbeErrorInvalidRequest || hits.Load() != 1 {
		t.Fatalf("production private target allowed %+v hits=%d", got, hits.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got = newHTTPModelProberWithClient(server.Client()).Probe(ctx, ModelProbeRequest{ProviderType: "gemini", BaseURL: server.URL, APIKey: "secret", DeploymentName: "fixture", Timeout: time.Second})
	if got.ErrorKind != ModelProbeErrorCancelled || hits.Load() != 1 {
		t.Fatalf("cancel did not stop request %+v", got)
	}
}

func TestNativeProbeUsesConfiguredOutboundProxy(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Goog-Api-Key") != "fixture" {
			t.Error("auth lost through proxy")
		}
		io.WriteString(w, nativeGoogleOK)
	}))
	defer upstream.Close()
	var connects atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connects.Add(1)
		if r.Method != "CONNECT" || r.Host != upstream.Listener.Addr().String() {
			w.WriteHeader(403)
			return
		}
		target, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			target.Close()
			return
		}
		fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { defer target.Close(); defer client.Close(); io.Copy(target, client) }()
		go func() { defer target.Close(); defer client.Close(); io.Copy(client, target) }()
	}))
	defer proxy.Close()
	result := newHTTPModelProberWithClient(upstream.Client()).Probe(WithOutboundProxy(context.Background(), proxy.URL), ModelProbeRequest{ProviderType: "gemini", BaseURL: upstream.URL, APIKey: "fixture", DeploymentName: "model", Protocol: "chat"})
	if !result.OK || connects.Load() != 1 {
		t.Fatalf("configured proxy bypassed: %+v connects=%d", result, connects.Load())
	}
}

func TestNativeOAuthRejectsUnsafeTokenURIWithoutSendingRequest(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); io.WriteString(w, nativeGoogleOK) }))
	defer server.Close()
	key, _ := json.Marshal(nativeGoogleServiceAccount{ProjectID: "project", ClientEmail: "svc@fixture", PrivateKey: "invalid-but-not-sent", TokenURI: "http://169.254.169.254/metadata"})
	result := newHTTPModelProberWithClient(server.Client()).Probe(context.Background(), ModelProbeRequest{ProviderType: "vertex", BaseURL: server.URL, APIKey: string(key), DeploymentName: "model", Protocol: "chat"})
	if result.OK || result.PayloadValidated || hits.Load() != 0 {
		t.Fatalf("unsafe OAuth URI reached network %+v hits=%d", result, hits.Load())
	}
}

func TestNativeBedrockSigningMatchesIndependentGolden(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[{"text":"Reply OK."}]}],"inferenceConfig":{"maxTokens":16}}`
	req, _ := http.NewRequest(http.MethodPost, "https://bedrock-runtime.us-east-1.amazonaws.com/model/fixture/converse", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if err := signNativeBedrockRequest(req, nativeBedrockCredential{AccessKeyID: "AKID", SecretAccessKey: "SECRET", Region: "us-east-1"}, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	expected := "AWS4-HMAC-SHA256 Credential=AKID/20260102/us-east-1/bedrock/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=f4ad9306e5ca793ad99382074d7624d7784343e701627688bb2ee40540f5939f"
	if req.Header.Get("Authorization") != expected {
		t.Fatalf("SigV4 golden mismatch: %s", req.Header.Get("Authorization"))
	}
}

func TestNativeOAuthProductionRejectsPrivateTokenDestination(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer server.Close()
	_, _, err := (&httpModelProber{}).nativeGoogleToken(context.Background(), &nativeGoogleServiceAccount{TokenURI: server.URL + "/token", ProjectID: "fixture", ClientEmail: "svc@fixture", PrivateKey: "never-used"})
	if err == nil || hits.Load() != 0 {
		t.Fatal("private token destination bypassed production safetarget")
	}
}
