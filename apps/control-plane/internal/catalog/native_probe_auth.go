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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type nativeBedrockCredential struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}
type nativeGoogleServiceAccount struct {
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

func parseNativeGoogleAccount(raw string) (*nativeGoogleServiceAccount, error) {
	var account nativeGoogleServiceAccount
	if json.Unmarshal([]byte(raw), &account) != nil || account.ProjectID == "" || account.ClientEmail == "" || account.PrivateKey == "" || strings.ContainsAny(account.ProjectID, "/\\?#\r\n\t ") {
		return nil, errors.New("invalid service account")
	}
	if account.TokenURI == "" {
		account.TokenURI = "https://oauth2.googleapis.com/token"
	}
	return &account, nil
}

func (p *httpModelProber) nativeGoogleToken(ctx context.Context, account *nativeGoogleServiceAccount) (string, int, error) {
	check := ModelProbeRequest{BaseURL: account.TokenURI, APIKey: "validation", AuthMode: "bearer", DeploymentName: "oauth", Protocol: "chat"}
	if _, _, _, err := validateModelProbeRequest(check); err != nil {
		return "", 0, err
	}
	client, err := p.clientFor(ctx, account.TokenURI, false)
	if err != nil {
		return "", 0, err
	}
	assertion, err := signedNativeGoogleJWT(account, time.Now())
	if err != nil {
		return "", 0, err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, account.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return "", 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", response.StatusCode, errors.New("OAuth exchange failed")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, modelProbeResponseBodyLimit+1))
	if err != nil {
		return "", response.StatusCode, err
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if len(raw) > modelProbeResponseBodyLimit || json.Unmarshal(raw, &token) != nil || strings.TrimSpace(token.AccessToken) == "" {
		return "", response.StatusCode, errors.New("invalid OAuth response")
	}
	return token.AccessToken, response.StatusCode, nil
}

func parseNativeBedrockCredential(raw string) (nativeBedrockCredential, error) {
	var credential nativeBedrockCredential
	if strings.TrimSpace(raw) == "" {
		return credential, errors.New("bedrock provider is not configured with AWS credential JSON")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return credential, fmt.Errorf("bedrock: invalid AWS credential JSON: %w", err)
	}
	credential.AccessKeyID = bedrockStringField(fields, "access_key_id", "aws_access_key_id", "accessKeyId")
	credential.SecretAccessKey = bedrockStringField(fields, "secret_access_key", "aws_secret_access_key", "secretAccessKey")
	credential.SessionToken = bedrockStringField(fields, "session_token", "aws_session_token", "sessionToken")
	credential.Region = bedrockStringField(fields, "region", "aws_region")
	if credential.AccessKeyID == "" || credential.SecretAccessKey == "" {
		return credential, errors.New("bedrock: AWS credential JSON must include access_key_id and secret_access_key")
	}
	if credential.Region == "" {
		return credential, errors.New("bedrock: AWS credential JSON must include region")
	}
	return credential, nil
}

func bedrockStringField(fields map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		raw, ok := fields[name]
		if !ok {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func signedNativeGoogleJWT(account *nativeGoogleServiceAccount, now time.Time) (string, error) {
	block, _ := pem.Decode([]byte(account.PrivateKey))
	if block == nil {
		return "", errors.New("gemini service-account private_key is not PEM encoded")
	}
	var privateKey *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		privateKey, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("gemini service-account private_key is not RSA")
		}
	} else if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		privateKey = parsed
	} else {
		return "", errors.New("gemini service-account private_key could not be parsed")
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]interface{}{
		"iss":   account.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   account.TokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(55 * time.Minute).Unix(),
	})
	encodedClaims := base64.RawURLEncoding.EncodeToString(claims)
	unsigned := header + "." + encodedClaims
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("gemini service-account JWT signing failed: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
