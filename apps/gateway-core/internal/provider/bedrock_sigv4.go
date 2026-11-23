package provider

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func signBedrockRequest(req *http.Request, credential bedrockCredential) error {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("bedrock: read request body for signing: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	shortDate := now.Format("20060102")
	payloadHash := bedrockSHA256Hex(body)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if credential.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", credential.SessionToken)
	}
	canonicalHeaders, signedHeaders := bedrockCanonicalHeaders(req, host)
	canonicalRequest := strings.Join([]string{
		req.Method,
		bedrockCanonicalURI(req.URL),
		bedrockCanonicalQuery(req.URL),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
	scope := shortDate + "/" + credential.Region + "/bedrock/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		bedrockSHA256Hex([]byte(canonicalRequest)),
	}, "\n")
	signingKey := bedrockSigningKey(credential.SecretAccessKey, shortDate, credential.Region, "bedrock")
	signature := hex.EncodeToString(bedrockHMAC(signingKey, stringToSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+credential.AccessKeyID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
	return nil
}

func bedrockCanonicalHeaders(req *http.Request, host string) (string, string) {
	values := map[string]string{
		"content-type":         req.Header.Get("Content-Type"),
		"host":                 host,
		"x-amz-content-sha256": req.Header.Get("X-Amz-Content-Sha256"),
		"x-amz-date":           req.Header.Get("X-Amz-Date"),
	}
	if token := req.Header.Get("X-Amz-Security-Token"); token != "" {
		values["x-amz-security-token"] = token
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonical strings.Builder
	for _, name := range names {
		canonical.WriteString(name)
		canonical.WriteByte(':')
		canonical.WriteString(strings.Join(strings.Fields(values[name]), " "))
		canonical.WriteByte('\n')
	}
	return canonical.String(), strings.Join(names, ";")
}

func bedrockCanonicalURI(parsed *url.URL) string {
	if path := parsed.EscapedPath(); path != "" {
		return path
	}
	return "/"
}

func bedrockCanonicalQuery(parsed *url.URL) string {
	if parsed.RawQuery == "" {
		return ""
	}
	type pair struct{ key, value string }
	values := parsed.Query()
	pairs := make([]pair, 0)
	for key, list := range values {
		if len(list) == 0 {
			list = []string{""}
		}
		for _, value := range list {
			pairs = append(pairs, pair{bedrockPercentEncode(key), bedrockPercentEncode(value)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key == pairs[j].key {
			return pairs[i].value < pairs[j].value
		}
		return pairs[i].key < pairs[j].key
	})
	encoded := make([]string, 0, len(pairs))
	for _, item := range pairs {
		encoded = append(encoded, item.key+"="+item.value)
	}
	return strings.Join(encoded, "&")
}

func bedrockPercentEncode(value string) string {
	const hexChars = "0123456789ABCDEF"
	var encoded strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			encoded.WriteByte(c)
		} else {
			encoded.WriteByte('%')
			encoded.WriteByte(hexChars[c>>4])
			encoded.WriteByte(hexChars[c&0x0f])
		}
	}
	return encoded.String()
}

func bedrockSHA256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func bedrockHMAC(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func bedrockSigningKey(secret, date, region, service string) []byte {
	dateKey := bedrockHMAC([]byte("AWS4"+secret), date)
	regionKey := bedrockHMAC(dateKey, region)
	serviceKey := bedrockHMAC(regionKey, service)
	return bedrockHMAC(serviceKey, "aws4_request")
}
