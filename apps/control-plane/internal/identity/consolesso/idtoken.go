package consolesso

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	maxIDTokenBytes = 16 << 10
	clockSkew       = 60 * time.Second
)

// ErrInvalidIDToken 覆盖所有校验失败；具体原因只进日志，不回给浏览器。
var ErrInvalidIDToken = errors.New("console sso: invalid id_token")

// Claims 是控制台登录需要的最小声明集。角色不从 token 取，一律以库为准。
type Claims struct {
	Issuer            string
	Subject           string
	PreferredUsername string
	Email             string
	SessionID         string
	ExpiresAt         time.Time
}

type rawClaims struct {
	Iss               string          `json:"iss"`
	Sub               string          `json:"sub"`
	Aud               json.RawMessage `json:"aud"`
	Azp               string          `json:"azp"`
	Exp               json.Number     `json:"exp"`
	Iat               json.Number     `json:"iat"`
	Nbf               json.Number     `json:"nbf"`
	Nonce             string          `json:"nonce"`
	Sid               string          `json:"sid"`
	PreferredUsername string          `json:"preferred_username"`
	Email             string          `json:"email"`
}

type verifyOptions struct {
	issuer   string
	audience string
	nonce    string
	now      time.Time
}

// verifyIDToken 手写 JWS 校验：只接受 RS256（拒绝 none/HS*/alg 混淆），
// 校验签名、iss、aud（多 aud 时要求 azp=client_id）、exp/nbf/iat、nonce（常量时间比较）。
func verifyIDToken(ctx context.Context, keys keySource, token string, opts verifyOptions) (Claims, error) {
	if len(token) == 0 || len(token) > maxIDTokenBytes {
		return Claims{}, ErrInvalidIDToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalidIDToken
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrInvalidIDToken
	}
	var header struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Crit json.RawMessage `json:"crit"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Claims{}, ErrInvalidIDToken
	}
	if header.Alg != "RS256" || header.Kid == "" || len(header.Crit) != 0 {
		return Claims{}, ErrInvalidIDToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrInvalidIDToken
	}
	pub, err := keys.key(ctx, header.Kid)
	if err != nil {
		return Claims{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return Claims{}, ErrInvalidIDToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidIDToken
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	var c rawClaims
	if err := dec.Decode(&c); err != nil {
		return Claims{}, ErrInvalidIDToken
	}
	if c.Iss != opts.issuer || strings.TrimSpace(c.Sub) == "" {
		return Claims{}, ErrInvalidIDToken
	}
	if !audienceOK(c.Aud, c.Azp, opts.audience) {
		return Claims{}, ErrInvalidIDToken
	}
	exp, ok := unixSeconds(c.Exp)
	if !ok || !opts.now.Before(exp.Add(clockSkew)) {
		return Claims{}, ErrInvalidIDToken
	}
	if nbf, ok := unixSeconds(c.Nbf); ok && opts.now.Add(clockSkew).Before(nbf) {
		return Claims{}, ErrInvalidIDToken
	}
	if iat, ok := unixSeconds(c.Iat); !ok || opts.now.Add(clockSkew).Before(iat) {
		return Claims{}, ErrInvalidIDToken
	}
	if opts.nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(opts.nonce)) != 1 {
		return Claims{}, ErrInvalidIDToken
	}
	return Claims{
		Issuer: c.Iss, Subject: c.Sub, PreferredUsername: c.PreferredUsername,
		Email: c.Email, SessionID: c.Sid, ExpiresAt: exp,
	}, nil
}

func audienceOK(raw json.RawMessage, azp, clientID string) bool {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == clientID && (azp == "" || azp == clientID)
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil || len(many) == 0 {
		return false
	}
	found := false
	for _, a := range many {
		if a == clientID {
			found = true
		}
	}
	if !found {
		return false
	}
	if len(many) > 1 {
		return azp == clientID
	}
	return azp == "" || azp == clientID
}

func unixSeconds(n json.Number) (time.Time, bool) {
	if n == "" {
		return time.Time{}, false
	}
	v, err := n.Int64()
	if err != nil || v <= 0 {
		return time.Time{}, false
	}
	return time.Unix(v, 0), true
}
