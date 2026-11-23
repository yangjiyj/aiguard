package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// RFC 6238 TOTP：SHA1、6 位、30 秒步长，与主流验证器 App 兼容。只用标准库，不引新依赖。
const (
	totpDigits = 6
	totpPeriod = 30
	totpSkew   = 1 // 允许前后各 1 个时间步，容忍客户端时钟漂移
	totpIssuer = "JJDGuard"
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func generateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return totpEncoding.EncodeToString(buf), nil
}

func totpCodeAt(secret string, counter uint64) (string, error) {
	key, err := totpEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("invalid totp secret")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000), nil
}

// verifyTOTP returns the matched time-step counter (for replay protection) and whether it matched.
func verifyTOTP(secret, code string, now time.Time) (uint64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	current := uint64(now.Unix() / totpPeriod)
	for delta := -totpSkew; delta <= totpSkew; delta++ {
		counter := current + uint64(int64(delta))
		expected, err := totpCodeAt(secret, counter)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return counter, true
		}
	}
	return 0, false
}

func totpProvisioningURI(username, secret string) string {
	label := url.PathEscape(totpIssuer + ":" + username)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", totpIssuer)
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
