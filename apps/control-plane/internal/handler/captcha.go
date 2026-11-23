package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	captchaTTL        = 5 * time.Minute
	captchaCodeLength = 5
	captchaAlphabet   = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	captchaKeyPrefix  = "auth:captcha:"
	// captchaRedisTimeout 限制验证码对 Redis 的单次等待。磁盘抖动时 Redis fsync 变慢，
	// 等满默认超时会让登录页卡住几秒后才报「验证码加载失败」。
	captchaRedisTimeout = 800 * time.Millisecond
	// captchaFallbackMaxEntries 是 Redis 不可用时进程内降级存储的上限，防止被刷爆内存。
	captchaFallbackMaxEntries = 5000
)

// captchaLocalStore 是 Redis 暂时不可用时的进程内降级存储：同样 5 分钟过期、一次性。
// 单个控制面实例内有效；多实例部署时降级期间可能需要重新获取验证码，可以接受。
type captchaLocalStore struct {
	mu      sync.Mutex
	entries map[string]captchaLocalEntry
}

type captchaLocalEntry struct {
	digest    string
	expiresAt time.Time
}

var captchaFallback = &captchaLocalStore{entries: map[string]captchaLocalEntry{}}

// captchaFallbackIssuedHook 仅供测试观察降级签发的验证码，生产为 nil。
var captchaFallbackIssuedHook func(id, code string)

func (s *captchaLocalStore) put(id, digest string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if len(s.entries) >= captchaFallbackMaxEntries {
		for key, entry := range s.entries {
			if now.After(entry.expiresAt) {
				delete(s.entries, key)
			}
		}
		for key := range s.entries {
			if len(s.entries) < captchaFallbackMaxEntries {
				break
			}
			delete(s.entries, key)
		}
	}
	s.entries[id] = captchaLocalEntry{digest: digest, expiresAt: now.Add(captchaTTL)}
}

// take 取出并删除（一次性）；不存在或已过期返回 false。
func (s *captchaLocalStore) take(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[id]
	if !ok {
		return "", false
	}
	delete(s.entries, id)
	if time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.digest, true
}

func (s *captchaLocalStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

type captchaResponse struct {
	CaptchaID string `json:"captcha_id"`
	Image     string `json:"image"`
	ExpiresIn int    `json:"expires_in"`
}

func captchaRedisKey(id string) string {
	return captchaKeyPrefix + id
}

func captchaDigest(code string) string {
	normalized := strings.ToUpper(strings.TrimSpace(code))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func randomCaptchaCode() (string, error) {
	code := make([]byte, captchaCodeLength)
	limit := big.NewInt(int64(len(captchaAlphabet)))
	for i := range code {
		index, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		code[i] = captchaAlphabet[index.Int64()]
	}
	return string(code), nil
}

func randomCaptchaOffset(max int64) int64 {
	value, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return value.Int64()
}

func renderCaptchaSVG(code string) string {
	var text strings.Builder
	for index, character := range code {
		x := 22 + index*25
		y := 31 + int(randomCaptchaOffset(7))
		rotation := int(randomCaptchaOffset(25)) - 12
		fmt.Fprintf(&text, `<text x="%d" y="%d" transform="rotate(%d %d %d)">%c</text>`, x, y, rotation, x, y, character)
	}

	var noise strings.Builder
	for i := 0; i < 7; i++ {
		fmt.Fprintf(
			&noise,
			`<line x1="%d" y1="%d" x2="%d" y2="%d"/>`,
			randomCaptchaOffset(145), randomCaptchaOffset(44),
			randomCaptchaOffset(145), randomCaptchaOffset(44),
		)
	}

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="145" height="44" viewBox="0 0 145 44">
<rect width="145" height="44" rx="6" fill="#eef4fb"/>
<g stroke="#7aa7d9" stroke-width="1" opacity=".35">%s</g>
<g fill="#173b63" font-family="Arial,sans-serif" font-size="25" font-weight="700">%s</g>
</svg>`, noise.String(), text.String())
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))
}

// Captcha creates a short-lived, single-use login challenge.
func Captcha(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.RedisClient == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "captcha_unavailable", "captcha service unavailable")
			return
		}
		code, err := randomCaptchaCode()
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "captcha_generation_failed", "failed to generate captcha")
			return
		}
		id := uuid.NewString()
		setCtx, cancel := context.WithTimeout(r.Context(), captchaRedisTimeout)
		err = deps.RedisClient.Set(setCtx, captchaRedisKey(id), captchaDigest(code), captchaTTL).Err()
		cancel()
		if err != nil {
			// Redis 暂时不可用时降级到进程内存储，不让磁盘抖动直接导致无法登录。
			log.Printf("captcha: redis unavailable, using local fallback: %v", err)
			captchaFallback.put(id, captchaDigest(code))
			if captchaFallbackIssuedHook != nil {
				captchaFallbackIssuedHook(id, code)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_ = json.NewEncoder(w).Encode(captchaResponse{
			CaptchaID: id,
			Image:     renderCaptchaSVG(code),
			ExpiresIn: int(captchaTTL.Seconds()),
		})
	}
}

func validateCaptcha(ctx context.Context, client *redis.Client, id, code string) (bool, error) {
	id = strings.TrimSpace(id)
	code = strings.TrimSpace(code)
	if client == nil {
		return false, fmt.Errorf("captcha store is not configured")
	}
	if id == "" || len(id) > 128 || code == "" || len(code) > 16 {
		return false, nil
	}

	expected := captchaDigest(code)
	// 降级期间签发的验证码只在进程内；先查本地，命中即一次性消费。
	if local, ok := captchaFallback.take(id); ok {
		return subtle.ConstantTimeCompare([]byte(local), []byte(expected)) == 1, nil
	}
	getCtx, cancel := context.WithTimeout(ctx, captchaRedisTimeout)
	defer cancel()
	stored, err := client.GetDel(getCtx, captchaRedisKey(id)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(expected)) == 1, nil
}
