package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// 客户现场回归：磁盘抖动时 Redis 写入超时，验证码接口 3～12 秒后返回 503，
// 登录页显示「验证码加载失败」。Redis 暂时不可用时，验证码应降级到进程内短期存储，
// 仍保持 5 分钟有效、一次性、错答即作废。
func TestCaptchaFallsBackToLocalStoreWhenRedisUnavailable(t *testing.T) {
	resetCaptchaFallbackForTest()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	server.Close() // 模拟 Redis 不可用

	rec := httptest.NewRecorder()
	Captcha(&Dependencies{RedisClient: client}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/v1/captcha", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("Redis 不可用时验证码应降级仍可用，得到 %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CaptchaID string `json:"captcha_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.CaptchaID == "" {
		t.Fatalf("decode: %v %s", err, rec.Body.String())
	}
	code, ok := captchaFallbackCodeForTest(resp.CaptchaID)
	if !ok {
		t.Fatal("降级存储里应有这道验证码")
	}
	if valid, err := validateCaptcha(context.Background(), client, resp.CaptchaID, code); err != nil || !valid {
		t.Fatalf("降级验证码应能校验通过：valid=%v err=%v", valid, err)
	}
	if valid, _ := validateCaptcha(context.Background(), client, resp.CaptchaID, code); valid {
		t.Fatal("降级验证码必须一次性")
	}
}

func TestCaptchaFallbackWrongAnswerConsumesAndIsBounded(t *testing.T) {
	resetCaptchaFallbackForTest()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	server.Close()

	id := "fallback-wrong"
	captchaFallback.put(id, captchaDigest("K7M2P"))
	if valid, _ := validateCaptcha(context.Background(), client, id, "WRONG"); valid {
		t.Fatal("错答必须失败")
	}
	if valid, _ := validateCaptcha(context.Background(), client, id, "K7M2P"); valid {
		t.Fatal("错答后验证码必须作废")
	}
	for i := 0; i < captchaFallbackMaxEntries+500; i++ {
		captchaFallback.put("flood-"+itoaCaptchaTest(i), "x")
	}
	if n := captchaFallback.size(); n > captchaFallbackMaxEntries {
		t.Fatalf("降级存储必须有上限，当前 %d", n)
	}
}

func itoaCaptchaTest(i int) string {
	b := []byte{}
	if i == 0 {
		return "0"
	}
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
