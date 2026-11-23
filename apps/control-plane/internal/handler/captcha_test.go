package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func captchaTestClient(t *testing.T) *redis.Client {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestCaptchaReturnsNoStoreSVGChallenge(t *testing.T) {
	client := captchaTestClient(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/captcha", nil)

	Captcha(&Dependencies{RedisClient: client}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected no-store cache policy, got %q", got)
	}
	var response struct {
		CaptchaID string `json:"captcha_id"`
		Image     string `json:"image"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.CaptchaID == "" || !strings.HasPrefix(response.Image, "data:image/svg+xml;base64,") {
		t.Fatalf("invalid captcha response: %#v", response)
	}
	if response.ExpiresIn != 300 {
		t.Fatalf("expected 300 second expiry, got %d", response.ExpiresIn)
	}
	if exists, err := client.Exists(context.Background(), captchaRedisKey(response.CaptchaID)).Result(); err != nil || exists != 1 {
		t.Fatalf("captcha challenge was not persisted: exists=%d err=%v", exists, err)
	}
}

func TestValidateCaptchaIsCaseInsensitiveAndSingleUse(t *testing.T) {
	client := captchaTestClient(t)
	const captchaID = "challenge-id"
	if err := client.Set(context.Background(), captchaRedisKey(captchaID), captchaDigest("A7bK2"), captchaTTL).Err(); err != nil {
		t.Fatal(err)
	}

	valid, err := validateCaptcha(context.Background(), client, captchaID, "a7Bk2")
	if err != nil || !valid {
		t.Fatalf("expected valid captcha, got valid=%v err=%v", valid, err)
	}
	valid, err = validateCaptcha(context.Background(), client, captchaID, "A7BK2")
	if err != nil || valid {
		t.Fatalf("captcha must be consumed after one attempt, got valid=%v err=%v", valid, err)
	}
}

func TestValidateCaptchaConsumesChallengeAfterWrongAnswer(t *testing.T) {
	client := captchaTestClient(t)
	const captchaID = "wrong-answer-challenge"
	if err := client.Set(context.Background(), captchaRedisKey(captchaID), captchaDigest("K7M2P"), captchaTTL).Err(); err != nil {
		t.Fatal(err)
	}

	if valid, err := validateCaptcha(context.Background(), client, captchaID, "WRONG"); err != nil || valid {
		t.Fatalf("wrong answer must fail: valid=%v err=%v", valid, err)
	}
	if valid, err := validateCaptcha(context.Background(), client, captchaID, "K7M2P"); err != nil || valid {
		t.Fatalf("challenge must be consumed after a wrong answer: valid=%v err=%v", valid, err)
	}
}

func TestLoginRejectsMissingCaptchaBeforeCredentialLookup(t *testing.T) {
	client := captchaTestClient(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/login", strings.NewReader(`{"username":"admin","password":"secret"}`))

	Login(&Dependencies{RedisClient: client}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"code":"invalid_captcha"`) {
		t.Fatalf("expected invalid_captcha error, got %s", recorder.Body.String())
	}
}
