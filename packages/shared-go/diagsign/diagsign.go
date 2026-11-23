// Package diagsign 实现诊断控制面与宿主机采集器之间的任务签名协议。
//
// canonical = id|action|issued_at| + 参数按 key 排序后的紧凑 JSON（不转义 HTML 字符）。
// sig = hex(hmac-sha256(key, canonical))。
package diagsign

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const (
	// MaxAge 是任务从签发到被接受的最长时间。
	MaxAge = 120 * time.Second
	// MaxFutureSkew 是允许的时钟超前量。
	MaxFutureSkew = 30 * time.Second
	// MaxOutputBytes 是结果输出的上限。
	MaxOutputBytes = 64 * 1024
)

var (
	ErrBadSignature = errors.New("bad_signature")
	ErrExpired      = errors.New("expired")
	ErrBadTime      = errors.New("bad_issued_at")
	ErrEmptyKey     = errors.New("empty_key")
)

// Task 是写入 inbox/<id>.json 的任务。
type Task struct {
	ID       string         `json:"id"`
	Action   string         `json:"action"`
	Params   map[string]any `json:"params"`
	IssuedAt string         `json:"issued_at"`
	Sig      string         `json:"sig"`
}

// Result 是写入 outbox/<id>.json 的结果。
type Result struct {
	ID         string `json:"id"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Output     string `json:"output"`
	Truncated  bool   `json:"truncated"`
	FinishedAt string `json:"finished_at"`
}

// Canonical 返回待签名的规范字节串。
func Canonical(id, action, issuedAt string, params map[string]any) []byte {
	var b bytes.Buffer
	b.WriteString(id)
	b.WriteByte('|')
	b.WriteString(action)
	b.WriteByte('|')
	b.WriteString(issuedAt)
	b.WriteByte('|')
	if params == nil {
		params = map[string]any{}
	}
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(params); err != nil {
		b.WriteString("{}")
		return b.Bytes()
	}
	// Encode 末尾带换行
	out := b.Bytes()
	return bytes.TrimRight(out, "\n")
}

// Sign 对任务内容签名，返回十六进制字符串。
func Sign(key []byte, id, action, issuedAt string, params map[string]any) string {
	m := hmac.New(sha256.New, key)
	m.Write(Canonical(id, action, issuedAt, params))
	return hex.EncodeToString(m.Sum(nil))
}

// Verify 以当前时间校验签名与时效。
func Verify(key []byte, task Task) error {
	return VerifyAt(key, task, time.Now())
}

// VerifyAt 校验签名与时效（以 now 为准）。先验签，再验时间。
func VerifyAt(key []byte, task Task, now time.Time) error {
	if len(key) == 0 {
		return ErrEmptyKey
	}
	got, err := hex.DecodeString(task.Sig)
	if err != nil {
		return ErrBadSignature
	}
	m := hmac.New(sha256.New, key)
	m.Write(Canonical(task.ID, task.Action, task.IssuedAt, task.Params))
	if !hmac.Equal(got, m.Sum(nil)) {
		return ErrBadSignature
	}
	t, err := time.Parse(time.RFC3339, task.IssuedAt)
	if err != nil {
		return ErrBadTime
	}
	if now.Sub(t) > MaxAge || t.Sub(now) > MaxFutureSkew {
		return ErrExpired
	}
	return nil
}
