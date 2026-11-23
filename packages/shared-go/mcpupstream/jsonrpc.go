package mcpupstream

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Envelope 是 JSON-RPC 2.0 响应包络（只取用到的字段）。
type Envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCErrorBody   `json:"error"`
}

// RPCErrorBody 是 JSON-RPC error 对象。
type RPCErrorBody struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// RPCError 是上游返回的 JSON-RPC 错误（HTTP 200 + error），原样映射不吞掉。
type RPCError struct {
	Code    int
	Message string // 已脱敏
	Data    json.RawMessage
}

func (e *RPCError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("上游返回 JSON-RPC 错误 %d", e.Code)
	}
	return fmt.Sprintf("上游返回 JSON-RPC 错误 %d：%s", e.Code, e.Message)
}

// IDKey 把 JSON-RPC id 规范成可比较的键；null / 缺失 / 非标量返回 ok=false。
func IDKey(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", false
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return "", false
	}
	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return "string:" + t, true
	case json.Number:
		return "number:" + t.String(), true
	}
	return "", false
}

// idMatchesInt 宽松比对 id：数字与字符串形态都认（有实现回 "1" 而非 1）。
func idMatchesInt(raw json.RawMessage, want int) bool {
	key, ok := IDKey(raw)
	if !ok {
		return false
	}
	w := fmt.Sprintf("%d", want)
	return key == "number:"+w || key == "string:"+w
}

// IsNullID 判断 id 缺失或为 null。
func IsNullID(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

// DecodeResponse 解析一条 JSON-RPC 响应并校验与请求 id 的关联。
// 返回 (envelope, nil) 或带分类的错误：
//   - 数组 → batch 不支持
//   - 不是 JSON-RPC（无 result/error，或 jsonrpc 字段不是 2.0 且无 result/error）→ NotJSONRPC
//   - id 不匹配 → 错误（唯一例外：error 响应的 id 为 null，按“无法关联的错误”接受）
func DecodeResponse(body []byte, wantID int, status int, secrets ...string) (*Envelope, error) {
	trimmed := bytes.TrimSpace(body)
	if bytes.HasPrefix(trimmed, []byte("[")) {
		return nil, Errorf(KindParse, "MCP JSON-RPC batch 响应不受支持")
	}
	var env Envelope
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return nil, NotJSONRPC(status, body, secrets...)
	}
	if len(env.Result) == 0 && env.Error == nil {
		return nil, NotJSONRPC(status, body, secrets...)
	}
	if !idMatchesInt(env.ID, wantID) {
		if env.Error != nil && IsNullID(env.ID) {
			return &env, nil
		}
		return nil, Errorf(KindParse, "MCP 响应 id 与请求不匹配")
	}
	return &env, nil
}

func (e *Envelope) rpcError(secrets ...string) error {
	if e.Error == nil {
		return nil
	}
	msg := strings.TrimSpace(e.Error.Message)
	return &RPCError{Code: e.Error.Code, Message: Summarize([]byte(msg), secrets...), Data: e.Error.Data}
}

func jsonUnmarshal(b []byte, v interface{}) error { return json.Unmarshal(b, v) }
