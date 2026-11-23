package handler

// W1 1.1：MCP JSON-RPC 严格解析 + 规范化重序列化。
//
// 网关判定与上游执行必须看到同一请求。Go encoding/json 解码时键名大小写不敏感、
// 重复键后者覆盖；其他语言的上游可能区分大小写或取前者。因此：
//   - 任意层级对象内，两个键在大小写折叠后相同（含完全重复）一律拒绝（-32600）；
//   - 非法 UTF-8 拒绝（Go 会静默替换成 U+FFFD，与上游看到的字节不同）；
//   - 字段只按精确小写键读取；
//   - 转发给上游的是网关重新序列化的规范载荷，只含网关判定过的键，不转发原始 body。

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

var errMCPAmbiguousPayload = errors.New("MCP 请求含重复键或仅大小写不同的键，已按协议拒绝")

// mcpStrictValidate 逐 token 扫描整个 JSON 值，拒绝对象内大小写折叠后重复的键。
func mcpStrictValidate(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("%w（非法 UTF-8）", errMCPAmbiguousPayload)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := mcpStrictWalk(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("JSON-RPC 载荷含多余内容")
	}
	return nil
}

func mcpStrictWalk(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := keyTok.(string)
			folded := strings.ToLower(key)
			if _, dup := seen[folded]; dup {
				return fmt.Errorf("%w：%q", errMCPAmbiguousPayload, key)
			}
			seen[folded] = struct{}{}
			if err := mcpStrictWalk(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // '}'
		return err
	case '[':
		for dec.More() {
			if err := mcpStrictWalk(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // ']'
		return err
	}
	return nil
}

// mcpExactObject 把已通过严格校验的对象解成「精确键 → 原始值」。
func mcpExactObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return nil, false
	}
	return obj, true
}

func mcpExactString(obj map[string]json.RawMessage, key string) (string, bool, error) {
	raw, ok := obj[key]
	if !ok {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", true, fmt.Errorf("%s 必须是字符串", key)
	}
	return s, true, nil
}

func mcpCompact(raw json.RawMessage) (json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// mcpMarshalNoEscape 与 json.Marshal 相同但不把 <>& 转成 \u003c 等（不改写字面内容）。
func mcpMarshalNoEscape(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// mcpCanonicalParamKeys：对网关按字段判定的方法，params 只转发这些精确键。
// 其余方法 params 原样（已严格校验、紧凑化）转发——网关对它们只按方法名判定，不读字段。
var mcpCanonicalParamKeys = map[string][]string{
	"tools/call":     {"name", "arguments", "_meta"},
	"resources/read": {"uri", "_meta"},
	"prompts/get":    {"name", "arguments", "_meta"},
	"initialize":     {"protocolVersion", "capabilities", "clientInfo", "_meta"},
}

// parseMCPStrictMessage 严格解析单条 JSON-RPC 消息，返回判定用投影与规范化转发体。
func parseMCPStrictMessage(body []byte) (mcpRPCMessage, []byte, error) {
	var msg mcpRPCMessage
	if err := mcpStrictValidate(body); err != nil {
		return msg, nil, err
	}
	top, ok := mcpExactObject(body)
	if !ok {
		return msg, nil, fmt.Errorf("非法 JSON-RPC 载荷")
	}
	version, hasVersion, err := mcpExactString(top, "jsonrpc")
	if err != nil || !hasVersion || version != "2.0" {
		return msg, nil, fmt.Errorf("%w（jsonrpc 必须为 \"2.0\"）", errMCPInvalidRequest)
	}
	msg.JSONRPC = version
	method, hasMethod, err := mcpExactString(top, "method")
	if err != nil {
		return msg, nil, fmt.Errorf("%w（%v）", errMCPInvalidRequest, err)
	}
	method = canonicalMCPMethod(method)
	msg.Method = method

	var keys []string
	out := map[string]json.RawMessage{"jsonrpc": json.RawMessage(`"2.0"`)}
	keys = append(keys, "jsonrpc")
	if id, ok := top["id"]; ok {
		compacted, err := mcpCompact(id)
		if err != nil {
			return msg, nil, err
		}
		msg.ID = compacted
		out["id"] = compacted
		keys = append(keys, "id")
	}
	if hasMethod {
		out["method"], _ = mcpMarshalNoEscape(method)
		keys = append(keys, "method")
	} else {
		// 客户端对服务端请求的响应（result/error）：只转发这两个精确键。
		for _, key := range []string{"result", "error"} {
			if raw, ok := top[key]; ok {
				compacted, err := mcpCompact(raw)
				if err != nil {
					return msg, nil, err
				}
				out[key] = compacted
				keys = append(keys, key)
			}
		}
		if len(keys) == 1 || msg.ID == nil {
			return msg, nil, fmt.Errorf("%w（缺少 method）", errMCPInvalidRequest)
		}
	}
	if rawParams, ok := top["params"]; ok && hasMethod {
		params, err := mcpCanonicalParams(method, rawParams, &msg)
		if err != nil {
			return msg, nil, err
		}
		out["params"] = params
		keys = append(keys, "params")
	} else if hasMethod {
		if _, need := mcpCanonicalParamKeys[method]; need && method != "initialize" {
			return msg, nil, fmt.Errorf("%w（%s 缺少 params）", errMCPInvalidRequest, method)
		}
	}
	canonical, err := mcpOrderedObject(keys, out)
	return msg, canonical, err
}

var errMCPInvalidRequest = errors.New("非法 JSON-RPC 请求")

func mcpCanonicalParams(method string, rawParams json.RawMessage, msg *mcpRPCMessage) (json.RawMessage, error) {
	allowed, fieldLevel := mcpCanonicalParamKeys[method]
	if !fieldLevel {
		return mcpCompact(rawParams)
	}
	params, ok := mcpExactObject(rawParams)
	if !ok {
		return nil, fmt.Errorf("%w（params 必须是对象）", errMCPInvalidRequest)
	}
	switch method {
	case "tools/call", "prompts/get":
		name, has, err := mcpExactString(params, "name")
		if err != nil || !has || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("%w（%s 缺少 params.name）", errMCPInvalidRequest, method)
		}
		msg.Params.Name = name
		if args, ok := params["arguments"]; ok {
			compacted, err := mcpCompact(args)
			if err != nil {
				return nil, err
			}
			msg.Params.Arguments = compacted
		}
	case "resources/read":
		uri, has, err := mcpExactString(params, "uri")
		if err != nil || !has || uri == "" {
			return nil, fmt.Errorf("%w（resources/read 缺少 params.uri）", errMCPInvalidRequest)
		}
		msg.Params.URI = uri
	case "initialize":
		version, _, err := mcpExactString(params, "protocolVersion")
		if err != nil {
			return nil, fmt.Errorf("%w（%v）", errMCPInvalidRequest, err)
		}
		msg.Params.ProtocolVersion = version
	}
	out := make(map[string]json.RawMessage, len(allowed))
	var keys []string
	for _, key := range allowed {
		raw, ok := params[key]
		if !ok {
			continue
		}
		if key == "name" || key == "uri" || key == "protocolVersion" {
			var s string
			_ = json.Unmarshal(raw, &s)
			raw, _ = mcpMarshalNoEscape(s)
		} else {
			compacted, err := mcpCompact(raw)
			if err != nil {
				return nil, err
			}
			raw = compacted
		}
		out[key] = raw
		keys = append(keys, key)
	}
	return mcpOrderedObject(keys, out)
}

func mcpOrderedObject(keys []string, values map[string]json.RawMessage) (json.RawMessage, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		encodedKey, err := mcpMarshalNoEscape(key)
		if err != nil {
			return nil, err
		}
		buf.Write(encodedKey)
		buf.WriteByte(':')
		buf.Write(values[key])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}
