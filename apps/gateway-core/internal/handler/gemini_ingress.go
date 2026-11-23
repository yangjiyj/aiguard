package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

const geminiBridgeLimit = 32 << 20

// GeminiIngressHandler translates the explicitly supported stateless Google
// contract through the existing protected Chat handler. Output is inspected by
// that handler before this bounded adapter emits a complete Gemini response.
type GeminiIngressHandler struct {
	cfg             *config.Config
	protectedChat   http.Handler
	protectedModels http.Handler
}

func NewGeminiIngressHandler(cfg *config.Config, protectedChat http.Handler, models ...http.Handler) *GeminiIngressHandler {
	h := &GeminiIngressHandler{cfg: cfg, protectedChat: protectedChat}
	if len(models) > 0 {
		h.protectedModels = models[0]
	}
	return h
}

func geminiIngressPath(path string) (model string, stream, ok bool) {
	for _, prefix := range []string{"/v1beta/models/", "/v1/models/"} {
		if strings.HasPrefix(path, prefix) {
			tail := strings.TrimPrefix(path, prefix)
			for _, suffix := range []string{":generateContent", ":streamGenerateContent"} {
				if strings.HasSuffix(tail, suffix) {
					model = strings.TrimSuffix(tail, suffix)
					return model, suffix == ":streamGenerateContent", model != ""
				}
			}
		}
	}
	return "", false, false
}

// GeminiURLCredentialGuard must precede the access logger: query credentials
// are rejected and removed from both URL representations before any observer.
func GeminiURLCredentialGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1beta" || strings.HasPrefix(r.URL.Path, "/v1beta/") || r.URL.Path == "/v1/models" || strings.HasPrefix(r.URL.Path, "/v1/models/") {
			query, err := url.ParseQuery(r.URL.RawQuery)
			_, hasKey := query["key"]
			if err != nil || hasKey {
				query.Del("key")
				r.URL.RawQuery = query.Encode()
				r.RequestURI = r.URL.RequestURI()
				message := "API keys in URLs are not supported; use X-Goog-Api-Key or Authorization."
				if err != nil {
					r.URL.RawQuery = ""
					r.RequestURI = r.URL.RequestURI()
					message = "Invalid Google request query."
				}
				writeGeminiError(w, 400, message)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// geminiErrorStatus 把状态码规整到 400-599（其余视为 502），并返回对应的 Google 错误 status 名。
func geminiErrorStatus(status int) (int, string) {
	if status < 400 || status > 599 {
		status = 502
	}
	kind := map[int]string{400: "INVALID_ARGUMENT", 401: "UNAUTHENTICATED", 403: "PERMISSION_DENIED", 404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 413: "RESOURCE_EXHAUSTED", 422: "INVALID_ARGUMENT", 429: "RESOURCE_EXHAUSTED", 500: "INTERNAL", 502: "UNAVAILABLE", 503: "UNAVAILABLE", 504: "DEADLINE_EXCEEDED"}[status]
	if kind == "" {
		kind = "UNKNOWN"
	}
	return status, kind
}

// writeCommittedGeminiStreamError 在保活已发出 200 + SSE 头后，把错误改发成一帧 `data: {"error":...}`。
// 与 writeGeminiError 同一套 code/status/message，只是不再写状态码和响应头。
func writeCommittedGeminiStreamError(w http.ResponseWriter, status int, message string) {
	status, kind := geminiErrorStatus(status)
	payload, _ := json.Marshal(map[string]any{"error": map[string]any{"code": status, "status": kind, "message": message}})
	_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func writeGeminiError(w http.ResponseWriter, status int, message string) {
	status, kind := geminiErrorStatus(status)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": status, "status": kind, "message": message}})
}

func normalizeGeminiCredential(r *http.Request) error {
	tokens := []string{}
	for _, name := range []string{"X-Goog-Api-Key", "X-Api-Key"} {
		for _, value := range r.Header.Values(name) {
			if value = strings.TrimSpace(value); value != "" {
				tokens = append(tokens, value)
			}
		}
	}
	for _, value := range r.Header.Values("Authorization") {
		fields := strings.Fields(value)
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
			return errors.New("Invalid authorization format.")
		}
		tokens = append(tokens, fields[1])
	}
	for _, token := range tokens {
		if len(token) > 8192 || strings.IndexFunc(token, unicode.IsSpace) >= 0 || strings.IndexFunc(token, unicode.IsControl) >= 0 {
			return errors.New("Invalid API key header.")
		}
		if token != tokens[0] {
			return errors.New("Conflicting API key headers.")
		}
	}
	if len(tokens) > 0 {
		r.Header.Set("Authorization", "Bearer "+tokens[0])
		r.Header.Del("X-Api-Key")
		r.Header.Del("X-Goog-Api-Key")
	}
	return nil
}

type geminiCapture struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	overflow bool
}

func (c *geminiCapture) Header() http.Header { return c.header }
func (c *geminiCapture) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
}
func (c *geminiCapture) Write(data []byte) (int, error) {
	if c.status == 0 {
		c.status = 200
	}
	if c.overflow || len(data) > geminiBridgeLimit-c.body.Len() {
		c.overflow = true
		return 0, errors.New("Google response exceeds bounded buffer")
	}
	return c.body.Write(data)
}

func (h *GeminiIngressHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		model, stream, ok := geminiIngressPath(r.URL.Path)
		if !ok {
			writeGeminiError(w, 404, "This Google API method is not supported.")
			return
		}
		if len(model) > 512 || strings.ContainsAny(model, "\\?#") || strings.IndexFunc(model, unicode.IsControl) >= 0 || strings.HasPrefix(model, "/") || strings.HasSuffix(model, "/") {
			writeGeminiError(w, 400, "Invalid Google model or action path.")
			return
		}
		for _, part := range strings.Split(model, "/") {
			if part == "" || part == "." || part == ".." {
				writeGeminiError(w, 400, "Invalid Google model path.")
				return
			}
		}
		// Defense in depth for direct handler use; production also guards before logging.
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			writeGeminiError(w, 400, "Invalid Google request query.")
			return
		}
		if _, present := query["key"]; present {
			query.Del("key")
			r.URL.RawQuery = query.Encode()
			r.RequestURI = r.URL.RequestURI()
			writeGeminiError(w, 400, "API keys in URLs are not supported; use X-Goog-Api-Key or Authorization.")
			return
		}
		for key, values := range query {
			if key != "alt" || len(values) != 1 || (values[0] != "sse" && values[0] != "json") {
				writeGeminiError(w, 400, "Unsupported Google request query field.")
				return
			}
		}
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		if err = normalizeGeminiCredential(clone); err != nil {
			writeGeminiError(w, 400, err.Error())
			return
		}
		limit := apiRequestBodyLimitBytes(h.cfg)
		if limit > geminiBridgeLimit {
			limit = geminiBridgeLimit
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
		if err != nil {
			var size *http.MaxBytesError
			if errors.As(err, &size) {
				writeGeminiError(w, 413, "Google request exceeds bounded buffer.")
			} else {
				writeGeminiError(w, 400, "Failed to read Google request.")
			}
			return
		}
		chat, err := geminiRequestToChat(raw, model)
		if err != nil {
			writeGeminiError(w, 400, err.Error())
			return
		}
		if h.protectedChat == nil {
			writeGeminiError(w, 503, "Google model gateway is unavailable.")
			return
		}
		body, err := json.Marshal(chat)
		if err != nil {
			writeGeminiError(w, 400, "Invalid Google request.")
			return
		}
		clone.Body = io.NopCloser(bytes.NewReader(body))
		clone.GetBody = nil
		clone.ContentLength = int64(len(body))
		clone.Header.Set("Content-Type", "application/json")
		clone.Header.Del("Content-Length")
		clone.Header.Set("Accept", "application/json")
		originalURL := *r.URL
		clone.URL = &originalURL
		clone.URL.Path = "/v1/chat/completions"
		clone.URL.RawPath = ""
		clone.URL.RawQuery = ""
		clone.RequestURI = clone.URL.RequestURI()
		captured := &geminiCapture{header: make(http.Header)}

		// streamGenerateContent 的整段生成 + 输出安全扫描都发生在 protectedChat.ServeHTTP 里，期间客户端
		// 收不到任何字节。这里对真实的 w 做连接保活：只发单个换行（Google SDK / Gemini CLI 都接受；
		// SSE 注释 ": keepalive" 会被 Python google-genai 和 Gemini CLI 当成非法 JSON 报错）。
		// ServeHTTP 只写 captured（不支持 Flush，所以内层 chat 自己的保活不会启动），保活期间 handler
		// 不碰 w；Stop 返回后才独占 w。头已发出（状态码固定 200）后，错误改发 `data: {"error":...}` 帧。
		var keepalive *keepaliveSession
		if interval := streamKeepaliveIntervalOf(h.cfg); stream && interval > 0 {
			keepalive = newKeepaliveSession(w, interval, streamKeepaliveSpec{payload: []byte("\n"), cacheControl: "no-store"}, func() {
				w.Header().Set("X-Content-Type-Options", "nosniff")
			})
		}
		defer keepalive.Stop()
		keepalive.Start()
		h.protectedChat.ServeHTTP(captured, clone)
		committed := keepalive.Stop()
		fail := func(status int, message string) {
			if committed {
				writeCommittedGeminiStreamError(w, status, message)
				return
			}
			writeGeminiError(w, status, message)
		}
		if !committed {
			// 头已发出后再改 Header 不会生效，慢请求因此拿不到 x-request-* / x-jjdguard-* / retry-after。
			for key, values := range captured.header {
				lower := strings.ToLower(key)
				if strings.HasPrefix(lower, "x-request-") || strings.HasPrefix(lower, "x-jjdguard-") || lower == "retry-after" {
					w.Header()[key] = append([]string(nil), values...)
				}
			}
		}
		if captured.overflow {
			fail(502, "Google response exceeds the 32 MiB output buffer.")
			return
		}
		if captured.status >= 400 {
			message := "Gateway could not complete the model request."
			var payload struct {
				Error struct {
					Message string `json:"message"`
				}
			}
			if json.Unmarshal(captured.body.Bytes(), &payload) == nil && payload.Error.Message != "" {
				message = payload.Error.Message
			}
			fail(captured.status, message)
			return
		}
		response, err := geminiResponseFromChat(captured.body.Bytes())
		if err != nil {
			fail(502, err.Error())
			return
		}
		encoded, err := json.Marshal(response)
		if err != nil || len(encoded) > geminiBridgeLimit {
			fail(502, "Google response exceeds the output contract.")
			return
		}
		if !committed {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}
		if stream {
			if !committed {
				w.Header().Set("Content-Type", "text/event-stream")
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", encoded)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(encoded)
	}
}

func gObject(value any, path string) (map[string]any, error) {
	out, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", path)
	}
	return out, nil
}
func gFields(object map[string]any, path string, allowed ...string) error {
	for key := range object {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s contains an unsupported field", path)
		}
	}
	return nil
}
func gString(value any, path string) (string, error) {
	out, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", path)
	}
	return out, nil
}
func gName(value any, path string) (string, error) {
	out, err := gString(value, path)
	if err != nil || out == "" || len(out) > 256 || strings.IndexFunc(out, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("%s must be a nonempty name", path)
	}
	return out, nil
}
func gArray(value any, path string) ([]any, error) {
	out, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", path)
	}
	return out, nil
}
func gNumber(value any, path string) (json.Number, error) {
	out, ok := value.(json.Number)
	if !ok {
		return "", fmt.Errorf("%s must be numeric", path)
	}
	if _, err := out.Float64(); err != nil {
		return "", fmt.Errorf("%s must be numeric", path)
	}
	return out, nil
}

type geminiPendingCall struct{ id, name string }

func geminiRequestToChat(raw []byte, model string) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root map[string]any
	if decoder.Decode(&root) != nil || root == nil {
		return nil, errors.New("Invalid Google JSON request.")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("Google request must contain exactly one JSON object.")
	}
	if err := gFields(root, "request", "contents", "systemInstruction", "tools", "toolConfig", "generationConfig"); err != nil {
		return nil, err
	}
	messages := []any{}
	pending := []geminiPendingCall{}
	usedIDs := map[string]bool{}
	counter := 0
	if system, exists := root["systemInstruction"]; exists {
		object, err := gObject(system, "systemInstruction")
		if err != nil {
			return nil, err
		}
		if err = gFields(object, "systemInstruction", "role", "parts"); err != nil {
			return nil, err
		}
		if value, exists := object["role"]; exists {
			if _, err = gString(value, "systemInstruction.role"); err != nil {
				return nil, err
			}
		}
		parts, err := gArray(object["parts"], "systemInstruction.parts")
		if err != nil {
			return nil, err
		}
		var text strings.Builder
		for _, raw := range parts {
			part, err := gObject(raw, "systemInstruction.parts")
			if err != nil {
				return nil, err
			}
			if err = gFields(part, "systemInstruction.parts", "text"); err != nil {
				return nil, err
			}
			value, err := gString(part["text"], "systemInstruction.text")
			if err != nil {
				return nil, err
			}
			text.WriteString(value)
		}
		if text.Len() > 0 {
			messages = append(messages, map[string]any{"role": "system", "content": text.String()})
		}
	}
	contents, err := gArray(root["contents"], "contents")
	if err != nil || len(contents) == 0 {
		return nil, errors.New("contents must be a nonempty array")
	}
	for index, raw := range contents {
		path := "contents[" + strconv.Itoa(index) + "]"
		content, err := gObject(raw, path)
		if err != nil {
			return nil, err
		}
		if err = gFields(content, path, "role", "parts"); err != nil {
			return nil, err
		}
		role := "user"
		if value, exists := content["role"]; exists {
			role, err = gString(value, path+".role")
			if err != nil {
				return nil, err
			}
		}
		if role != "user" && role != "model" {
			return nil, fmt.Errorf("%s.role must be user or model", path)
		}
		if role == "model" && len(pending) > 0 {
			return nil, errors.New("pending functionCall results must precede the next model turn")
		}
		parts, err := gArray(content["parts"], path+".parts")
		if err != nil || len(parts) == 0 {
			return nil, fmt.Errorf("%s.parts must be nonempty", path)
		}
		var text strings.Builder
		calls := []any{}
		results := []any{}
		sawText := false
		for _, rawPart := range parts {
			part, err := gObject(rawPart, path+".parts")
			if err != nil {
				return nil, err
			}
			if err = gFields(part, path+".parts", "text", "functionCall", "functionResponse"); err != nil {
				return nil, err
			}
			if len(part) != 1 {
				return nil, fmt.Errorf("%s.parts must contain exactly one supported part kind", path)
			}
			if value, exists := part["text"]; exists {
				if role == "model" && len(calls) > 0 {
					return nil, errors.New("model text after functionCall has no ordered Chat mapping")
				}
				value, err := gString(value, path+".text")
				if err != nil {
					return nil, err
				}
				text.WriteString(value)
				sawText = true
				continue
			}
			if value, exists := part["functionCall"]; exists {
				if role != "model" {
					return nil, errors.New("functionCall requires model role")
				}
				call, err := gObject(value, path+".functionCall")
				if err != nil {
					return nil, err
				}
				if err = gFields(call, path+".functionCall", "id", "name", "args"); err != nil {
					return nil, err
				}
				name, err := gName(call["name"], "functionCall.name")
				if err != nil {
					return nil, err
				}
				id := ""
				if value, exists := call["id"]; exists {
					id, err = gName(value, "functionCall.id")
					if err != nil {
						return nil, err
					}
				} else {
					counter++
					id = "gemini_call_" + strconv.Itoa(counter)
				}
				if usedIDs[id] {
					return nil, errors.New("functionCall ids must be unique")
				}
				usedIDs[id] = true
				args := any(map[string]any{})
				if value, exists := call["args"]; exists {
					args, err = gObject(value, "functionCall.args")
					if err != nil {
						return nil, err
					}
				}
				encoded, _ := json.Marshal(args)
				calls = append(calls, map[string]any{"id": id, "type": "function", "function": map[string]any{"name": name, "arguments": string(encoded)}})
				pending = append(pending, geminiPendingCall{id, name})
				continue
			}
			if role != "user" || sawText {
				return nil, errors.New("functionResponse requires user role and must precede text parts")
			}
			result, err := gObject(part["functionResponse"], path+".functionResponse")
			if err != nil {
				return nil, err
			}
			if err = gFields(result, path+".functionResponse", "id", "name", "response"); err != nil {
				return nil, err
			}
			name, err := gName(result["name"], "functionResponse.name")
			if err != nil {
				return nil, err
			}
			id := ""
			if value, exists := result["id"]; exists {
				id, err = gName(value, "functionResponse.id")
				if err != nil {
					return nil, err
				}
			}
			found := -1
			for i, call := range pending {
				if call.name == name && (id == "" || call.id == id) {
					if found >= 0 {
						return nil, errors.New("functionResponse requires id for ambiguous parallel calls")
					}
					found = i
				}
			}
			if found < 0 {
				return nil, errors.New("functionResponse has no matching pending functionCall")
			}
			id = pending[found].id
			pending = append(pending[:found], pending[found+1:]...)
			output, err := gObject(result["response"], "functionResponse.response")
			if err != nil {
				return nil, err
			}
			encoded, _ := json.Marshal(output)
			results = append(results, map[string]any{"role": "tool", "tool_call_id": id, "content": string(encoded)})
		}
		if role == "user" && text.Len() > 0 && len(pending) > 0 {
			return nil, errors.New("pending functionCall results must precede user text")
		}
		messages = append(messages, results...)
		if text.Len() > 0 || len(calls) > 0 {
			message := map[string]any{"role": map[string]string{"user": "user", "model": "assistant"}[role]}
			if text.Len() > 0 {
				message["content"] = text.String()
			}
			if len(calls) > 0 {
				message["tool_calls"] = calls
			}
			messages = append(messages, message)
		}
	}
	if len(pending) > 0 {
		return nil, errors.New("functionCall history requires its matching functionResponse")
	}
	if len(messages) == 0 {
		return nil, errors.New("contents have no representable text or tool results")
	}
	request := map[string]any{"model": model, "messages": messages, "stream": false}
	declarations := []any{}
	names := map[string]bool{}
	if raw, exists := root["tools"]; exists {
		tools, err := gArray(raw, "tools")
		if err != nil {
			return nil, err
		}
		for _, raw := range tools {
			tool, err := gObject(raw, "tools")
			if err != nil {
				return nil, err
			}
			if err = gFields(tool, "tools", "functionDeclarations"); err != nil {
				return nil, err
			}
			functions, err := gArray(tool["functionDeclarations"], "functionDeclarations")
			if err != nil {
				return nil, err
			}
			for _, raw := range functions {
				fn, err := gObject(raw, "functionDeclarations")
				if err != nil {
					return nil, err
				}
				if err = gFields(fn, "functionDeclarations", "name", "description", "parameters", "parametersJsonSchema"); err != nil {
					return nil, err
				}
				name, err := gName(fn["name"], "functionDeclarations.name")
				if err != nil {
					return nil, err
				}
				if names[name] {
					return nil, errors.New("function names must be unique")
				}
				names[name] = true
				function := map[string]any{"name": name}
				if value, exists := fn["description"]; exists {
					description, err := gString(value, "functionDeclarations.description")
					if err != nil {
						return nil, err
					}
					function["description"] = description
				}
				if _, a := fn["parameters"]; a {
					if _, b := fn["parametersJsonSchema"]; b {
						return nil, errors.New("function parameters schema must be specified once")
					}
				}
				schema := fn["parametersJsonSchema"]
				if schema == nil {
					schema = fn["parameters"]
				}
				if schema == nil {
					schema = map[string]any{"type": "object", "properties": map[string]any{}}
				}
				schema, err = geminiSchema(schema, 0)
				if err != nil {
					return nil, err
				}
				function["parameters"] = schema
				declarations = append(declarations, map[string]any{"type": "function", "function": function})
			}
		}
	}
	if len(declarations) > 0 {
		request["tools"] = declarations
	}
	if raw, exists := root["toolConfig"]; exists {
		object, err := gObject(raw, "toolConfig")
		if err != nil {
			return nil, err
		}
		if err = gFields(object, "toolConfig", "functionCallingConfig"); err != nil {
			return nil, err
		}
		choice, err := gObject(object["functionCallingConfig"], "functionCallingConfig")
		if err != nil {
			return nil, err
		}
		if err = gFields(choice, "functionCallingConfig", "mode", "allowedFunctionNames"); err != nil {
			return nil, err
		}
		mode := "AUTO"
		if value, exists := choice["mode"]; exists {
			mode, err = gString(value, "functionCallingConfig.mode")
			if err != nil {
				return nil, err
			}
		}
		mapped := map[string]string{"AUTO": "auto", "ANY": "required", "NONE": "none"}[mode]
		if mapped == "" {
			return nil, errors.New("functionCallingConfig.mode has no lossless Chat mapping")
		}
		request["tool_choice"] = mapped
		if raw, exists := choice["allowedFunctionNames"]; exists {
			allowed, err := gArray(raw, "allowedFunctionNames")
			if err != nil {
				return nil, err
			}
			if len(allowed) > 0 {
				if mode != "ANY" || len(allowed) != 1 {
					return nil, errors.New("allowedFunctionNames requires ANY and exactly one function")
				}
				name, err := gName(allowed[0], "allowedFunctionNames")
				if err != nil || !names[name] {
					return nil, errors.New("allowedFunctionNames must name a declared function")
				}
				request["tool_choice"] = map[string]any{"type": "function", "function": map[string]any{"name": name}}
			}
		}
		if len(declarations) == 0 {
			return nil, errors.New("toolConfig requires functionDeclarations")
		}
	}
	if raw, exists := root["generationConfig"]; exists {
		generation, err := gObject(raw, "generationConfig")
		if err != nil {
			return nil, err
		}
		if err = gFields(generation, "generationConfig", "temperature", "topP", "topK", "maxOutputTokens", "stopSequences", "candidateCount", "responseMimeType", "responseSchema", "responseJsonSchema", "thinkingConfig"); err != nil {
			return nil, err
		}
		for source, target := range map[string]string{"temperature": "temperature", "topP": "top_p", "maxOutputTokens": "max_tokens"} {
			if value, exists := generation[source]; exists {
				number, err := gNumber(value, "generationConfig."+source)
				if err != nil {
					return nil, err
				}
				n, _ := number.Float64()
				if source == "maxOutputTokens" {
					if integer, e := number.Int64(); e != nil || integer <= 0 {
						return nil, errors.New("maxOutputTokens must be a positive integer")
					}
				} else if n < 0 || (source == "topP" && n > 1) || (source == "temperature" && n > 2) {
					return nil, errors.New("generationConfig sampling control is out of range")
				}
				request[target] = number
			}
		}
		if raw, exists := generation["candidateCount"]; exists {
			n, err := gNumber(raw, "candidateCount")
			if err != nil || string(n) != "1" {
				return nil, errors.New("candidateCount currently supports exactly one candidate")
			}
		}
		if raw, exists := generation["stopSequences"]; exists {
			stops, err := gArray(raw, "stopSequences")
			if err != nil {
				return nil, err
			}
			for _, value := range stops {
				if _, err = gString(value, "stopSequences"); err != nil {
					return nil, err
				}
			}
			request["stop"] = stops
		}
		if raw, exists := generation["topK"]; exists {
			number, err := gNumber(raw, "generationConfig.topK")
			if err != nil {
				return nil, err
			}
			if integer, e := number.Int64(); e != nil || integer <= 0 {
				return nil, errors.New("generationConfig.topK must be a positive integer")
			}
			request["top_k"] = number
		}
		// Gemini CLI 0.67 实测（11-06 pskc、11-07 本地捕获）generationConfig 还会带
		// responseMimeType / responseJsonSchema / thinkingConfig：白名单外一律 400 时
		// CLI 完全不可用（400 generationConfig contains an unsupported field）。
		var responseSchema any
		for _, name := range []string{"responseSchema", "responseJsonSchema"} {
			if raw, exists := generation[name]; exists {
				converted, err := geminiSchema(raw, 0)
				if err != nil {
					return nil, fmt.Errorf("generationConfig.%s: %w", name, err)
				}
				responseSchema = converted
				break
			}
		}
		responseMime := ""
		if raw, exists := generation["responseMimeType"]; exists {
			value, err := gString(raw, "generationConfig.responseMimeType")
			if err != nil {
				return nil, err
			}
			responseMime = value
		}
		if responseSchema != nil {
			request["response_format"] = map[string]any{
				"type":        "json_schema",
				"json_schema": map[string]any{"name": "response", "schema": responseSchema},
			}
		} else if responseMime == "application/json" {
			request["response_format"] = map[string]any{"type": "json_object"}
		} else if responseMime != "" && responseMime != "text/plain" {
			return nil, fmt.Errorf("generationConfig.responseMimeType %q is not supported", responseMime)
		}
		if raw, exists := generation["thinkingConfig"]; exists {
			// 思考档位按既有跨协议惯例映射为 chat reasoning_effort（与 Anthropic 桥同款）：
			// thinkingLevel HIGH/LOW 直映；thinkingBudget 只有 0（关闭思考）有等价映射；
			// 其余预算值映射不了，保持“映射不了就在后端前拒绝”的口径。
			// includeThoughts 只决定响应是否回显思考摘要，不影响答案，忽略。
			thinking, err := gObject(raw, "generationConfig.thinkingConfig")
			if err != nil {
				return nil, err
			}
			effort := ""
			if raw, exists := thinking["thinkingLevel"]; exists {
				level, err := gString(raw, "generationConfig.thinkingConfig.thinkingLevel")
				if err != nil {
					return nil, err
				}
				switch level {
				case "HIGH":
					effort = "high"
				case "LOW":
					effort = "low"
				default:
					return nil, fmt.Errorf("generationConfig.thinkingConfig.thinkingLevel %q is not supported", level)
				}
			}
			if raw, exists := thinking["thinkingBudget"]; exists {
				number, err := gNumber(raw, "generationConfig.thinkingConfig.thinkingBudget")
				if err != nil {
					return nil, err
				}
				integer, e := number.Int64()
				if e != nil || integer < 0 {
					return nil, errors.New("generationConfig.thinkingConfig.thinkingBudget must be a non-negative integer")
				}
				if integer == 0 {
					effort = "minimal"
				} else {
					return nil, errors.New("generationConfig.thinkingConfig.thinkingBudget has no exact chat mapping; use thinkingLevel")
				}
			}
			if effort != "" {
				request["reasoning_effort"] = effort
			}
		}
	}
	return request, nil
}

func geminiSchema(raw any, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("function schema exceeds supported nesting")
	}
	value, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("function schema must be a JSON Schema object")
	}
	out := map[string]any{}
	for key, child := range value {
		switch key {
		case "nullable":
			if flag, ok := child.(bool); !ok || flag {
				return nil, errors.New("nullable Google schemas require explicit JSON Schema union types")
			}
			continue
		case "propertyOrdering":
			return nil, errors.New("Google propertyOrdering has no lossless Chat schema mapping")
		case "type":
			switch typ := child.(type) {
			case string:
				out[key] = strings.ToLower(typ)
			case []any:
				types := make([]any, len(typ))
				for i, raw := range typ {
					value, ok := raw.(string)
					if !ok {
						return nil, errors.New("invalid schema type union")
					}
					types[i] = strings.ToLower(value)
				}
				out[key] = types
			default:
				return nil, errors.New("invalid function schema type")
			}
		case "properties", "$defs", "definitions", "patternProperties":
			children, ok := child.(map[string]any)
			if !ok {
				return nil, errors.New("invalid function schema properties")
			}
			converted := map[string]any{}
			for name, schema := range children {
				value, err := geminiSchema(schema, depth+1)
				if err != nil {
					return nil, err
				}
				converted[name] = value
			}
			out[key] = converted
		case "items", "additionalProperties", "not", "if", "then", "else", "contains", "propertyNames", "unevaluatedProperties":
			if flag, ok := child.(bool); ok {
				out[key] = flag
				continue
			}
			value, err := geminiSchema(child, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = value
		case "anyOf", "oneOf", "allOf", "prefixItems":
			children, ok := child.([]any)
			if !ok {
				return nil, errors.New("invalid function schema alternatives")
			}
			converted := make([]any, len(children))
			for i, schema := range children {
				value, err := geminiSchema(schema, depth+1)
				if err != nil {
					return nil, err
				}
				converted[i] = value
			}
			out[key] = converted
		default:
			out[key] = child // Defaults, enums, const values and extensions are data, not schemas.
		}
	}
	return out, nil
}

func geminiResponseFromChat(raw []byte) (map[string]any, error) {
	var response struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Index   int `json:"index"`
			Message struct {
				Content   string `json:"content"`
				Reasoning string `json:"reasoning_content"`
				Refusal   string `json:"refusal"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			Finish string `json:"finish_reason"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	if json.Unmarshal(raw, &response) != nil || len(response.Choices) == 0 {
		return nil, errors.New("Upstream returned an invalid Chat response for Google conversion.")
	}
	candidates := []any{}
	for _, choice := range response.Choices {
		parts := []any{}
		if choice.Message.Reasoning != "" {
			parts = append(parts, map[string]any{"text": choice.Message.Reasoning, "thought": true})
		}
		if choice.Message.Content != "" {
			parts = append(parts, map[string]any{"text": choice.Message.Content})
		}
		if choice.Message.Refusal != "" {
			parts = append(parts, map[string]any{"text": choice.Message.Refusal})
		}
		for _, call := range choice.Message.ToolCalls {
			var args map[string]any
			if call.Type != "function" || call.ID == "" || call.Function.Name == "" || json.Unmarshal([]byte(call.Function.Arguments), &args) != nil || args == nil {
				return nil, errors.New("Upstream tool call has no complete Google function mapping.")
			}
			parts = append(parts, map[string]any{"functionCall": map[string]any{"id": call.ID, "name": call.Function.Name, "args": args}})
		}
		finish := map[string]string{"stop": "STOP", "tool_calls": "STOP", "length": "MAX_TOKENS", "content_filter": "SAFETY"}[choice.Finish]
		if finish == "" {
			finish = "OTHER"
		}
		candidates = append(candidates, map[string]any{"index": choice.Index, "content": map[string]any{"role": "model", "parts": parts}, "finishReason": finish})
	}
	usage := map[string]any{}
	for source, target := range map[string]string{"prompt_tokens": "promptTokenCount", "completion_tokens": "candidatesTokenCount", "total_tokens": "totalTokenCount", "cache_read_input_tokens": "cachedContentTokenCount"} {
		if value, exists := response.Usage[source]; exists {
			usage[target] = value
		}
	}
	if details, ok := response.Usage["completion_tokens_details"].(map[string]any); ok {
		if value, exists := details["reasoning_tokens"]; exists {
			usage["thoughtsTokenCount"] = value
		}
	}
	if _, exists := usage["cachedContentTokenCount"]; !exists {
		if details, ok := response.Usage["prompt_tokens_details"].(map[string]any); ok {
			if value, exists := details["cached_tokens"]; exists {
				usage["cachedContentTokenCount"] = value
			}
		}
	}
	return map[string]any{"candidates": candidates, "usageMetadata": usage, "modelVersion": response.Model, "responseId": response.ID}, nil
}
