package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/providercompat"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

type Msg struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

type ToolCall struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"arguments"`
}

type ToolSpec struct {
	Name, Description string
	Schema            json.RawMessage
}

type Reply struct {
	Content                        string
	ToolCalls                      []ToolCall
	PromptTokens, CompletionTokens int
}

type LLM interface {
	Chat(ctx context.Context, msgs []Msg, tools []ToolSpec) (Reply, error)
}

var ErrNoTools = errors.New("model does not support tool calls")

// t8HTTPError 是模型接口返回的非 200 响应；上层据 Status 判断是否值得重试。
type t8HTTPError struct {
	Status  int
	Snippet string
}

func (e *t8HTTPError) Error() string {
	return fmt.Sprintf("模型返回 HTTP %d: %s", e.Status, e.Snippet)
}

const (
	t8ChatTimeout  = 60 * time.Second
	t8MaxOutput    = 2048
	t8MaxRespBytes = 4 << 20
	t8AzureAPIVer  = "2024-10-21"
)

type t8HTTPLLM struct {
	baseURL, apiKey, authMode, providerType, model string
	client                                         *http.Client
}

// NewHTTPLLM 返回 OpenAI 兼容 /chat/completions 客户端（Azure 自动适配）。
// 传入的 client 会被浅拷贝并禁用重定向跟随。
func NewHTTPLLM(baseURL, apiKey, authMode, providerType, model string, client *http.Client) LLM {
	var c http.Client
	if client != nil {
		c = *client
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &t8HTTPLLM{baseURL: baseURL, apiKey: apiKey, authMode: strings.ToLower(strings.TrimSpace(authMode)),
		providerType: providerType, model: model, client: &c}
}

func t8IsAzure(baseURL, providerType string) bool {
	if strings.EqualFold(strings.TrimSpace(providerType), "azure") {
		return true
	}
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return false
	}
	h := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	return strings.HasSuffix(h, ".openai.azure.com") || strings.HasSuffix(h, ".cognitiveservices.azure.com")
}

// t8ChatURL 的拼法与 catalog.joinModelProbePath（chat_completions）保持一致。
func t8ChatURL(baseURL, deployment string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if u, err := url.Parse(baseURL); err == nil {
		h := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
		if strings.HasSuffix(h, ".openai.azure.com") || strings.HasSuffix(h, ".cognitiveservices.azure.com") {
			u.RawPath = ""
			p := strings.TrimRight(u.Path, "/")
			if p == "/openai" || p == "/openai/v1" {
				p = ""
			}
			u.Path = p + "/openai/deployments/" + deployment + "/chat/completions"
			u.ForceQuery = false
			u.RawQuery = "api-version=" + url.QueryEscape(t8AzureAPIVer)
			return u.String()
		}
	}
	if strings.HasSuffix(baseURL, "/v1") {
		return baseURL + "/chat/completions"
	}
	return baseURL + "/v1/chat/completions"
}

type t8WireTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Parameters  json.RawMessage `json:"parameters,omitempty"`
	} `json:"function"`
}

type t8WireCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type t8WireMsg struct {
	Role       string       `json:"role"`
	Content    *string      `json:"content"`
	ToolCalls  []t8WireCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
	Name       string       `json:"name,omitempty"`
}

func t8ToWire(msgs []Msg) []t8WireMsg {
	out := make([]t8WireMsg, 0, len(msgs))
	for _, m := range msgs {
		w := t8WireMsg{Role: m.Role, ToolCallID: m.ToolCallID, Name: m.Name}
		if m.Content != "" || len(m.ToolCalls) == 0 {
			c := m.Content
			w.Content = &c
		}
		for _, tc := range m.ToolCalls {
			var wc t8WireCall
			wc.ID, wc.Type = tc.ID, "function"
			wc.Function.Name = tc.Name
			args := strings.TrimSpace(string(tc.Args))
			if args == "" {
				args = "{}"
			}
			wc.Function.Arguments = args
			w.ToolCalls = append(w.ToolCalls, wc)
		}
		out = append(out, w)
	}
	return out
}

func (l *t8HTTPLLM) Chat(ctx context.Context, msgs []Msg, tools []ToolSpec) (Reply, error) {
	azure := t8IsAzure(l.baseURL, l.providerType)
	body := map[string]any{"model": l.model, "messages": t8ToWire(msgs)}
	if azure {
		body["max_completion_tokens"] = t8MaxOutput
	} else {
		body["max_tokens"] = t8MaxOutput
	}
	if len(tools) > 0 {
		wt := make([]t8WireTool, 0, len(tools))
		for _, t := range tools {
			var x t8WireTool
			x.Type = "function"
			x.Function.Name, x.Function.Description = t.Name, t.Description
			x.Function.Parameters = t.Schema
			if len(x.Function.Parameters) == 0 {
				x.Function.Parameters = json.RawMessage(`{"type":"object","properties":{}}`)
			}
			wt = append(wt, x)
		}
		body["tools"] = wt
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Reply{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, t8ChatTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t8ChatURL(l.baseURL, l.model), bytes.NewReader(payload))
	if err != nil {
		return Reply{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	switch {
	case azure:
		req.Header.Set("api-key", l.apiKey)
	case l.authMode == "authorization_raw":
		req.Header.Set("Authorization", l.apiKey)
	default:
		req.Header.Set("Authorization", "Bearer "+l.apiKey)
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return Reply{}, fmt.Errorf("调用模型失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, t8MaxRespBytes))
	if err != nil {
		return Reply{}, fmt.Errorf("读取模型响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusBadRequest && len(tools) > 0 && t8NoToolsError(string(raw)) {
			return Reply{}, ErrNoTools
		}
		snippet := Redact(string(raw))
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		return Reply{}, &t8HTTPError{Status: resp.StatusCode, Snippet: snippet}
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content   json.RawMessage `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string          `json:"name"`
						Arguments json.RawMessage `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Reply{}, fmt.Errorf("模型响应不是合法 JSON: %w", err)
	}
	if len(out.Choices) == 0 {
		return Reply{}, errors.New("模型响应没有 choices")
	}
	m := out.Choices[0].Message
	r := Reply{PromptTokens: out.Usage.PromptTokens, CompletionTokens: out.Usage.CompletionTokens}
	var s string
	if json.Unmarshal(m.Content, &s) == nil {
		r.Content = s
	}
	for i, tc := range m.ToolCalls {
		args := tc.Function.Arguments
		var as string
		if len(args) > 0 && args[0] == '"' && json.Unmarshal(args, &as) == nil {
			args = json.RawMessage(as) // 标准做法：arguments 是字符串，原样放入（可能非法 JSON，由上层判定）
		}
		id := tc.ID
		if id == "" {
			id = fmt.Sprintf("call_%d", i)
		}
		r.ToolCalls = append(r.ToolCalls, ToolCall{ID: id, Name: tc.Function.Name, Args: args})
	}
	return r, nil
}

func t8NoToolsError(body string) bool {
	b := strings.ToLower(body)
	mentions := strings.Contains(b, "tools") || strings.Contains(b, "tool_choice") ||
		strings.Contains(b, "function") || strings.Contains(b, "tool call") || strings.Contains(b, "tool_call")
	if !mentions {
		return false
	}
	for _, k := range []string{"not support", "unsupported", "does not support", "not allowed", "not available", "unrecognized", "unknown parameter", "extra inputs", "invalid parameter", "不支持"} {
		if strings.Contains(b, k) {
			return true
		}
	}
	return false
}

// ---- 选模型 ----

type ModelChoice struct {
	ModelID, ModelName, ProviderID, ProviderType, BaseURL, AuthMode, Deployment string
}

func t8Str(v any) string {
	s, _ := v.(string)
	return s
}

func t8Choice(r map[string]any) *ModelChoice {
	c := &ModelChoice{ModelID: t8Str(r["model_id"]), ModelName: t8Str(r["model_name"]), ProviderID: t8Str(r["provider_id"]),
		ProviderType: t8Str(r["provider_type"]), BaseURL: t8Str(r["base_url"]), AuthMode: t8Str(r["auth_mode"]),
		Deployment: t8Str(r["deployment"])}
	if c.Deployment == "" {
		c.Deployment = c.ModelName
	}
	return c
}

func t8Usable(c *ModelChoice) bool {
	return c.BaseURL != "" && (providercompat.OpenAICompatible(c.ProviderType) || strings.EqualFold(c.ProviderType, "azure"))
}

const t8ModelCols = `m.id AS model_id, m.model_name, p.id AS provider_id, p.provider_type, COALESCE(p.base_url,'') AS base_url,
  COALESCE(p.auth_mode,'') AS auth_mode, COALESCE(NULLIF(m.upstream_model_id,''), m.model_name) AS deployment`

// PickModel 选诊断用模型；没有可用模型时返回 nil, nil。
func PickModel(ctx context.Context, q Querier, tenantID, preferredModelID string) (*ModelChoice, error) {
	if preferredModelID != "" {
		rows, err := q.Query(ctx, `SELECT `+t8ModelCols+`
FROM models m JOIN providers p ON p.id = m.provider_id
WHERE m.id = $1 AND p.tenant_id = $2 AND m.status = 'active' AND p.status = 'active'`, preferredModelID, tenantID)
		if err != nil {
			return nil, err
		}
		if len(rows) == 1 {
			if c := t8Choice(rows[0]); t8Usable(c) {
				return c, nil
			}
		}
	}
	cands, err := PickCandidates(ctx, q, tenantID, 1)
	if err != nil || len(cands) == 0 {
		return nil, err
	}
	return cands[0], nil
}

// t8IsImageModel 判断是否图像类模型。models 表只有 capabilities_json（各渠道填写不一致，没有统一的 chat 能力字段），
// 所以按模型名/部署名含 image 排除，自动选型不会把它们当作诊断候选。
func t8IsImageModel(c *ModelChoice) bool {
	return strings.Contains(strings.ToLower(c.ModelName), "image") || strings.Contains(strings.ToLower(c.Deployment), "image")
}

// t8PickWindows 是自动选型的统计窗口：先看近 1 小时（至少 5 次），流量少时逐级放宽，
// 避免夜间或小租户因为近 1 小时调用太少而选不出模型、智能排查一直不可用。
var t8PickWindows = []struct {
	Hours, MinCalls int
}{{1, 5}, {24, 3}, {24 * 7, 1}}

// PickCandidates 按请求成功率从高到低返回至多 limit 个自动选型候选（跳过不可用与图像类模型）。
// 统计窗口按 t8PickWindows 逐级放宽，取第一个能选出候选的窗口。
func PickCandidates(ctx context.Context, q Querier, tenantID string, limit int) ([]*ModelChoice, error) {
	for _, w := range t8PickWindows {
		rows, err := q.Query(ctx, `SELECT `+t8ModelCols+`,
  count(*) AS total, count(*) FILTER (WHERE r.request_status = 'success') AS ok
FROM request_logs r
JOIN models m ON m.id = r.model_id
JOIN providers p ON p.id = m.provider_id
WHERE r.tenant_id = $1 AND r.created_at >= now() - make_interval(hours => $2) AND r.created_at <= now()
  AND p.tenant_id = $1 AND m.status = 'active' AND p.status = 'active'
GROUP BY m.id, m.model_name, m.upstream_model_id, p.id, p.provider_type, p.base_url, p.auth_mode
HAVING count(*) >= $3
ORDER BY (count(*) FILTER (WHERE r.request_status = 'success'))::float8 / count(*) DESC, count(*) DESC, m.id
LIMIT 20`, tenantID, w.Hours, w.MinCalls)
		if err != nil {
			return nil, err
		}
		var out []*ModelChoice
		for _, r := range rows {
			if len(out) >= limit {
				break
			}
			if c := t8Choice(r); t8Usable(c) && !t8IsImageModel(c) {
				out = append(out, c)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	return nil, nil
}

// ModelOption 是设置页可选的诊断模型。
type ModelOption struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ListUsableModels 列出本租户能当诊断模型的模型：启用的模型与渠道、渠道兼容 OpenAI 接口、非图像类。
// 与自动选型的过滤口径一致，设置页下拉只显示这些，避免手动选到注定自检失败的模型。
func ListUsableModels(ctx context.Context, q Querier, tenantID string) ([]ModelOption, error) {
	rows, err := q.Query(ctx, `SELECT `+t8ModelCols+`
FROM models m JOIN providers p ON p.id = m.provider_id
WHERE p.tenant_id = $1 AND m.status = 'active' AND p.status = 'active'
ORDER BY m.model_name, m.id LIMIT 500`, tenantID)
	if err != nil {
		return nil, err
	}
	out := []ModelOption{}
	for _, r := range rows {
		if c := t8Choice(r); t8Usable(c) && !t8IsImageModel(c) {
			out = append(out, ModelOption{ID: c.ModelID, Name: c.ModelName})
		}
	}
	return out, nil
}

// LoadLLM 取渠道凭据并解密，构造客户端。
func LoadLLM(ctx context.Context, db *pgxpool.Pool, choice *ModelChoice) (LLM, error) {
	if choice == nil {
		return nil, errors.New("未选择模型")
	}
	var cipher string
	err := db.QueryRow(ctx, `SELECT COALESCE(secret_ciphertext,'') FROM provider_credentials
WHERE provider_id = $1 AND status = 'active' ORDER BY created_at DESC LIMIT 1`, choice.ProviderID).Scan(&cipher)
	if err != nil {
		return nil, fmt.Errorf("读取渠道凭据失败: %w", err)
	}
	key, err := secrets.DecryptProviderSecret(cipher)
	if err != nil || strings.TrimSpace(key) == "" {
		return nil, errors.New("渠道凭据无法解密或为空")
	}
	authMode := choice.AuthMode
	if strings.EqualFold(choice.ProviderType, "azure") {
		authMode = "api-key"
	}
	return NewHTTPLLM(choice.BaseURL, key, authMode, choice.ProviderType, choice.Deployment, &http.Client{}), nil
}
