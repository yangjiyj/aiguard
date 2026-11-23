package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// restrictedFilePolicyTTL 是受限文件策略只读缓存的 TTL（30 秒，失败回退上次值）。
const restrictedFilePolicyTTL = 30 * time.Second

// RestrictedFilePolicy 是正向代理侧的受限文件策略视图。
type RestrictedFilePolicy struct {
	Patterns []string
	Action   string // record | alert_allow | block；空 = 功能关闭
	// Scopes 是受限文件生效的环节（tool_call、user_mention、proxy_output）；ScopesConfigured=false
	// 表示控制面没下发（升级前的控制面），所有环节都生效。
	Scopes           []string
	ScopesConfigured bool
	// Exceptions 是指向受限文件的放行例外（与网关同一来源、同一路径口径）。
	Exceptions []RestrictedFileException
}

// RestrictedFileException 是一条指向受限文件的例外：目标为空放开全部受限文件，否则按路径层级比对。
type RestrictedFileException struct {
	ID            string
	TargetPattern string
	ExpiresAt     time.Time
}

// 受限文件作用范围（与控制面、网关一致）。
const (
	restrictedFileScopeUserMention = "user_mention"
	restrictedFileScopeProxyOutput = "proxy_output"
)

// restrictedFileExceptionRule 判断例外的 rule_id 是否指向受限文件：防护项键或它在注册表里的原因码。
func restrictedFileExceptionRule(ruleID string) bool {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == protection.KeyRestrictedFile {
		return true
	}
	item, ok := protection.ItemForReason(ruleID)
	return ok && item.Key == protection.KeyRestrictedFile
}

func (p RestrictedFilePolicy) applies(scope string) bool {
	if !p.ScopesConfigured {
		return true
	}
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// exceptionFor 返回放开这个受限文件的例外编号；没有例外覆盖它时返回空串。
func (p RestrictedFilePolicy) exceptionFor(target string, now time.Time) string {
	matchTarget := filerestrict.ExceptionTarget(target)
	for _, exception := range p.Exceptions {
		if exception.ExpiresAt.IsZero() || !exception.ExpiresAt.After(now) {
			continue
		}
		if filerestrict.ExceptionTargetMatches(exception.TargetPattern, matchTarget) {
			return exception.ID
		}
	}
	return ""
}

// splitExceptedHits 把命中分成仍受限的和被例外放开的（返回其中一个例外编号）。
func (p RestrictedFilePolicy) splitExceptedHits(hits []filerestrict.Hit) ([]filerestrict.Hit, string) {
	now := time.Now()
	var kept []filerestrict.Hit
	excepted := ""
	for _, hit := range hits {
		if id := p.exceptionFor(hit.Target, now); id != "" {
			excepted = id
			continue
		}
		kept = append(kept, hit)
	}
	return kept, excepted
}

// RestrictedFilePolicyReader 按 (tenantID, agentType) 读生效策略。
type RestrictedFilePolicyReader interface {
	// Get 返回当前生效策略；空 Patterns = 功能关闭。永不出错阻塞请求。
	Get(ctx context.Context, tenantID, agentType string) RestrictedFilePolicy
}

// httpRestrictedFilePolicyReader 经控制面内部 API 读策略，带 TTL 缓存 + 失败回退上次值。
// 从未成功过则视为空（功能关闭）并限频记录。
type httpRestrictedFilePolicyReader struct {
	baseURL string
	secret  string
	client  *http.Client
	ttl     time.Duration

	mu        sync.Mutex
	policy    RestrictedFilePolicy
	hasValue  bool
	expireAt  time.Time
	lastLogAt time.Time
}

// NewHTTPRestrictedFilePolicyReader 构造内部 API 读取器。secret 为空时永远返回空策略。
func NewHTTPRestrictedFilePolicyReader(baseURL, secret string) RestrictedFilePolicyReader {
	if strings.TrimSpace(secret) == "" {
		log.Printf("restricted_file_policy: JJD_INTERNAL_API_SECRET 未配置，受限文件模式在正向代理侧关闭")
		return staticRestrictedFilePolicyReader{}
	}
	return &httpRestrictedFilePolicyReader{
		baseURL: strings.TrimRight(baseURL, "/"),
		secret:  secret,
		client:  &http.Client{Timeout: 5 * time.Second},
		ttl:     restrictedFilePolicyTTL,
	}
}

type staticRestrictedFilePolicyReader struct{}

func (staticRestrictedFilePolicyReader) Get(context.Context, string, string) RestrictedFilePolicy {
	return RestrictedFilePolicy{}
}

func (r *httpRestrictedFilePolicyReader) Get(ctx context.Context, tenantID, agentType string) RestrictedFilePolicy {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Before(r.expireAt) {
		return r.policy
	}
	policy, err := r.fetch(ctx, tenantID, agentType)
	if err == nil {
		r.policy = policy
		r.hasValue = true
	} else {
		if !r.hasValue {
			// 从未成功过：视为空（功能关闭），限频记录。
			if now.Sub(r.lastLogAt) > time.Minute {
				log.Printf("restricted_file_policy: 首次拉取失败，按功能关闭处理: %v", err)
				r.lastLogAt = now
			}
			r.policy = RestrictedFilePolicy{}
		}
		// 否则失败回退上次值（r.policy 保持）。
	}
	r.expireAt = now.Add(r.ttl)
	return r.policy
}

func (r *httpRestrictedFilePolicyReader) fetch(ctx context.Context, tenantID, agentType string) (RestrictedFilePolicy, error) {
	endpoint := fmt.Sprintf("%s/admin/v1/internal/agentguard/effective-policy?agent_id=%s&protocol=responses",
		r.baseURL, url.QueryEscape(agentType))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return RestrictedFilePolicy{}, err
	}
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set(headeraudit.InternalTokenHeader, r.secret)

	resp, err := r.client.Do(req)
	if err != nil {
		return RestrictedFilePolicy{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return RestrictedFilePolicy{}, fmt.Errorf("effective-policy status %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			RestrictedFilePatterns []string  `json:"restricted_file_patterns"`
			RestrictedFileAction   string    `json:"restricted_file_action"`
			RestrictedFileScopes   *[]string `json:"restricted_file_scopes"`
			Exceptions             []struct {
				ID            string    `json:"id"`
				RuleID        string    `json:"rule_id"`
				TargetPattern string    `json:"target_pattern"`
				ExpiresAt     time.Time `json:"expires_at"`
			} `json:"exceptions"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return RestrictedFilePolicy{}, err
	}
	action := body.Data.RestrictedFileAction
	if action == "" {
		action = string(filerestrict.ActionBlock)
	}
	policy := RestrictedFilePolicy{Patterns: body.Data.RestrictedFilePatterns, Action: action}
	if body.Data.RestrictedFileScopes != nil {
		policy.ScopesConfigured = true
		policy.Scopes = append([]string{}, (*body.Data.RestrictedFileScopes)...)
	}
	for _, exception := range body.Data.Exceptions {
		if restrictedFileExceptionRule(exception.RuleID) {
			policy.Exceptions = append(policy.Exceptions, RestrictedFileException{
				ID: exception.ID, TargetPattern: exception.TargetPattern, ExpiresAt: exception.ExpiresAt,
			})
		}
	}
	return policy, nil
}

// fileToolPathKeys 是文件类工具参数里放路径的键（Read 的 file_path 等）。
var fileToolPathKeys = map[string]bool{
	"path": true, "file_path": true, "filepath": true, "file": true, "target": true,
	"destination": true, "notebook_path": true, "paths": true, "files": true,
}

// fileToolPathArguments 取文件类工具参数里路径键下的值（含嵌套对象与字符串数组），供精确层
// 按路径匹配：只按扩展名的粗略层认不出目录型（/vault/）和带路径通配的模式。按键排序遍历，命中
// 顺序（拦截预览取第一条）稳定。
func fileToolPathArguments(arguments string) []string {
	var decoded any
	if json.Unmarshal([]byte(arguments), &decoded) != nil {
		return nil
	}
	var out []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" && !strings.ContainsAny(value, "\n\r") && !strings.Contains(value, "://") && len(value) <= 4096 {
			out = append(out, value)
		}
	}
	var walk func(any, int)
	walk = func(node any, depth int) {
		object, ok := node.(map[string]any)
		if !ok || depth > 4 {
			return
		}
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := object[key]
			switch typed := value.(type) {
			case string:
				if fileToolPathKeys[strings.ToLower(key)] {
					add(typed)
				}
			case []any:
				if fileToolPathKeys[strings.ToLower(key)] {
					for _, item := range typed {
						if text, ok := item.(string); ok {
							add(text)
						}
					}
				}
			case map[string]any:
				walk(typed, depth+1)
			}
		}
	}
	walk(decoded, 0)
	return out
}

// evaluateRestrictedFileToolCalls 对本轮工具调用跑受限文件匹配，合成 finding 列表。
// policy 为空 / Patterns 为空 → 零 finding。finding 字段与 SE finding 约定一致，
// counts_as_security_finding 恒为 true（proxy 合成，不经 SE）。
func evaluateRestrictedFileToolCalls(policy RestrictedFilePolicy, invocations []ToolInvocation) []map[string]interface{} {
	if len(policy.Patterns) == 0 || len(invocations) == 0 || !policy.applies(restrictedFileScopeProxyOutput) {
		return nil
	}
	matcher, err := filerestrict.Compile(policy.Patterns)
	if err != nil {
		return nil
	}
	action := policy.Action
	if action == "" {
		action = string(filerestrict.ActionBlock)
	}
	findingAction := "audit"
	if action == string(filerestrict.ActionBlock) {
		findingAction = "block"
	}

	var findings []map[string]interface{}
	for _, inv := range invocations {
		commands, coarse := filerestrict.ExtractCommandTextsFromJSON(inv.Arguments)
		var hits []filerestrict.Hit
		for _, cmd := range commands {
			hits = append(hits, matcher.MatchCommand(cmd)...)
		}
		if len(hits) == 0 {
			// file 类工具（Read/view_image 等）：参数里直接是路径，先按路径精确匹配，再整串试粗略层。
			hits = append(hits, matcher.MatchPaths(fileToolPathArguments(inv.Arguments))...)
		}
		if len(hits) == 0 {
			hits = append(hits, matcher.MatchText(inv.Arguments)...)
			if len(hits) == 0 && coarse != "" {
				hits = append(hits, matcher.MatchText(coarse)...)
			}
		}
		if len(hits) == 0 {
			continue
		}
		kept, exceptionID := policy.splitExceptedHits(hits)
		hit, thisAction := hits[0], findingAction
		if len(kept) == 0 {
			// 例外放开了这次命中的全部受限文件：只记录。
			thisAction = "audit"
		} else {
			hit = kept[0]
		}
		finding := map[string]interface{}{
			"type":                       "agent",
			"category":                   "restricted_file_access",
			"rule_id":                    "agentguard-restricted-file-pattern",
			"severity":                   "high",
			"action":                     thisAction,
			"counts_as_security_finding": true,
			"content_source":             "model_output",
			"output_field":               "tool_arguments",
			"matched_text_preview":       fmt.Sprintf("pattern=%s target=%s precision=%s", hit.Pattern, filerestrict.RedactTarget(hit.Target), hit.Precision),
			"tool_name":                  inv.Name,
		}
		if len(kept) == 0 {
			finding["exception_id"] = exceptionID
		}
		findings = append(findings, finding)
	}
	return findings
}
