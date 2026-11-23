package inspectionscope

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/runtimeoptions"
)

type Reader interface{ InspectionPolicy(context.Context) Policy }

// GatewayReader consumes the same credential-free, signed projection as gateway-core.
// It never reads browser-supplied scope flags. Failed refreshes retain the last good policy.
type GatewayReader struct {
	url, token, key string
	client          *http.Client
	mu              sync.RWMutex
	refreshMu       sync.Mutex
	policy          Policy
	revision        string
	// options 是投影里已签名的字符串键（2.9.22 故障处理与检测执行），未下发的键不在里面。
	options                  map[string]string
	ignoredOptions           runtimeoptions.IgnoredValues
	lastAttempt, lastSuccess time.Time
	errorCode                string
	now                      func() time.Time
}

func NewGatewayReader(url, token, key string) *GatewayReader {
	return &GatewayReader{url: strings.TrimRight(url, "/"), token: token, key: key, client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, policy: Default()}
}
func (r *GatewayReader) InspectionPolicy(context.Context) Policy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.policy
}

// RuntimeOption 返回最近一次验签通过的投影里某个字符串键的值；没有下发时 ok=false。
func (r *GatewayReader) RuntimeOption(key string) (string, bool) {
	if r == nil {
		return "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, ok := r.options[key]
	return value, ok
}

func (r *GatewayReader) Refresh(ctx context.Context) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	attempt := r.runtimeNow()
	err := r.refresh(ctx)
	r.mu.Lock()
	r.lastAttempt = attempt
	if err != nil {
		r.errorCode = runtimeFailureCode(err)
	} else {
		r.errorCode = ""
		r.lastSuccess = r.runtimeNow()
	}
	r.mu.Unlock()
	return err
}

func (r *GatewayReader) refresh(ctx context.Context) error {
	if len(r.key) < 16 {
		return runtimeConfigError("attestation_key_missing")
	}
	if r.token == "" {
		return runtimeConfigError("internal_token_missing")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url+"/admin/v1/internal/security/semantic-config/gateway", nil)
	if err != nil {
		return runtimeConfigError("config_invalid")
	}
	req.Header.Set(headeraudit.InternalTokenHeader, r.token)
	resp, err := r.client.Do(req)
	if err != nil {
		return runtimeConfigError("control_plane_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return runtimeConfigError("config_auth_failed")
		}
		if resp.StatusCode >= 500 {
			return runtimeConfigError("control_plane_unavailable")
		}
		return runtimeConfigError("config_fetch_failed")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil {
		return runtimeConfigError("config_fetch_failed")
	}
	if len(body) > 64<<10 {
		return runtimeConfigError("config_invalid")
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(body, &config); err != nil {
		return runtimeConfigError("config_invalid")
	}
	var revision string
	if json.Unmarshal(config["revision"], &revision) != nil || len(revision) != 32 {
		return runtimeConfigError("config_invalid")
	}
	allowed := map[string]bool{"semantic_enabled": true, "semantic_input_enabled": true, "semantic_agent_enabled": true, "security_audit_only": true, "file_content_dlp_enabled": true, "security_execution_mode_managed": true, "guardrail_fail_closed_enabled": true,
		"inspect_user_input": true, "inspect_model_output": true, "inspect_builtin_context": true, "inspect_history": true, "inspect_tool_results": true}
	keys := []string{}
	for key := range config {
		if key != "revision" {
			if !allowed[key] && !runtimeoptions.IsGatewayKey(key) && !forwardProxyProjectionKey(key) {
				return runtimeConfigError("config_invalid")
			}
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var canonical bytes.Buffer
	options := map[string]string{}
	ignored := map[string]string{}
	for _, key := range keys {
		raw := string(bytes.TrimSpace(config[key]))
		fmt.Fprintf(&canonical, "%d:%s=", len([]byte(key)), key)
		if forwardProxyStringKeys[key] {
			// 正向代理设置（批次 3）：网关投影一并下发，独立代理这里只参与验签，不读取。
			var value string
			if json.Unmarshal(config[key], &value) != nil {
				return runtimeConfigError("config_invalid")
			}
			fmt.Fprintf(&canonical, "s:%d:%s;", len([]byte(value)), value)
			continue
		}
		if runtimeoptions.IsGatewayKey(key) {
			var value string
			if json.Unmarshal(config[key], &value) != nil {
				return runtimeConfigError("config_invalid")
			}
			fmt.Fprintf(&canonical, "s:%d:%s;", len([]byte(value)), value)
			// 取值照样纳入签名；不认识的取值只让该键按未下发处理（与网关同口径）。
			if normalized, err := runtimeoptions.Normalize(key, value); err == nil {
				options[key] = normalized
			} else {
				ignored[key] = value
			}
			continue
		}
		if raw != "true" && raw != "false" {
			return runtimeConfigError("config_invalid")
		}
		if raw == "true" {
			canonical.WriteString("b:1;")
		} else {
			canonical.WriteString("b:0;")
		}
	}
	for _, key := range []string{"semantic_enabled", "semantic_input_enabled", "semantic_agent_enabled", "security_audit_only", "file_content_dlp_enabled"} {
		if _, ok := config[key]; !ok {
			return runtimeConfigError("config_invalid")
		}
	}
	mac := hmac.New(sha256.New, []byte(r.key))
	mac.Write([]byte("jjdguard:semantic-config:gateway-core\n"))
	mac.Write(canonical.Bytes())
	if !hmac.Equal([]byte(revision), []byte(hex.EncodeToString(mac.Sum(nil)[:16]))) {
		return runtimeConfigError("config_attestation_invalid")
	}
	// 验签通过后才记不认识的取值，且同一取值只记一次（周期刷新不刷屏）。
	for _, key := range r.ignoredOptions.Changed(ignored) {
		log.Printf("proxy runtime config: unrecognized value %q for %s ignored", truncateLogValue(ignored[key]), key)
	}
	var fields Fields
	if err := json.Unmarshal(body, &fields); err != nil {
		return runtimeConfigError("config_invalid")
	}
	policy, err := fields.Resolve()
	if err != nil {
		return runtimeConfigError("inspection_scope_incomplete")
	}
	if fields.InspectUserInput == nil {
		return runtimeConfigError("inspection_scope_unmanaged")
	}
	r.mu.Lock()
	r.policy = policy
	r.revision = revision
	r.options = options
	r.mu.Unlock()
	return nil
}
func (r *GatewayReader) Start(ctx context.Context) {
	refresh := func() {
		if err := r.Refresh(ctx); err != nil {
			log.Printf("proxy inspection scope refresh failed; holding policy: %s", runtimeFailureCode(err))
		}
	}
	refresh()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()
}

// truncateLogValue 截断写进日志的配置取值。
func truncateLogValue(value string) string {
	if len(value) > 64 {
		return value[:64] + "..."
	}
	return value
}

// 网关投影里的正向代理设置（egresspolicy.Keys，批次 3）：开关是布尔，其余是字符串。独立代理读同一份
// 网关投影，要认识这些键才能验签；它们由网关执行，独立代理不读取。
var (
	forwardProxyBoolKeys   = map[string]bool{egresspolicy.KeyAllowPrivate: true, egresspolicy.KeyAllowLoopback: true, egresspolicy.KeyAllowMetadata: true}
	forwardProxyStringKeys = map[string]bool{egresspolicy.KeyAllowedCIDRs: true, egresspolicy.KeyAllowedHosts: true, egresspolicy.KeyUnlistedAction: true, egresspolicy.KeyWhitelistFailMode: true}
)

func forwardProxyProjectionKey(key string) bool {
	return forwardProxyBoolKeys[key] || forwardProxyStringKeys[key]
}
