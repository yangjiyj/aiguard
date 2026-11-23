package handler

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
)

// mcpUpstreamConfigKeys 是上游连接配置在 capabilities_json 中的键（不新增迁移）。
var mcpUpstreamConfigKeys = []string{
	mcpupstream.CapAuthHeaderName, mcpupstream.CapAuthLocation, mcpupstream.CapAuthQueryParam,
	mcpupstream.CapAuthTemplate, mcpupstream.CapExtraHeaders,
}

// mcpServerInputResult 是保存前对 server_url / transport / capabilities / 密钥 的统一处理结果。
type mcpServerInputResult struct {
	ServerURL    string
	Capabilities map[string]interface{} // nil 表示保持库里不变（仅当请求未传 capabilities 且无拆分）
	AuthToken    string
	Extracted    *mcpupstream.ExtractedAuth
}

// prepareMCPServerInput 校验并规整一次注册/编辑请求：
//  1. transport 白名单：auto / streamable_http / sse（空串由 repository 落默认 streamable_http）；
//  2. server_url 基础校验；
//  3. URL 中禁止明文存放密钥：query 里的敏感参数（key/ak/api_key/Authorization/token…）自动拆出，
//     转成 query 鉴权配置，密钥进入 auth_token 走加密存储；URL 回写为不含密钥的干净地址。
//     无法安全拆分（多个疑似密钥）时拒绝保存并给出中文提示；
//  4. capabilities 里的上游连接配置键必须通过 mcpupstream.ParseConfig 校验（头名黑名单、模板、额外头）。
//
// existing 是编辑场景下库里现有的 capabilities（用于合并与校验）；create 时为 nil。
func prepareMCPServerInput(rawURL, transport string, caps map[string]interface{}, authToken string, existing map[string]interface{}) (*mcpServerInputResult, error) {
	if !validMCPTransport(transport) {
		return nil, fmt.Errorf("传输方式必须是 自动识别 / Streamable HTTP / SSE（旧版）")
	}
	serverURL, err := validateMCPServerURL(rawURL)
	if err != nil {
		return nil, err
	}
	// 鉴权位置：以请求里的 capabilities 为准（省略则沿用库里现有配置）。path 模式的 URL 用 {secret} 占位标出
	// 密钥所在的路径位置：此时不做 query 密钥自动拆分，URL 原样（占位形态）保存。
	locView := caps
	if locView == nil {
		locView = existing
	}
	isPath, _ := locView[mcpupstream.CapAuthLocation].(string)
	if strings.EqualFold(strings.TrimSpace(isPath), mcpupstream.AuthPath) {
		if err := mcpupstream.ValidatePathSecretURL(serverURL); err != nil {
			return nil, err
		}
		if _, ex, _ := mcpupstream.SplitURLSecrets(serverURL); ex != nil {
			return nil, fmt.Errorf("鉴权位置为「URL 路径」时，服务地址的 URL 参数里不能再带密钥参数（%s）。请删除该参数", ex.ParamName)
		}
		// 新建时（existing == nil）必须带密钥；编辑时留空表示沿用库里的密文，是否允许由 UpdateMCPServer 的
		// “改地址 / 鉴权形态必须重填密钥”规则统一判断，这里不重复要求。
		if existing == nil && strings.TrimSpace(authToken) == "" {
			return nil, fmt.Errorf("鉴权位置为「URL 路径」时必须填写鉴权密钥（用来替换服务地址里的 {密钥} 占位）")
		}
		// 单独的 "." / ".." 作为路径段会被 URL 规范化当作目录引用：保存时就拒绝，不等到请求时才失败。
		if strings.TrimSpace(authToken) != "" {
			if err := mcpupstream.ValidatePathSecretValue(authToken); err != nil {
				return nil, err
			}
		}
		if view := mergedCapsView(existing, caps); view != nil {
			if _, err := mcpupstream.ParseConfig(transport, view); err != nil {
				return nil, err
			}
		}
		return &mcpServerInputResult{ServerURL: serverURL, Capabilities: caps, AuthToken: authToken}, nil
	}
	if err := mcpupstream.ValidateNonPathURL(serverURL); err != nil {
		return nil, err
	}
	cleanURL, extracted, err := mcpupstream.SplitURLSecrets(serverURL)
	if err != nil {
		return nil, fmt.Errorf("%s", err.Error())
	}
	out := &mcpServerInputResult{ServerURL: cleanURL, AuthToken: authToken, Extracted: extracted}

	merged := caps
	if extracted != nil {
		if strings.TrimSpace(authToken) != "" && authToken != extracted.Secret {
			return nil, fmt.Errorf("服务地址的 URL 参数里带有密钥（参数 %s），同时又填写了另一个鉴权密钥，无法判断以哪个为准。请从地址中删除该参数，只在「鉴权」中填写", extracted.ParamName)
		}
		base := map[string]interface{}{}
		if caps != nil {
			for k, v := range caps {
				base[k] = v
			}
		} else {
			for k, v := range existing {
				base[k] = v
			}
		}
		base[mcpupstream.CapAuthLocation] = mcpupstream.AuthQuery
		base[mcpupstream.CapAuthQueryParam] = extracted.ParamName
		base[mcpupstream.CapAuthTemplate] = extracted.Template
		delete(base, mcpupstream.CapAuthHeaderName)
		merged = base
		out.AuthToken = extracted.Secret
	}
	if merged != nil {
		// 校验用合并视图（请求里的配置优先于库里已有的）。
		view := map[string]interface{}{}
		for k, v := range existing {
			view[k] = v
		}
		for k, v := range merged {
			view[k] = v
		}
		cfg, err := mcpupstream.ParseConfig(transport, view)
		if err != nil {
			return nil, err
		}
		// 新黑名单只约束“新建或被修改”的鉴权头名；回传未改动的存量头名不阻断无关编辑。
		oldName, _ := existing[mcpupstream.CapAuthHeaderName].(string)
		newName, _ := view[mcpupstream.CapAuthHeaderName].(string)
		if !strings.EqualFold(strings.TrimSpace(oldName), strings.TrimSpace(newName)) || existing == nil {
			if err := cfg.ValidateForSave(); err != nil {
				return nil, err
			}
		}
		if err := rejectCapabilityPlaintextSecrets(merged); err != nil {
			return nil, err
		}
	}
	out.Capabilities = merged
	return out, nil
}

// rejectCapabilityPlaintextSecrets 额外请求头是明文静态配置（非敏感），敏感值不允许放在这里：
// 头名命中常见密钥头名的直接拒绝，提示改用「鉴权」。
func rejectCapabilityPlaintextSecrets(caps map[string]interface{}) error {
	raw, ok := caps[mcpupstream.CapExtraHeaders].(map[string]interface{})
	if !ok {
		return nil
	}
	for name := range raw {
		l := strings.ToLower(name)
		if mcpupstream.IsSensitiveQueryName(l) || strings.Contains(l, "token") || strings.Contains(l, "secret") || strings.Contains(l, "api-key") || strings.Contains(l, "apikey") {
			return fmt.Errorf("额外请求头 %s 疑似密钥，额外请求头以明文保存，请改在「鉴权」中填写密钥", name)
		}
	}
	return nil
}

// restoreRedactedQueryValues 处理“编辑表单把列表里已脱敏的 server_url 原样回传”的情形：
// 提交的 URL 含 name=*** 形态的占位时，仅当 scheme、host、port、path 与库内旧 URL 完全一致，
// 才用旧 URL 的同名参数值还原；否则一律拒绝——旧明文绝不能被还原进另一个 origin / 路径的 URL。
func restoreRedactedQueryValues(submitted, stored string) (string, error) {
	if !strings.Contains(submitted, "=***") {
		return submitted, nil
	}
	su, err := url.Parse(submitted)
	if err != nil {
		return submitted, nil
	}
	tu, terr := url.Parse(stored)
	if terr != nil || !sameUpstreamEndpoint(su, tu) {
		return "", fmt.Errorf("服务地址中含脱敏占位符（***），但地址的协议、主机、端口或路径与已保存的不一致，无法还原。请重新填写完整地址，并在「鉴权」中重新填写密钥")
	}
	storedQuery := tu.Query()
	var parts []string
	for _, pair := range strings.Split(su.RawQuery, "&") {
		if pair == "" {
			continue
		}
		k, v, has := strings.Cut(pair, "=")
		if has && v == "***" {
			name, _ := url.QueryUnescape(k)
			orig := storedQuery.Get(name)
			if orig == "" {
				return "", fmt.Errorf("服务地址中的参数 %s 是脱敏占位符（***），无法还原。请重新填写完整地址，或删除该参数后在「鉴权」中填写密钥", name)
			}
			pair = k + "=" + url.QueryEscape(orig)
		}
		parts = append(parts, pair)
	}
	su.RawQuery = strings.Join(parts, "&")
	return su.String(), nil
}

// sameUpstreamEndpoint 判断两个 URL 的 scheme、host、port、path 是否完全一致（query 不参与）。
func sameUpstreamEndpoint(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) &&
		port(a) == port(b) && a.EscapedPath() == b.EscapedPath()
}

// upstreamRouteOrAuthChanged 判断一次编辑是否改变了“密钥将被发往的地方 / 注入方式”：
// scheme、host、port、path 任一变化，或鉴权位置、头名、参数名、值模板任一变化。
// 此时必须同时重新提交 auth_token，旧密钥不得被带去新地址或新格式。
// oldCaps/newCaps 为空视为默认配置（请求头 Authorization + Bearer），与 mcpupstream.ParseConfig 同口径。
func upstreamRouteOrAuthChanged(oldURL, newURL, oldTransport, newTransport string, oldCaps, newCaps map[string]interface{}) bool {
	ou, e1 := url.Parse(oldURL)
	nu, e2 := url.Parse(newURL)
	if e1 != nil || e2 != nil || !sameUpstreamEndpoint(ou, nu) {
		return true
	}
	oc, oerr := mcpupstream.ParseConfig(oldTransport, oldCaps)
	nc, nerr := mcpupstream.ParseConfig(newTransport, newCaps)
	if oerr != nil || nerr != nil {
		return true
	}
	return oc.AuthLocation != nc.AuthLocation || oc.AuthName != nc.AuthName || oc.AuthTemplate != nc.AuthTemplate
}

const mcpReenterSecretHint = "上游地址或鉴权方式已变更，请重新填写密钥"

// mergedCapsView 合并库内现有 capabilities 与请求里的 capabilities（请求优先）。
func mergedCapsView(existing, caps map[string]interface{}) map[string]interface{} {
	if existing == nil && caps == nil {
		return nil
	}
	view := map[string]interface{}{}
	for k, v := range existing {
		view[k] = v
	}
	for k, v := range caps {
		view[k] = v
	}
	return view
}
