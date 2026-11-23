package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// securityEngineScanTimeout 是 control-plane 到 security-engine 的单次请求上限。
// legacy/portal 路径故障降级；admission-grade 路径返回错误并隔离未验证资产。
const securityEngineScanTimeout = 5 * time.Second

// 正则验证响应很小；限制读取量，避免异常上游占用 control-plane 内存。
const securityEngineRegexValidationResponseLimit = 64 << 10

// securityEngineClient 是 control-plane 调用 security-engine /check-input/ 的最小客户端，
// 用于 MCP 工具描述投毒扫描和门户附件内容扫描。内部请求必须携带共享内部令牌。
// ScanToolDescription 保留历史 fail-open 语义；ScanToolDescriptionChecked 会区分
// “扫描干净”和“扫描不可用”，供供应链准入在不可用时 fail-closed 隔离。
type securityEngineClient struct {
	baseURL       string
	internalToken string
	client        *http.Client
}

// newSecurityEngineClient 构造内部安全引擎客户端。baseURL 或令牌是否为空由各调用路径
// 按自身的 fail-open/fail-closed 契约处理。
func newSecurityEngineClient(baseURL, internalToken string) *securityEngineClient {
	return &securityEngineClient{
		baseURL:       strings.TrimRight(baseURL, "/"),
		internalToken: strings.TrimSpace(internalToken),
		client:        &http.Client{Timeout: securityEngineScanTimeout},
	}
}

func (c *securityEngineClient) setRequestHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if c == nil || c.internalToken == "" {
		return
	}
	req.Header.Set(InternalAPISecretHeader, c.internalToken)
}

// ValidateRegex 让实际执行 Python 正则的 security-engine 做权威语法与安全校验。
// valid=false 是正常的业务判定；配置、传输或响应协议异常一律返回 error，调用方
// 必须 fail-closed。错误只描述故障类别，不包含 pattern 或上游响应内容。
func (c *securityEngineClient) ValidateRegex(ctx context.Context, pattern string) (valid bool, errorCode string, err error) {
	if c == nil || c.baseURL == "" || c.internalToken == "" || c.client == nil {
		return false, "", fmt.Errorf("security engine regex validation is not configured")
	}
	if ctx == nil {
		return false, "", fmt.Errorf("security engine regex validation request is invalid")
	}

	body, err := json.Marshal(map[string]string{"pattern": pattern})
	if err != nil {
		return false, "", fmt.Errorf("security engine regex validation request is invalid")
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(c.baseURL, "/")+"/admin/v1/internal/regex/validate",
		bytes.NewReader(body),
	)
	if err != nil {
		return false, "", fmt.Errorf("security engine regex validation request is invalid")
	}
	c.setRequestHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("security engine regex validation is unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return false, "", fmt.Errorf("security engine regex validation is unavailable")
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return false, "", fmt.Errorf("security engine regex validation returned an invalid response")
	}

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, securityEngineRegexValidationResponseLimit+1))
	if err != nil || len(responseBody) > securityEngineRegexValidationResponseLimit {
		return false, "", fmt.Errorf("security engine regex validation returned an invalid response")
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	var parsed map[string]json.RawMessage
	if err := decoder.Decode(&parsed); err != nil {
		return false, "", fmt.Errorf("security engine regex validation returned an invalid response")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false, "", fmt.Errorf("security engine regex validation returned an invalid response")
	}
	if len(parsed) != 2 {
		return false, "", fmt.Errorf("security engine regex validation returned an invalid response")
	}

	validRaw, hasValid := parsed["valid"]
	errorCodeRaw, hasErrorCode := parsed["error_code"]
	if !hasValid || !hasErrorCode {
		return false, "", fmt.Errorf("security engine regex validation returned an invalid response")
	}
	validRaw = bytes.TrimSpace(validRaw)
	errorCodeRaw = bytes.TrimSpace(errorCodeRaw)
	switch {
	case bytes.Equal(validRaw, []byte("true")) && bytes.Equal(errorCodeRaw, []byte("null")):
		return true, "", nil
	case bytes.Equal(validRaw, []byte("false")):
		var code string
		if err := json.Unmarshal(errorCodeRaw, &code); err != nil {
			return false, "", fmt.Errorf("security engine regex validation returned an invalid response")
		}
		if code != "invalid_syntax" && code != "unsafe_regex" {
			return false, "", fmt.Errorf("security engine regex validation returned an invalid response")
		}
		return false, code, nil
	default:
		return false, "", fmt.Errorf("security engine regex validation returned an invalid response")
	}
}

// checkInputFinding 只解析描述投毒判定需要的字段（security-engine 返回体的子集）。
type checkInputFinding struct {
	Type     string `json:"type"`
	Category string `json:"category"`
	RuleID   string `json:"rule_id"`
}

type checkInputResponse struct {
	Findings []checkInputFinding `json:"findings"`
}

// ScanToolDescription 对单个 MCP 工具的 description 做描述投毒扫描。
// 命中判据：findings 里 type=="agent_guard" 且 category 以 "mcp_description_poison" 开头
// （覆盖正则初筛 mcp_description_poison 与语义复核 mcp_description_poison_semantic 两类）。
// 返回命中的标签（rule_id，缺则回退 category）去重数组；未命中或任何异常返回 nil。
// observe-only：本调用不改变 security-engine 的任何决策，只读取其判定结果。
func (c *securityEngineClient) ScanToolDescription(ctx context.Context, requestID, toolName, description string) []string {
	if c == nil || c.baseURL == "" || description == "" {
		return nil
	}

	reqBody := map[string]interface{}{
		"request_id": requestID,
		"content":    description,
		"context": map[string]interface{}{
			"mcp_admission_scan": true,
			"mcp_tools": []map[string]string{
				{"name": toolName, "description": description},
			},
		},
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil // fail-open
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/check-input/", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil // fail-open
	}
	c.setRequestHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil // fail-open：不可达/超时一律当未命中
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil // fail-open：非 200 当未命中
	}

	var parsed checkInputResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil // fail-open：解析失败当未命中
	}

	var flags []string
	seen := map[string]bool{}
	for _, f := range parsed.Findings {
		// 语义复核层（judge_mcp_description_poison）产出 category=mcp_description_poison_semantic，
		// 与正则初筛同属描述投毒，用前缀匹配一并纳入 poison_flags（否则 judge 命中会被静默丢弃）。
		if f.Type != "agent_guard" || !strings.HasPrefix(f.Category, "mcp_description_poison") {
			continue
		}
		flag := f.RuleID
		if flag == "" {
			flag = f.Category
		}
		if flag == "" || seen[flag] {
			continue
		}
		seen[flag] = true
		flags = append(flags, flag)
	}
	return flags
}

// ScanToolDescriptionChecked is the admission-grade variant: unlike the legacy
// observe-only wrapper it distinguishes a clean scan from an unavailable scanner.
func (c *securityEngineClient) ScanToolDescriptionChecked(ctx context.Context, requestID, toolName, description string) ([]string, error) {
	if description == "" {
		return []string{}, nil
	}
	if c == nil || c.baseURL == "" {
		return nil, fmt.Errorf("security engine is not configured")
	}
	reqBody := map[string]interface{}{
		"request_id": requestID,
		"content":    description,
		"context": map[string]interface{}{
			"mcp_tools":          []map[string]string{{"name": toolName, "description": description}},
			"mcp_admission_scan": true,
		},
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal MCP description scan: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/check-input/", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create MCP description scan: %w", err)
	}
	c.setRequestHeaders(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call MCP description scan: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("MCP description scan status %d", resp.StatusCode)
	}
	var parsed checkInputResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode MCP description scan: %w", err)
	}
	var flags []string
	seen := map[string]bool{}
	for _, finding := range parsed.Findings {
		if finding.Type != "agent_guard" || !strings.HasPrefix(finding.Category, "mcp_description_poison") {
			continue
		}
		flag := finding.RuleID
		if flag == "" {
			flag = finding.Category
		}
		if flag == "" || seen[flag] {
			continue
		}
		seen[flag] = true
		flags = append(flags, flag)
	}
	if flags == nil {
		flags = []string{}
	}
	return flags, nil
}
func (c *securityEngineClient) scanContent(ctx context.Context, requestID, text, filename, referenceKey, sha256Hex string) (string, []map[string]interface{}, error) {

	// scanContent 对文件抽取文本做 DLP 检测，返回 (action, findings, err)。
	// audit-only：调用方（portal upload ingest）负责不拦；本方法只返回检测结果。
	// payload 与 proxy-server security.go attachmentContext 对齐（attachments 带 text_preview + sha256 + reference）。
	if c == nil || c.baseURL == "" {
		return "audit", nil, nil
	}
	payload := map[string]interface{}{
		"request_id": requestID,
		"content":    text,
		"file_name":  filename,
		"context": map[string]interface{}{
			"attachments": []map[string]interface{}{{
				"source":       "portal_upload",
				"file_name":    filename,
				"reference_id": referenceKey,
				"sha256":       sha256Hex,
				"text_preview": text,
			}},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "audit", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/check-input/", bytes.NewReader(body))
	if err != nil {
		return "audit", nil, err
	}
	c.setRequestHeaders(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return "audit", nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "audit", nil, err
	}
	var parsed struct {
		Findings []map[string]interface{} `json:"findings"`
		Action   string                   `json:"action"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "audit", nil, err
	}
	if parsed.Action == "" {
		parsed.Action = "audit"
	}
	return parsed.Action, parsed.Findings, nil
}

func (c *securityEngineClient) uploadScanObject(ctx context.Context, tenantID, requestID, filename, mimeType string, data []byte) (string, error) {
	if c == nil || c.baseURL == "" || c.internalToken == "" || len(data) == 0 {
		return "", fmt.Errorf("file DLP engine is not configured")
	}
	endpoint := c.baseURL + "/scan-objects/?tenant_id=" + url.QueryEscape(tenantID) +
		"&request_id=" + url.QueryEscape(requestID) +
		"&file_name=" + url.QueryEscape(filename) +
		"&content_type=" + url.QueryEscape(mimeType)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set(InternalAPISecretHeader, c.internalToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	slowClient := &http.Client{Timeout: 60 * time.Second}
	resp, err := slowClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("scan object upload failed")
	}
	var parsed struct {
		ObjectID string `json:"object_id"`
	}
	if json.Unmarshal(body, &parsed) != nil || parsed.ObjectID == "" {
		return "", fmt.Errorf("scan object upload response is invalid")
	}
	return parsed.ObjectID, nil
}

func (c *securityEngineClient) consumeScanObject(ctx context.Context, tenantID, objectID string) {
	if c == nil || objectID == "" {
		return
	}
	endpoint := c.baseURL + "/scan-objects/" + url.PathEscape(objectID) + "?tenant_id=" + url.QueryEscape(tenantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set(InternalAPISecretHeader, c.internalToken)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// scanAttachmentObject 只把短 object_id 送统一引擎，避免门户解码后再次 Base64 编码并复制大文件。
func (c *securityEngineClient) scanAttachmentObject(ctx context.Context, tenantID, requestID, filename, mimeType, sha256Hex, objectID string) (string, []map[string]interface{}, error) {
	payload := map[string]interface{}{
		"request_id": requestID,
		"content":    "",
		"context": map[string]interface{}{
			"tenant_id": tenantID,
			"attachments": []map[string]interface{}{{
				"source":       "portal_upload",
				"file_name":    filename,
				"content_type": mimeType,
				"sha256":       sha256Hex,
				"object_id":    objectID,
			}},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "audit", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/check-input/", bytes.NewReader(body))
	if err != nil {
		return "audit", nil, err
	}
	c.setRequestHeaders(req)
	slowClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := slowClient.Do(req)
	if err != nil {
		return "audit", nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "audit", nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "audit", nil, fmt.Errorf("security engine returned HTTP %d", resp.StatusCode)
	}
	var parsed struct {
		Findings []map[string]interface{} `json:"findings"`
		Action   string                   `json:"action"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "audit", nil, err
	}
	if parsed.Action == "" {
		parsed.Action = "audit"
	}
	return parsed.Action, parsed.Findings, nil
}
