package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionfmt"
)

var accessRetentionImageHTTPClient = &http.Client{
	Timeout:       12 * time.Second,
	Transport:     newAccessRetentionImageTransport(),
	CheckRedirect: accessRetentionImageRedirectPolicy,
}
var accessRetentionImageURLAllowed = isPublicAccessRetentionImageURL

func accessRetentionImageRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return http.ErrUseLastResponse
	}
	if !accessRetentionImageURLAllowed(req.Context(), req.URL) {
		return fmt.Errorf("redirect image url host is not allowed")
	}
	return nil
}

func newAccessRetentionImageTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		ControlContext: func(ctx context.Context, network, address string, conn syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return nil
			}
			if !isPublicAccessRetentionImageAddr(addr) {
				return fmt.Errorf("image url host resolved to private address")
			}
			return nil
		},
	}
	transport.DialContext = dialer.DialContext
	return transport
}

func getAccessRetentionContentLegacy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		requestID := strings.TrimSpace(chi.URLParam(r, "request_id"))
		if requestID == "" {
			writeError(w, "invalid_request", "request id is required")
			return
		}
		scope, start, end, windowErr := retentionScopeAndWindow(r)
		if windowErr != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid UTC retention window")
			return
		}

		repo := deps.AccessContentRepo
		if repo == nil && deps.RequestLogRepo != nil {
			repo = deps.RequestLogRepo
		}
		if repo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "access content repository is not configured")
			return
		}

		item, err := getAccessContentLog(r.Context(), repo, user.TenantID, requestID, scope, start, end)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get access content")
			return
		}

		// SP4 单请求下钻 / turn 合并：
		//   - 不带 members 参数 → 单请求详情，行为与改造前完全一致（保留逐 request_id 寻址）。
		//   - 带 members=id1,id2,… → 把同一逻辑 turn 的多个成员（豆包双行/同 section 复用）的
		//     请求/响应正文与 file_metadata 合并进同一份四栏详情。members 必含本 request_id；
		//     全部成员都按 user.TenantID 收口取数，跨租户不可见。任一成员缺失静默跳过。
		if members := parseTurnMemberIDs(r.URL.Query().Get("members"), requestID); len(members) > 1 {
			logs, merr := getAccessContentLogs(r.Context(), repo, user.TenantID, members, scope, start, end)
			if merr != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get turn member content")
				return
			}
			if merged := mergeTurnAccessContentLogs(requestID, members, logs); merged != nil {
				item = merged
			}
		}

		if item == nil {
			// 主链路（反向代理/主对话）只写 content_logs，不写 access_content_logs。
			// 留存详情对这类请求做读侧回退：用 content_logs 合成请求/响应内容，
			// 让「审计合规→内容留存」对每一条反向代理请求都有记录。
			// 该回退不挂 content_audit_enabled——内容留存是合规底账，不随浏览开关关闭。
			if deps.ContentLogReader != nil {
				logs, lerr := listContentLogsByRequest(r.Context(), deps.ContentLogReader, user.TenantID, requestID, scope, start, end)
				if lerr != nil {
					writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get content logs")
					return
				}
				if len(logs) > 0 {
					// 与 proxy 侧 messagesToRetentionText 同款折叠（共用 shared-go/retentionfmt）：
					//   - 真实对话（用户提问/模型回复）在前、机器噪音（系统提示词/工具）在后，
					//     防 64KB 截断切掉真话；
					//   - 编码 agent（WorkBuddy/Claude Code）把真实用户输入包在 <user_query> 里、
					//     周围塞满 <system-reminder> 上下文——剥出 <user_query> 作正文、其余折叠；
					//   - system/tool 段先 CollapseBlankLines 压平成单 paragraph 再加【角色】前缀，
					//     否则巨型系统提示词内部空行会把它裂成多段、只有首段带前缀、其余当正文展开＝噪音。
					var convo, noise, respParts []string
					for _, l := range logs {
						content := strings.TrimSpace(retentionfmt.NormalizeNewlines(l.Content))
						if content == "" {
							continue
						}
						switch l.Role {
						case "assistant":
							respParts = append(respParts, content) // 模型回复是正文，不折叠
						case "user":
							if query, rest := retentionfmt.SplitUserQuery(content); query != "" {
								convo = append(convo, query)
								if rest != "" {
									noise = append(noise, "【system】"+retentionfmt.CollapseBlankLines(rest))
								}
							} else if retentionfmt.IsAgentMetaContent(content) {
								// 无 <user_query> 但整段是塞在 user 里的 agent 系统提示词 → 折叠。
								noise = append(noise, "【system】"+retentionfmt.CollapseBlankLines(content))
							} else {
								convo = append(convo, content) // 普通真实提问
							}
						default:
							// system / tool / 其它角色既不是用户提问也不是模型回复，但合规底账
							// 不能丢内容：折叠成单段、加【角色】前缀，供前端 collapseSystemSections
							// 整块折叠，避免被当成「用户问了什么」或误提取成上传文件。
							label := l.Role
							if label == "" {
								label = "其它"
							}
							noise = append(noise, "【"+label+"】"+retentionfmt.CollapseBlankLines(content))
						}
					}
					reqParts := make([]string, 0, len(convo)+len(noise))
					reqParts = append(reqParts, convo...)
					reqParts = append(reqParts, noise...)
					// content_logs 无留存截止时间列，回退记录的 RetentionUntil 恒为空（omitempty 省略）。
					info := types.AccessRetentionContentInfo{
						RequestID:       requestID,
						RequestContent:  strings.Join(reqParts, "\n\n"),
						ResponseContent: strings.Join(respParts, "\n\n"),
						FileMetadata:    []map[string]interface{}{},
					}
					w.Header().Set("Content-Type", "application/json")
					rawRequest := info.RequestContent
					info.RequestContent = formatAccessRetentionRequest(rawRequest)
					info.ResponseContent = formatAccessRetentionResponse(info.ResponseContent, rawRequest)
					_ = json.NewEncoder(w).Encode(info)
					return
				}
			}
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "access content not found")
			return
		}

		normalizeAccessRetentionContent(item)
		fileMetadata := []map[string]interface{}{}
		if len(item.FileMetadataJSON) > 0 {
			if err := json.Unmarshal(item.FileMetadataJSON, &fileMetadata); err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to parse access content metadata")
				return
			}
		}

		// 网页版上传的真实字节存放在「上传行」，对话行只携带 source=json_file_reference 的
		// 引用条目。按 reference_id 在租户内解引用，把图片/文件字节合并回这些引用条目，让后台
		// 留存详情直接展示真实图片/文件，而不是只显示一个引用 ID。
		referenceIDs := make([]string, 0, len(fileMetadata))
		seenRef := map[string]bool{}
		for _, entry := range fileMetadata {
			refID, _ := entry["reference_id"].(string)
			if refID == "" {
				continue
			}
			if dataB64, _ := entry["data_base64"].(string); dataB64 != "" {
				continue // 条目已自带字节，无需解引用
			}
			if !seenRef[refID] {
				seenRef[refID] = true
				referenceIDs = append(referenceIDs, refID)
			}
		}
		if len(referenceIDs) > 0 {
			resolved, err := resolveUploadedFileBytes(r.Context(), repo, user.TenantID, referenceIDs, scope, start, end)
			if err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to resolve uploaded file content")
				return
			}
			for _, entry := range fileMetadata {
				refID, _ := entry["reference_id"].(string)
				if refID == "" {
					continue
				}
				file, ok := resolved[refID]
				if !ok || file.DataBase64 == "" {
					continue
				}
				entry["data_base64"] = file.DataBase64
				if file.FileName != "" {
					entry["file_name"] = file.FileName
				}
				if file.ContentType != "" {
					entry["content_type"] = file.ContentType
				}
				if file.SHA256 != "" {
					entry["sha256"] = file.SHA256
				}
				if file.Size > 0 {
					entry["size"] = file.Size
				}
				// 改写成可预览/可下载的真实文件，而非引用 ID：前端 isReferenceFile 依据
				// source==='json_file_reference' 或 (reference_id && !file_name) 判定为引用，
				// 这里改写 source=multipart、stage=request 并补齐 file_name。
				entry["source"] = "multipart"
				entry["stage"] = "request"
			}
		}

		// 小图内联：把已外置(externalized)的小图片字节随详情响应一并返回(data_base64)，
		// 让前端不必再为每张图单发一次 /blob 请求——省掉一次网络往返，图随正文一起出现。
		// 仅限小图(≤64KB/张)且设总预算(≤512KB)，避免详情响应被大图撑大反而更慢；大图仍走 /blob 懒加载。
		// 不入库、只在本次响应内联。对话行上传图已在上面按 reference_id 带上 data_base64，这里只补
		// 模型返回/引用的外置图。任何失败/超限静默跳过——object_key 仍在，前端回退 /blob，绝不影响显示。
		if deps.RetentionStore != nil {
			const maxInlineImageBytes = 64 << 10
			const maxInlineTotalBytes = 512 << 10
			inlinedTotal := 0
			for _, entry := range fileMetadata {
				if dataB64, _ := entry["data_base64"].(string); dataB64 != "" {
					continue // 已带字节（上传图解引用）
				}
				objectKey, _ := entry["object_key"].(string)
				if objectKey == "" {
					continue
				}
				ct, _ := entry["content_type"].(string)
				if !strings.HasPrefix(strings.ToLower(ct), "image/") {
					continue
				}
				var sz int64
				switch v := entry["size"].(type) {
				case float64:
					sz = int64(v)
				case int64:
					sz = v
				}
				if sz <= 0 || sz > maxInlineImageBytes {
					continue
				}
				if inlinedTotal+int(sz) > maxInlineTotalBytes {
					continue
				}
				obj, gerr := deps.RetentionStore.GetObject(r.Context(), user.TenantID, objectKey)
				if gerr != nil {
					continue
				}
				data, rerr := io.ReadAll(io.LimitReader(obj.Body, maxInlineImageBytes+1))
				obj.Body.Close()
				if rerr != nil || len(data) == 0 || len(data) > maxInlineImageBytes {
					continue
				}
				entry["data_base64"] = base64.StdEncoding.EncodeToString(data)
				if ct == "" {
					if ctMeta := strings.TrimSpace(obj.Metadata.ContentType); ctMeta != "" {
						entry["content_type"] = ctMeta
					}
				}
				inlinedTotal += len(data)
			}
		}

		info := types.AccessRetentionContentInfo{
			RequestID:       item.RequestID,
			RequestContent:  item.RequestContent,
			ResponseContent: item.ResponseContent,
			FileMetadata:    fileMetadata,
		}
		if item.RetentionUntil != nil {
			info.RetentionUntil = item.RetentionUntil.Format(time.RFC3339)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	}
}

// GetAccessRetentionImageProxy 返回带证据读取审计的 handler（Low-2）：读取成功后写 evidence.read，见 AuditEvidenceRead。
func GetAccessRetentionImageProxy(deps *Dependencies) http.HandlerFunc {
	return auditedEvidenceHandler(deps, "image_proxy", getAccessRetentionImageProxyInner(deps))
}

func getAccessRetentionImageProxyInner(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		requestID := strings.TrimSpace(chi.URLParam(r, "request_id"))
		rawURL := strings.TrimSpace(r.URL.Query().Get("url"))
		if requestID == "" || rawURL == "" {
			writeError(w, "invalid_request", "request id and url are required")
			return
		}
		scope, start, end, windowErr := retentionScopeAndWindow(r)
		if windowErr != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid UTC retention window")
			return
		}
		imageURL, err := url.Parse(rawURL)
		if err != nil || imageURL == nil || imageURL.Host == "" || (imageURL.Scheme != "https" && imageURL.Scheme != "http") {
			writeError(w, "invalid_request", "only absolute http(s) image urls are supported")
			return
		}
		if !accessRetentionImageURLAllowed(r.Context(), imageURL) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "image url host is not allowed")
			return
		}

		repo := deps.AccessContentRepo
		if repo == nil && deps.RequestLogRepo != nil {
			repo = deps.RequestLogRepo
		}
		if repo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "access content repository is not configured")
			return
		}

		item, err := getAccessContentLog(r.Context(), repo, user.TenantID, requestID, scope, start, end)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get access content")
			return
		}
		// SP4 turn 合并：详情合并展示时，图片可能来自 turn 内其它成员。带 members 参数时把
		// 鉴权范围扩到同 turn 全部成员的留证内容——只要该 URL 出现在任一成员里即放行，
		// 与 /content 合并口径一致；不带 members 仍只按单条 request_id 鉴权（行为不变）。
		if members := parseTurnMemberIDs(r.URL.Query().Get("members"), requestID); len(members) > 1 {
			logs, merr := getAccessContentLogs(r.Context(), repo, user.TenantID, members, scope, start, end)
			if merr != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to get turn member content")
				return
			}
			if merged := mergeTurnAccessContentLogs(requestID, members, logs); merged != nil {
				item = merged
			}
		}
		if item == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "access content not found")
			return
		}
		if !accessRetentionContentContainsURL(item, rawURL) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "image url is not retained for this request")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		outboundReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			writeError(w, "invalid_request", "invalid image url")
			return
		}
		outboundReq.Header.Set("User-Agent", "jjdguard-access-retention-image-proxy/1.0")

		resp, err := accessRetentionImageHTTPClient.Do(outboundReq)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadGateway, "bad_gateway", "failed to fetch retained image")
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			writeErrorWithStatus(w, http.StatusBadGateway, "bad_gateway", "retained image fetch failed")
			return
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		if !strings.HasPrefix(strings.ToLower(contentType), "image/") {
			writeErrorWithStatus(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "retained url is not an image")
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "private, no-store")
		if _, err := io.Copy(w, io.LimitReader(resp.Body, 25<<20)); err != nil {
			return
		}
	}
}

const (
	maxTurnMemberIDs           = 500
	maxEvidenceRunMembers      = 5000
	maxEvidenceMembersBodySize = 1 << 20
)

// parseTurnMemberIDs 解析 members 查询参数（逗号分隔的 request_id 列表）为去重后的成员集，
// 并保证本请求 requestID 一定在内。空/无效输入返回仅含 requestID 的单元素集（即退回单请求）。
func parseTurnMemberIDs(raw string, requestID string) []string {
	return normalizeTurnMemberIDs(strings.Split(raw, ","), requestID, maxTurnMemberIDs)
}

func normalizeTurnMemberIDs(raw []string, requestID string, limit int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	add := func(id string) {
		if len(out) >= limit {
			return
		}
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	add(requestID)
	for _, part := range raw {
		add(part)
	}
	return out
}

func readEvidenceMemberIDs(w http.ResponseWriter, r *http.Request, requestID string) ([]string, error) {
	var members []string
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxEvidenceMembersBodySize)
		var payload struct {
			Members []string `json:"members"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil {
			return nil, fmt.Errorf("invalid members body: %w", err)
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return nil, fmt.Errorf("invalid members body")
		}
		members = normalizeTurnMemberIDs(payload.Members, requestID, maxEvidenceRunMembers)
	} else {
		members = parseTurnMemberIDs(r.URL.Query().Get("members"), requestID)
	}
	if len(members) > maxEvidenceRunMembers {
		return nil, fmt.Errorf("too many evidence run members")
	}
	return members, nil
}

// mergeTurnAccessContentLogs 把同一 conversation 的物理请求合并成多轮会话详情：
//   - 同 section_id 的多条物理请求折叠为一轮，正文取该轮最后一个非空请求/响应；
//   - 不同 section_id 按 created_at 顺序展示为「第 N/M 轮」；
//   - file_metadata 汇总所有物理请求并按 sha256/reference_id/file_name 去重；
//   - section_id 为空时按 request_id 单独成轮，避免误并旧数据；
//   - retention_until 取成员中最晚的截止时间，RequestID 保持代表行 requestID。
//
// 仅当存在至少一条成员内容时返回合并记录；否则返回 nil。
func mergeTurnAccessContentLogs(requestID string, members []string, logs []repository.AccessContentLog) *repository.AccessContentLog {
	if len(logs) == 0 {
		return nil
	}
	type conversationRound struct {
		requestContent  string
		responseContent string
	}
	rounds := make([]conversationRound, 0, len(logs))
	roundIndex := map[string]int{}
	mergedMeta := []map[string]interface{}{}
	var latestUntil *time.Time
	for _, l := range logs {
		key := strings.TrimSpace(l.SectionID)
		if key == "" {
			key = "request:" + l.RequestID
		}
		idx, ok := roundIndex[key]
		if !ok {
			idx = len(rounds)
			roundIndex[key] = idx
			rounds = append(rounds, conversationRound{})
		}
		if strings.TrimSpace(l.RequestContent) != "" {
			rounds[idx].requestContent = l.RequestContent
		}
		if strings.TrimSpace(l.ResponseContent) != "" {
			rounds[idx].responseContent = l.ResponseContent
		}
		if len(l.FileMetadataJSON) > 0 {
			var arr []map[string]interface{}
			if err := json.Unmarshal(l.FileMetadataJSON, &arr); err == nil {
				mergedMeta = append(mergedMeta, arr...)
			}
		}
		if l.RetentionUntil != nil && (latestUntil == nil || l.RetentionUntil.After(*latestUntil)) {
			latestUntil = l.RetentionUntil
		}
	}

	var reqParts, respParts []string
	multiRound := len(rounds) > 1
	for idx, round := range rounds {
		prefix := ""
		if multiRound {
			prefix = fmt.Sprintf("【第 %d/%d 轮】\n", idx+1, len(rounds))
		}
		if strings.TrimSpace(round.requestContent) != "" {
			reqParts = append(reqParts, prefix+round.requestContent)
		}
		if strings.TrimSpace(round.responseContent) != "" {
			respParts = append(respParts, prefix+round.responseContent)
		}
	}
	metaJSON, err := json.Marshal(dedupeTurnFileMetadata(mergedMeta))
	if err != nil {
		metaJSON = []byte("[]")
	}
	return &repository.AccessContentLog{
		RequestID:        requestID,
		RequestContent:   strings.Join(reqParts, "\n\n"),
		ResponseContent:  strings.Join(respParts, "\n\n"),
		FileMetadataJSON: metaJSON,
		RetentionUntil:   latestUntil,
	}
}

// dedupeTurnFileMetadata 把 turn 合并后的 file_metadata 数组按文件去重，避免同一文件在多个
// 成员里重复出现（豆包双行/同 section 复用常携带相同的上传/引用/生成文件）。
//
//   - 去重键：sha256 非空则用 sha256；否则 reference_id；否则 file_name——与前端 uniqueFiles 的
//     `reference_id||sha256||file_name` 口径对齐。三者全空的条目无法判等，原样保留。
//   - 同键多条时优先保留「带字节」的那条（object_key / download_url / data_base64 任一非空），
//     让详情能直接预览/下载；都不带字节则保留首次出现的那条。
//   - 保持各文件首次出现的相对顺序（含无键条目按原序穿插）。
func dedupeTurnFileMetadata(entries []map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(entries))
	indexByKey := map[string]int{} // 去重键 -> out 中的下标
	for _, entry := range entries {
		key := turnFileMetadataDedupKey(entry)
		if key == "" {
			// 无法判等，原样保留（不折叠）。
			out = append(out, entry)
			continue
		}
		if idx, ok := indexByKey[key]; ok {
			// 已有同键：仅当现存条目不带字节、而新条目带字节时，用新条目替换（升级为可预览/下载）。
			if !turnFileMetadataHasBytes(out[idx]) && turnFileMetadataHasBytes(entry) {
				out[idx] = entry
			}
			continue
		}
		indexByKey[key] = len(out)
		out = append(out, entry)
	}
	return out
}

// turnFileMetadataDedupKey 取文件去重键：sha256 > reference_id > file_name，全空返回 ""。
func turnFileMetadataDedupKey(entry map[string]interface{}) string {
	for _, field := range []string{"sha256", "reference_id", "file_name"} {
		if v, ok := entry[field].(string); ok {
			if v = strings.TrimSpace(v); v != "" {
				return field + ":" + v
			}
		}
	}
	return ""
}

// turnFileMetadataHasBytes 判断条目是否「带字节」（可直接预览/下载）。
func turnFileMetadataHasBytes(entry map[string]interface{}) bool {
	for _, field := range []string{"object_key", "download_url", "data_base64"} {
		if v, ok := entry[field].(string); ok && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

func isPublicAccessRetentionImageURL(ctx context.Context, imageURL *url.URL) bool {
	if imageURL == nil {
		return false
	}
	host := imageURL.Hostname()
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return isPublicAccessRetentionImageIP(ip)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, addr := range addrs {
		if !isPublicAccessRetentionImageIP(addr.IP) {
			return false
		}
	}
	return true
}

func isPublicAccessRetentionImageIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return !ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsUnspecified() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast()
}

func isPublicAccessRetentionImageAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	return !addr.IsLoopback() &&
		!addr.IsPrivate() &&
		!addr.IsUnspecified() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsMulticast()
}

func accessRetentionContentContainsURL(item *repository.AccessContentLog, rawURL string) bool {
	if rawURL == "" || item == nil {
		return false
	}
	if strings.Contains(item.RequestContent, rawURL) || strings.Contains(item.ResponseContent, rawURL) {
		return true
	}
	var metadata []map[string]interface{}
	if len(item.FileMetadataJSON) == 0 || json.Unmarshal(item.FileMetadataJSON, &metadata) != nil {
		return false
	}
	for _, entry := range metadata {
		for _, key := range []string{"download_url", "url", "signed_url", "preview_url"} {
			if value, ok := entry[key].(string); ok && value == rawURL {
				return true
			}
		}
	}
	return false
}
