package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// 脱敏原文留证（迁移 994）的控制台接口。
//   - 列表只返回元数据（请求、方向、命中规则、阻断编号），永远不含原文；
//   - 查看原文的事由可选（最多 200 字）；每次查看都先写入操作审计（含审计链）再解密返回，写审计失败则不返回原文；
//   - 仅系统管理员与安全保密员可调用（roles.CanViewRawEvidence + SoD 类 raw_evidence 双重限制），身份检查与现有内容留证一致；
//     开关是全局设置，只有系统管理员可改。

const (
	rawEvidenceSettingKey     = "raw_evidence_enabled"
	rawEvidenceRevealAction   = "reveal_raw_evidence"
	rawEvidenceSettingAction  = "update_raw_evidence_setting"
	rawEvidenceMaxReasonRunes = 200
)

type rawEvidenceRevealRequest struct {
	Reason string `json:"reason"`
}

type rawEvidenceRevealResponse struct {
	repository.RawEvidenceMeta
	Text string `json:"text"`
	// Hits 命中段（UTF-16 下标），Rules 本条留证涉及的阻断/脱敏规则及是否在原文里定位到。
	Hits  []rawEvidenceHit      `json:"hits"`
	Rules []rawEvidenceRuleNote `json:"rules"`
}

// rawEvidenceSummariesLoader 可在测试里替换。
var rawEvidenceSummariesLoader = loadRawEvidenceSummaries

type rawEvidenceSettingBody struct {
	Enabled *bool `json:"enabled"`
}

// canViewRawEvidenceUser 是原文留证访问的唯一角色判断：系统管理员、安全保密员，且不是部门应急指派账号。
// 原文留证接口与告警里的“原文留证条数”共用它，不要另写一套规则。
func canViewRawEvidenceUser(user *repository.User) bool {
	return user != nil && user.DepartmentAssignmentMode != "emergency" && roles.CanViewRawEvidence(user.Role)
}

// rawEvidenceUser 与现有内容留证（RequireFullTenantContentEvidence）同一套身份检查，再收窄到两类角色：
// 会话与用户必须一致且同租户；部门应急指派（emergency）账号不能看；旧 admin 角色不放行
// （现有内容留证同样不放行旧 admin，迁移 890 已把它改写为 platform_admin）。
func rawEvidenceUser(w http.ResponseWriter, r *http.Request) *repository.User {
	user, ok := authenticatedContentEvidenceUser(w, r)
	if !ok {
		return nil
	}
	if !canViewRawEvidenceUser(user) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "仅系统管理员和安全保密员可查看脱敏原文留证")
		return nil
	}
	return user
}

// rawEvidenceSettingAdmin：开关 raw_evidence_enabled 存在全局 system_settings 里、对全部租户生效，
// 只有平台系统管理员（platform_admin）能改；安全保密员只能查看开关状态。
func rawEvidenceSettingAdmin(w http.ResponseWriter, r *http.Request) *repository.User {
	user := rawEvidenceUser(w, r)
	if user == nil {
		return nil
	}
	if user.Role != roles.SystemAdmin {
		writeErrorWithStatus(w, http.StatusForbidden, "global_config_requires_system_admin",
			"脱敏原文留证开关对全平台生效，只有系统管理员可以修改")
		return nil
	}
	return user
}

func rawEvidenceEnabled(r *http.Request, deps *Dependencies) bool {
	if deps == nil || deps.SystemRepo == nil {
		return true
	}
	setting, err := deps.SystemRepo.Get(r.Context(), rawEvidenceSettingKey)
	if err != nil || setting == nil {
		return true
	}
	return strings.TrimSpace(strings.ToLower(setting.Value)) != "false"
}

// ListRawEvidence 按请求编号、阻断编号、命中规则等定位留证；只返回元数据。
func ListRawEvidence(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := rawEvidenceUser(w, r)
		if user == nil {
			return
		}
		q := r.URL.Query()
		filter := repository.RawEvidenceFilter{
			TenantID:    user.TenantID,
			RequestID:   strings.TrimSpace(q.Get("request_id")),
			BlockID:     strings.TrimSpace(q.Get("block_id")),
			Rule:        strings.TrimSpace(q.Get("rule")),
			Direction:   strings.TrimSpace(q.Get("direction")),
			Disposition: strings.TrimSpace(q.Get("disposition")),
		}
		if filter.Direction != "" && filter.Direction != "input" && filter.Direction != "output" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "direction 只能是 input 或 output")
			return
		}
		if filter.Disposition != "" && filter.Disposition != "masked" && filter.Disposition != "blocked" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "disposition 只能是 masked 或 blocked")
			return
		}
		for key, dst := range map[string]*time.Time{"start": &filter.Start, "end": &filter.End} {
			if raw := strings.TrimSpace(q.Get(key)); raw != "" {
				parsed, err := time.Parse(time.RFC3339, raw)
				if err != nil {
					writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", key+" 需为 RFC3339 时间")
					return
				}
				*dst = parsed
			}
		}
		filter.Limit, _ = strconv.Atoi(q.Get("limit"))
		filter.Offset, _ = strconv.Atoi(q.Get("offset"))
		if filter.Offset < 0 {
			filter.Offset = 0
		}
		items, total, err := repository.NewRawEvidenceRepository(deps.DB).List(r.Context(), filter)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list raw evidence")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]interface{}{"items": items, "total": total, "enabled": rawEvidenceEnabled(r, deps)})
	}
}

// RevealRawEvidence 解密返回一条原文。顺序固定：校验 → 写审计（失败即终止）→ 解密 → 返回。
func RevealRawEvidence(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := rawEvidenceUser(w, r)
		if user == nil {
			return
		}
		// 事由可选（政企界面一路点通，不强制填写）：空请求体、{}、空事由都合法，审计里事由记空；
		// 只保留长度上限防滥用。
		var body rawEvidenceRevealRequest
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "请求体过大")
			return
		}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "请求体需为 JSON：{\"reason\":\"查看事由（可不填）\"}")
				return
			}
		}
		reason := strings.TrimSpace(body.Reason)
		if utf8.RuneCountInString(reason) > rawEvidenceMaxReasonRunes {
			writeErrorWithStatus(w, http.StatusBadRequest, "reason_too_long", "查看事由最多 200 字")
			return
		}
		id := chi.URLParam(r, "id")
		row, err := repository.NewRawEvidenceRepository(deps.DB).Get(r.Context(), user.TenantID, id)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load raw evidence")
			return
		}
		if row == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "raw evidence not found")
			return
		}
		// 引用行（去重后同会话后续请求写的那一行）不含密文：原文从它指向的首条留证解密，
		// 首条按同一租户查（跨租户引用视为不存在）；首条已过保留期则 404。
		source := row
		if row.RefEvidenceID != "" {
			source, err = repository.NewRawEvidenceRepository(deps.DB).Get(r.Context(), user.TenantID, row.RefEvidenceID)
			if err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load raw evidence")
				return
			}
			if source == nil || source.RefEvidenceID != "" || source.SessionID != row.SessionID {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "首次出现的原文留证已不存在（可能已过保留期）")
				return
			}
		}
		// 先审计后返回：审计里有谁、何时、哪个请求、哪条留证与事由，但绝不含原文。
		// 操作审计与审计链都必须成功才解密：任何一个不可用或写失败，直接 500，响应里不含原文。
		if deps.SystemRepo == nil || deps.AuditAppender == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "audit_unavailable", "审计不可用，已拒绝返回原文")
			return
		}
		detail := map[string]interface{}{
			"evidence_id": row.ID, "request_id": row.RequestID, "block_id": row.BlockID,
			"direction": row.Direction, "disposition": row.Disposition, "message_index": row.MessageIndex,
			"rule_ids": row.RuleIDs, "reason": reason, "ref_evidence_id": row.RefEvidenceID,
		}
		op := &repository.AuditOperation{
			ID: uuid.New().String(), UserID: user.ID, ActionType: rawEvidenceRevealAction,
			ActionDetail: detail, TargetType: "raw_evidence", TargetID: row.ID, IPAddress: r.RemoteAddr,
		}
		if err := deps.SystemRepo.CreateAuditOperation(r.Context(), op); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "audit_unavailable", "审计写入失败，已拒绝返回原文")
			return
		}
		if err := appendAuditChain(r.Context(), deps, user.TenantID, rawEvidenceRevealAction, op.ID, detail); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "audit_unavailable", "审计链写入失败，已拒绝返回原文")
			return
		}

		plain, err := secrets.DecryptRawEvidence(source.Ciphertext, secrets.RawEvidenceAAD(source.TenantID, source.RequestID, source.UserID, source.SessionID, source.Direction, source.MessageIndex, source.Disposition))
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "decrypt_failed", "原文无法解密（检查 JJD_PROVIDER_SECRET_KEY/JJD_MASTER_KEY 与 JJD_SECRETS_CIPHER/JJD_SM4_KEYRING 是否与网关写入时一致）")
			return
		}
		text := string(plain)
		hits, rules := []rawEvidenceHit{}, []rawEvidenceRuleNote{}
		// 定位只按本请求的安全事件；读事件失败不影响查看原文。
		if summaries, err := rawEvidenceSummariesLoader(deps)(r.Context(), user.TenantID, row.RequestID); err == nil {
			hits, rules = locateRawEvidenceHits(text, row.Direction, summaries)
			if hits == nil {
				hits = []rawEvidenceHit{}
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, rawEvidenceRevealResponse{RawEvidenceMeta: row.RawEvidenceMeta, Text: text, Hits: hits, Rules: rules})
	}
}

// GetRawEvidenceSettings / UpdateRawEvidenceSettings 管理独立开关"脱敏原文留证"。
func GetRawEvidenceSettings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rawEvidenceUser(w, r) == nil {
			return
		}
		writeJSON(w, map[string]interface{}{"enabled": rawEvidenceEnabled(r, deps)})
	}
}

func UpdateRawEvidenceSettings(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := rawEvidenceSettingAdmin(w, r)
		if user == nil {
			return
		}
		var body rawEvidenceSettingBody
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil || body.Enabled == nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "请求体需为 JSON：{\"enabled\":true|false}")
			return
		}
		previous := rawEvidenceEnabled(r, deps)
		if err := deps.SystemRepo.Set(r.Context(), rawEvidenceSettingKey, strconv.FormatBool(*body.Enabled)); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to update setting")
			return
		}
		logAudit(r, deps, rawEvidenceSettingAction, map[string]interface{}{"previous": previous, "enabled": *body.Enabled}, "setting", rawEvidenceSettingKey)
		writeJSON(w, map[string]interface{}{"enabled": *body.Enabled})
	}
}
