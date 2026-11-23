package handler

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

type rulePackTenantSource interface {
	GetByID(context.Context, string) (*repository.Tenant, error)
}

type rulePackRuleSource interface {
	ListCompilableRulesByTenant(context.Context, string, string) ([]*repository.Rule, error)
	ListActiveContentAuditExceptionsByTenant(context.Context, string) ([]*repository.ContentAuditException, error)
}

const maxRulePackCandidates = 10000

const (
	rulePackAttestationHeader          = "X-Rule-Pack-Attestation"
	rulePackAttestationUnavailableCode = "rule_pack_attestation_unavailable"
	rulePackAttestationInvalidCode     = "rule_pack_attestation_invalid"
	rulePackAttestationModeTenantToken = "tenant_scoped_token"
	invalidRulePackTenantCode          = "invalid_rule_pack_tenant"
	invalidRulePackNodeCode            = "invalid_rule_pack_node"
	invalidRulePackVersionCode         = "invalid_rule_pack_version"
	maxRulePackTenantIDLength          = 128
)

var errRulePackCandidateLimitExceeded = errors.New("runtime rule candidate limit exceeded")
var validRulePackTenantIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)
var validRulePackVersionPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// GetInternalRulePack 是「方案A：规则编译下发」的内部下发接口。
//
// security-engine 携带 X-JJDGuard-Internal-Token + X-Tenant-ID 拉取本租户的运行时
// 规则包；本路由仅挂载在内部鉴权中间件（InternalAPIMiddleware）之后。
// 权威的 ReDoS 校验已在 rules.Compile（编译期）完成，不安全正则不会出现在响应里。
func GetInternalRulePack(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := resolveInternalTenantID(r)
		if tenantID == "" {
			writeUnauthorized(w, "tenant context not found")
			return
		}
		if !validRulePackTenantID(tenantID) {
			writeErrorWithStatus(w, http.StatusBadRequest, invalidRulePackTenantCode, "tenant context is invalid")
			return
		}
		nodeID := strings.TrimSpace(r.Header.Get(nodeIDHeader))
		if nodeID == "" || len([]rune(nodeID)) > rulePackNodeIDMaxLength {
			writeErrorWithStatus(w, http.StatusBadRequest, invalidRulePackNodeCode, "node identity is invalid")
			return
		}
		heldVersion := r.Header.Get(rulePackVersionHeader)
		if !validRulePackHeldVersion(heldVersion) {
			writeErrorWithStatus(w, http.StatusBadRequest, invalidRulePackVersionCode, "held rule pack version is invalid")
			return
		}
		if status, code := verifyRulePackAttestation(deps, tenantID, r.Header.Get(rulePackAttestationHeader)); status != 0 {
			if status == http.StatusServiceUnavailable {
				logRulePackSecurityEvent(r, tenantID, code)
			}
			writeErrorWithStatus(w, status, code, "rule pack attestation failed")
			return
		}
		pack, err := compileTenantRulePack(r.Context(), deps, tenantID)
		if err != nil {
			logRulePackSecurityEvent(r, tenantID, runtimeCompileUnavailableCode)
			writeErrorWithStatus(w, http.StatusServiceUnavailable, runtimeCompileUnavailableCode, "runtime rule pack is unavailable")
			return
		}
		// 旧引擎（未声明能力）的 CompiledPolicy 是严格 DTO，收到新字段会拒收整包：
		// 按引擎声明裁剪，缺失能力记入节点台账（pull-status 显示"需升级引擎"）。
		missingCapabilities := rules.AdaptForEngine(pack, r.Header.Get(engineCapabilitiesHeader))
		if len(missingCapabilities) > 0 {
			log.Printf("rule pack served without %v to node %q of tenant %q: security-engine must be upgraded",
				missingCapabilities, safeRulePackLogField(nodeID, 64), safeRulePackLogField(tenantID, 64))
		}
		// 登记该节点本次拉取（持有版本 vs 本次下发版本），供 /admin/v1/rules/pull-status 观测各节点收敛。
		if !recordRulePackPullWithPolicyTelemetry(
			nodeID,
			tenantID,
			heldVersion,
			pack.Version,
			parseOptionalRulePackCount(r.Header.Get(rulePackActiveCountHeader)),
			parseOptionalRulePackCount(r.Header.Get(rulePackSkippedCountHeader)),
			parseOptionalRulePackCount(r.Header.Get(rulePackPolicyCountHeader)),
			parseRulePackRefreshSeconds(r.Header.Get(rulePackRefreshSecondsHeader)),
			time.Now().UTC(),
		) {
			writeErrorWithStatus(w, http.StatusBadRequest, invalidRulePackNodeCode, "node identity is invalid")
			return
		}
		markRulePackNodeEngineUpgrade(tenantID, nodeID, missingCapabilities)
		// generated_at 由 handler 盖戳（保持编译器纯函数）；引擎据此做缓存与热更新判定。
		pack.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
		writeAgentGuardJSON(w, pack)
	}
}

func logRulePackSecurityEvent(r *http.Request, tenantID, code string) {
	requestID := "-"
	if r != nil {
		requestID = safeRulePackLogField(r.Header.Get("X-Request-ID"), 128)
		if requestID == "" {
			requestID = "-"
		}
	}
	log.Printf("rule_pack_security_event request_id=%q tenant_id=%q code=%q", requestID, safeRulePackLogField(tenantID, maxRulePackTenantIDLength), safeRulePackLogField(code, 64))
}

func safeRulePackLogField(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	filtered := make([]rune, 0, len(value))
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			continue
		}
		filtered = append(filtered, char)
		if len(filtered) == maxRunes {
			break
		}
	}
	return string(filtered)
}

func validRulePackTenantID(tenantID string) bool {
	return len(tenantID) > 0 && len(tenantID) <= maxRulePackTenantIDLength && strings.TrimSpace(tenantID) == tenantID && validRulePackTenantIDPattern.MatchString(tenantID)
}

func validRulePackHeldVersion(version string) bool {
	return version == "" || validRulePackVersionPattern.MatchString(version)
}

func verifyRulePackAttestation(deps *Dependencies, tenantID, provided string) (int, string) {
	if deps == nil {
		return http.StatusServiceUnavailable, rulePackAttestationUnavailableCode
	}
	expected, ok := deps.RulePackAttestationTokens[tenantID]
	if !ok || strings.TrimSpace(expected) == "" {
		return http.StatusServiceUnavailable, rulePackAttestationUnavailableCode
	}
	expectedHash := sha256.Sum256([]byte(expected))
	providedHash := sha256.Sum256([]byte(provided))
	if subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) != 1 {
		return http.StatusUnauthorized, rulePackAttestationInvalidCode
	}
	return 0, ""
}

// compileTenantRulePack 编译指定租户的运行时规则包并盖上内容版本号，是
// GetInternalRulePack（引擎拉取）与 SyncRuleSet/GetVersionInfo（版本与收敛查询）
// 共用的**唯一**编译路径——确保各处算出的权威版本完全一致，从根上杜绝版本漂移。
//
// 返回的规则包已叠加 FilePolicy 并在叠加之后计算 pack.Version；但**不**盖
// generated_at 时间戳、也**不**登记拉取台账（那是各 handler 自身的职责）。
func compileTenantRulePack(ctx context.Context, deps *Dependencies, tenantID string) (*rules.RulePack, error) {
	if deps == nil || deps.RuleRepo == nil {
		return nil, errors.New("runtime rule source is unavailable")
	}
	var tenantSource rulePackTenantSource
	if deps.TenantRepo != nil {
		tenantSource = deps.TenantRepo
	}
	pack, err := compileTenantRulePackFromSources(ctx, tenantID, tenantSource, deps.RuleRepo)
	if err != nil {
		return nil, err
	}

	if err := applyRulePackFilePolicy(ctx, deps.SystemRepo, tenantID, pack); err != nil {
		return nil, err
	}
	if err := applyRulePackReplyPolicy(ctx, deps, tenantID, pack); err != nil {
		return nil, err
	}
	// 内容版本号：在 FilePolicy 叠加之后计算，确保版本覆盖最终下发内容。
	pack.Version = rules.ContentVersion(*pack)
	return pack, nil
}

func compileTenantRulePackFromSources(ctx context.Context, tenantID string, tenantSource rulePackTenantSource, ruleSource rulePackRuleSource) (*rules.RulePack, error) {
	if ruleSource == nil {
		return nil, errors.New("runtime rule source is unavailable")
	}
	// 租户必须可验证存在；依赖缺失、查询错误或不存在一律拒绝下发，
	// 让引擎保持 last-good。只有已存在租户的空行业才规范化为 generic。
	industry := "generic"
	warnings := make([]string, 0, 2)
	if tenantSource == nil {
		return nil, errors.New("tenant source is unavailable")
	} else {
		t, err := tenantSource.GetByID(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("load tenant for runtime pack: %w", err)
		}
		if t == nil {
			return nil, errors.New("tenant for runtime pack was not found")
		}
		if normalizedIndustry := strings.TrimSpace(t.Industry); normalizedIndustry != "" {
			industry = normalizedIndustry
		}
	}
	dbRules, err := ruleSource.ListCompilableRulesByTenant(ctx, tenantID, industry)
	if err != nil {
		return nil, fmt.Errorf("list runtime rule candidates: %w", err)
	}
	if len(dbRules) > maxRulePackCandidates {
		return nil, errRulePackCandidateLimitExceeded
	}
	// 例外（误报豁免）随规则包一同下发。查询失败不致命：宁可不下发例外
	// （更严格——命中照常拦截），也不阻断整包，避免例外故障放大成全租户失保护。
	dbExcs, err := ruleSource.ListActiveContentAuditExceptionsByTenant(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrContentAuditExceptionLimitExceeded) {
			return nil, fmt.Errorf("active content audit exceptions exceed runtime pack limit: %w", err)
		}
		dbExcs = nil
		warnings = append(warnings, runtimeWarningExceptionsUnavailable)
	}
	pack := rules.Compile(tenantID, dbRules, dbExcs)
	pack.Warnings = warnings
	pack.Degraded = len(warnings) > 0
	pack.Version = rules.ContentVersion(pack)
	return &pack, nil
}

// applyRulePackFilePolicy fails closed on dependency/read/parse uncertainty.
// Returning an error makes the internal endpoint answer 503, so the engine
// keeps its last-good pack instead of replacing a customer policy with empty.
func applyRulePackFilePolicy(ctx context.Context, systemRepo SystemRepo, tenantID string, pack *rules.RulePack) error {
	if systemRepo == nil {
		return errors.New("content file policy source is unavailable")
	}
	setting, err := systemRepo.Get(ctx, contentFilePolicySettingKeyForTenant(tenantID))
	if err != nil {
		return fmt.Errorf("load content file policy: %w", err)
	}
	if setting == nil || strings.TrimSpace(setting.Value) == "" {
		return nil
	}
	policy, err := decodeAndNormalizeFilePolicy([]byte(setting.Value))
	if err != nil {
		return fmt.Errorf("parse content file policy: %w", err)
	}
	pack.FilePolicy = &policy
	return nil
}

func applyRulePackReplyPolicy(ctx context.Context, deps *Dependencies, tenantID string, pack *rules.RulePack) error {
	policy, err := loadSecurityReplyPolicyContext(ctx, deps, tenantID)
	if err != nil {
		return fmt.Errorf("load security reply policy: %w", err)
	}
	pack.ReplyPolicy = &rules.ReplyPolicy{
		SchemaVersion: policy.SchemaVersion,
		Enabled:       policy.Enabled,
		Templates:     policy.Templates,
	}
	return nil
}
