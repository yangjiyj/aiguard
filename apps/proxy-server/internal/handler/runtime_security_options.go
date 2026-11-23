package handler

// 2.9.22 任务 4.2、4.5：独立代理执行的“故障处理”设置与文件引用处置。
//
// 故障类键随网关签名投影下发（inspectionscope.GatewayReader 验签后暴露 RuntimeOption），
// 没下发时才用环境变量作初值；文件引用处置读租户文件策略，与网关共用 filereference 口径。

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/filereference"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

type runtimeOptionReader interface {
	RuntimeOption(key string) (string, bool)
}

// FileReferencePolicyReader 按租户读文件引用处置。
type FileReferencePolicyReader interface {
	Policy(ctx context.Context, tenantID string) filereference.Policy
}

// WithFileReferencePolicyReader 注入文件引用处置读取器；未注入时按缺省告警放行。
func (s *SecurityClient) WithFileReferencePolicyReader(reader FileReferencePolicyReader) *SecurityClient {
	s.fileReferencePolicy = reader
	return s
}

// NewDBFileReferencePolicyReaderFromPool 从 system_settings 读租户文件策略（30 秒缓存）。
func NewDBFileReferencePolicyReaderFromPool(db *pgxpool.Pool) FileReferencePolicyReader {
	if db == nil {
		return nil
	}
	return filereference.NewCachedReader(func(ctx context.Context, key string) (string, bool, error) {
		var value string
		err := db.QueryRow(ctx, `SELECT value FROM system_settings WHERE key = $1`, key).Scan(&value)
		if err == pgx.ErrNoRows {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		return value, true, nil
	}, 30*time.Second)
}

func (s *SecurityClient) runtimeOption(key string) (string, bool) {
	if s == nil {
		return "", false
	}
	if reader, ok := s.inspectionScope.(runtimeOptionReader); ok {
		return reader.RuntimeOption(key)
	}
	return "", false
}

// guardrailFailClosedSettingKey 是控制台“检测服务不可用”的开关（与网关同一个键）。
const guardrailFailClosedSettingKey = "guardrail_fail_closed_enabled"

// proxyDetectionEnvFallback：库里没有 guardrail_fail_closed_enabled 时，用 PROXY_DETECTION_FAIL_MODE 作初值。
type proxyDetectionEnvFallback struct{}

func (proxyDetectionEnvFallback) Enabled(context.Context) bool {
	return securityexit.ProxyDetectionPolicy().FailClosedOnDetectionFailure
}

// NewDBDetectionFailClosedSettingReader 从 system_settings 读 guardrail_fail_closed_enabled（10 秒缓存）；
// 库里没有该键或读取失败且从未读到时，回落 PROXY_DETECTION_FAIL_MODE。
//
// 为什么读库而不读网关签名投影（投影里也有这个键）：控制面生成投影时，库里没存该键一律下发
// false，分不出“没存”和“存了 false”；而代理要在没存时沿用 PROXY_DETECTION_FAIL_MODE 作初值
// （设计 D7），所以和执行模式、文件检测开关一样直接读库，用同一个带缓存、限时的读取器。
func NewDBDetectionFailClosedSettingReader(query querierFunc) FileDLPSettingReader {
	return newDBBooleanSettingReader(query, guardrailFailClosedSettingKey, proxyDetectionEnvFallback{})
}

func NewDBDetectionFailClosedSettingReaderFromPool(db *pgxpool.Pool) FileDLPSettingReader {
	if db == nil {
		return nil
	}
	return NewDBDetectionFailClosedSettingReader(func(ctx context.Context, sql string, args ...any) rowScanner {
		return db.QueryRow(ctx, sql, args...)
	})
}

// WithDetectionFailClosedSettingReader 注入“检测服务不可用”开关读取器（2.9.22 审查第 7 项）。
func (s *SecurityClient) WithDetectionFailClosedSettingReader(reader FileDLPSettingReader) *SecurityClient {
	s.detectionFailClosed = reader
	return s
}

// detectionPolicy：检测服务不可用读控制台 guardrail_fail_closed_enabled（库里没有时
// PROXY_DETECTION_FAIL_MODE 作初值）；检测排队满读控制台 security_capacity_fail_mode
// （没存时 SECURITY_CAPACITY_FAIL_CLOSED 作初值）。
func (s *SecurityClient) detectionPolicy() securityexit.Policy {
	policy := securityexit.ProxyDetectionPolicy()
	if s != nil && s.detectionFailClosed != nil {
		policy.FailClosedOnDetectionFailure = s.detectionFailClosed.Enabled(context.Background())
	}
	switch value, _ := s.runtimeOption("security_capacity_fail_mode"); value {
	case "closed":
		policy.FailClosedOnCapacity = true
	case "open":
		policy.FailClosedOnCapacity = false
	}
	return policy
}

// uploadInspectionFailureBlocks：附件送检失败是否拦截（控制台 upload_inspection_failure_action）。
func (s *SecurityClient) uploadInspectionFailureBlocks() bool {
	value, _ := s.runtimeOption("upload_inspection_failure_action")
	return value == "block"
}

// attachmentUploadFailure：附件字节没能送进引擎检测（对象化上传失败）时的处置。
// 只看 upload_inspection_failure_action，不看“检测服务不可用即拦”：缺省 forward_alert 放行并留
// 一条告警；选 block 时在防护模式下拦，观察留痕下只记录。与网关 /v1/files、门户上传同一口径。
func (s *SecurityClient) attachmentUploadFailure(ctx context.Context) (string, []map[string]interface{}, *FingerprintScanMeta) {
	policy := securityexit.Policy{FailClosedOnDetectionFailure: s.uploadInspectionFailureBlocks()}
	err := securityexit.NewInspectionFailure("file_content_object_unavailable", nil)
	action, _, meta := proxyInspectionFailure(s.securityAuditOnly(ctx), err, "file_content_object_unavailable", policy)
	meta.ClientGone = proxyClientGone(ctx, err)
	return action, []map[string]interface{}{{
		"type": "engine_runtime", "category": "file_content_object_unavailable",
		"counts_as_security_finding": false,
		"severity":                   "low", "rule_id": "file-content-object-unavailable",
		"action": action, "matched_text_preview": "文件检测对象不可用，尚未形成风险结论",
	}}, meta
}

// fileIDGateResult 是只带文件 id 的附件的处置结果。
type fileIDGateResult struct {
	blocked    bool
	clientGone bool
	// findings：阻断时是一条 block 命中；告警放行时是 alert 命中，由调用方并入检测结果。
	findings []map[string]interface{}
	// outcomes 是各引用的处置；告警放行、还没核对例外的由 resolveReferenceAlerts 在拿到引擎结果后核对。
	outcomes           []*filereference.Outcome
	tenantID, provider string
}
