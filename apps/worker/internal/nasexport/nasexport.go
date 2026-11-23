// Package nasexport 把文件内容 DLP 的脱敏事件导出到管理员固定配置的挂载 NAS 目录。
//
// 设计 §13 最小可交付（第一期只实现挂载目录导出，不铺开 S3/SIEM/Syslog/Webhook）：
//   - 默认关（由 worker 配置 NASExportEnabled 控制，接线时默认 false）；
//   - 只导出脱敏事件，绝不导出原文件 / 完整 PII / 完整密钥；
//   - 稳定 event_id 作文件名 → 幂等写入（重复投递不产生重复文件）；
//   - 至少一次投递 + 有界重试由 outbox 上层保证（NAS 不可用 → 返回 error → outbox 退避重试）；
//   - 导出目录必须是管理员固定配置的绝对路径，事件请求不得携带任意路径；
//   - 路径穿越防护：event_id 只允许 [A-Za-z0-9._-]，否则拒绝；
//   - NAS 不可用不阻塞 DLP 判定（判定已在 security-engine 完成，导出是异步留痕）。
//
// 安全红线：WriteEvent 只写 ExportEvent 的白名单字段；任何 RawEvidence/完整正文字段
// 一律不落盘（结构体里不设该字段，从源头杜绝）。
package nasexport

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// eventIDRe 只允许安全的文件名字符，阻断路径穿越与特殊字符。
var eventIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ExportEvent 是可导出到 NAS 的脱敏事件。只含白名单字段——
// 故意不设 RawContent / RawEvidence / 完整 PII 等字段，从结构体源头杜绝泄露。
type ExportEvent struct {
	EventID     string         `json:"event_id"`           // 稳定事件ID（幂等键，兼做文件名）
	TenantLabel string         `json:"tenant_label,omitempty"` // 租户业务名（非 tenant_id UUID）
	Subject     string         `json:"subject,omitempty"`  // 用户/部门/应用（业务标识）
	EntryPoint  string         `json:"entry_point,omitempty"` // API网关/正向代理/企业门户
	TargetAI    string         `json:"target_ai,omitempty"`   // 目标AI/供应商/模型
	FileName    string         `json:"file_name,omitempty"`   // 原文件名（元数据，允许）
	FileSize    int64          `json:"file_size"`
	RealType    string         `json:"real_type,omitempty"`   // 真实类型（魔术字节判定）
	SHA256      string         `json:"sha256,omitempty"`      // 只留 sha16 截断更佳，这里接受全 sha256（不可逆）
	HitTypes    []string       `json:"hit_types,omitempty"`   // 命中类型
	HitCounts   map[string]int `json:"hit_counts,omitempty"`  // 各类型命中数量
	SampleHits  []string       `json:"sample_hits,omitempty"` // 少量脱敏样例（调用方必须已脱敏）
	Action      string         `json:"action"`                // allow/audit/block
	PolicyVer   string         `json:"policy_version,omitempty"`
	EngineBuild string         `json:"engine_build,omitempty"`
	LatencyMs   int64          `json:"latency_ms"`
	UpstreamGot bool           `json:"upstream_got"`          // 是否确认上游收到（阻断时应为 false）
	ExportedAt  string         `json:"exported_at,omitempty"` // ISO 时间（由调用方注入，避免包内时间依赖）
}

// WriteEvent 把单个脱敏事件写到 rootDir/event_id.json。幂等：同 event_id 重复写覆盖不报错。
//
// rootDir 必须是绝对路径（管理员固定配置）；事件本身不携带路径。
// event_id 必须匹配 [A-Za-z0-9._-]{1,128}，否则拒绝（路径穿越防护）。
// NAS 不可用（目录不可创建/不可写）返回 error，由上层 outbox 有限重试。
func WriteEvent(rootDir string, ev ExportEvent) error {
	if !filepath.IsAbs(rootDir) {
		return errors.New("nasexport: root dir must be an absolute path configured by admin")
	}
	rootDir = filepath.Clean(rootDir)
	if !eventIDRe.MatchString(ev.EventID) {
		return fmt.Errorf("nasexport: event_id %q is missing or contains disallowed characters", ev.EventID)
	}
	// 落盘前对脱敏样例再兜底清洗一次（防止调用方漏脱敏）
	ev.SampleHits = sanitizeSamples(ev.SampleHits)
	if err := os.MkdirAll(rootDir, 0o750); err != nil {
		return fmt.Errorf("nasexport: ensure root dir: %w", err)
	}
	// 文件名直接用 event_id（已校验字符集）+ .json；filepath.Join + Clean 后再次确认仍在 rootDir 内
	target := filepath.Join(rootDir, ev.EventID+".json")
	target = filepath.Clean(target)
	if !isWithin(rootDir, target) {
		return fmt.Errorf("nasexport: resolved path escapes root dir")
	}
	payload, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return fmt.Errorf("nasexport: marshal event: %w", err)
	}
	// 幂等：写临时文件再 rename，崩溃安全；已存在则覆盖
	tmp, err := os.CreateTemp(rootDir, ".nasexport-*.tmp")
	if err != nil {
		return fmt.Errorf("nasexport: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 成功后 Remove 无效；失败则清理临时文件
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return fmt.Errorf("nasexport: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("nasexport: close temp: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("nasexport: rename to final: %w", err)
	}
	if err := os.Chmod(target, 0o640); err != nil {
		// chmod 失败不致命（文件已就位），仅记录
		_ = err
	}
	return nil
}

// isWithin 确认 target 在 root 下（双重防护，配合 event_id 字符集校验）。
func isWithin(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return false
	}
	return true
}

// 手机号 / 身份证 / 长 digit / AWS key / openai key 的兜底掩码（防止调用方漏脱敏）。
var sampleRedactPatterns = []string{
	`1[3-9]\d{9}`,
	`\d{17}[\dXx]`,
	`\d{16,19}`,
	`AKIA[0-9A-Z]{16}`,
	`sk-[A-Za-z0-9]{20,}`,
}

// sanitizeSamples 对脱敏样例做兜底掩码（保留前3位+***）。仅作用在 SampleHits，
// 不触碰其它字段（结构体本来就没有完整正文/证据字段）。
func sanitizeSamples(samples []string) []string {
	if len(samples) == 0 {
		return samples
	}
	out := make([]string, 0, len(samples))
	for _, s := range samples {
		for _, pat := range sampleRedactPatterns {
			re := regexp.MustCompile(pat)
			s = re.ReplaceAllStringFunc(s, func(m string) string {
				if len(m) <= 3 {
					return "***"
				}
				return m[:3] + "***"
			})
		}
		out = append(out, s)
	}
	return out
}
