// Package diagnostics 实现运维诊断机器人的只读排查能力。
package diagnostics

import (
	"encoding/json"
	"time"
)

type Level string // 结论级别

const (
	LevelConfirmed Level = "confirmed" // 确定
	LevelSuspected Level = "suspected" // 疑似
	LevelUnknown   Level = "unknown"   // 无法判断
)

type Tier string

const (
	TierL1 Tier = "L1"
	TierL2 Tier = "L2"
	TierL3 Tier = "L3"
)

type Severity string

const (
	SevOK    Severity = "ok"
	SevWarn  Severity = "warn"
	SevError Severity = "error"
)

// Scope 决定数据可见范围；员工 Scope.UserID 非空，所有请求类工具强制按此过滤。
type Scope struct {
	TenantID string
	UserID   string // 员工必填；管理员为空
	IsAdmin  bool
}

type Evidence struct {
	Kind    string `json:"kind"`          // request | log | config | change | host
	Ref     string `json:"ref"`           // 请求编号 / 服务名 / 配置 ID
	Summary string `json:"summary"`       // 中文一句话
	Raw     string `json:"raw,omitempty"` // 上游原文等（已脱敏，≤2KB）
}

type Finding struct {
	CheckID  string     `json:"check_id"`
	Severity Severity   `json:"severity"`
	Level    Level      `json:"level"`
	Title    string     `json:"title"`  // 结论一句话（中文）
	Impact   string     `json:"impact"` // 影响面
	Advice   []Advice   `json:"advice"`
	Excluded []string   `json:"excluded"` // 已排除及依据
	Evidence []Evidence `json:"evidence"`
}

type Advice struct {
	Text string `json:"text"`
	Link string `json:"link,omitempty"` // 控制台内路由，如 /model-operations?model=xxx
}

type Step struct {
	Tool    string          `json:"tool"`
	Args    json.RawMessage `json:"args"`
	Summary string          `json:"summary"` // 中文进度文案
	Output  json.RawMessage `json:"-"`       // 不下发前端，只用于事实校验与诊断包
	Err     string          `json:"error,omitempty"`
}

type Report struct {
	ID         string    `json:"id"`
	Tier       Tier      `json:"tier"`
	Degraded   string    `json:"degraded,omitempty"` // 降档/降级原因（中文）
	Findings   []Finding `json:"findings"`
	OKCount    int       `json:"ok_count"` // 体检中正常项数
	Steps      []Step    `json:"steps"`
	Model      string    `json:"model,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// Input 是一次诊断的输入。
type Input struct {
	Kind    string `json:"kind"`         // request | user | model | provider | health | question
	Text    string `json:"text"`         // 原始输入（粘贴报错/问题）
	Ref     string `json:"ref"`          // 解析出的编号/用户/模型
	WindowH int    `json:"window_hours"` // 默认 1，最大 24
}
