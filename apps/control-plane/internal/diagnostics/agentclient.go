package diagnostics

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/diagsign"
)

const (
	agentDefaultDir     = "/var/lib/jjdguard/diag"
	agentSnapshotMaxAge = 3 * time.Minute
	agentDoTimeout      = 15 * time.Second
	agentPollInterval   = 500 * time.Millisecond
)

var (
	ErrAgentMissing = errors.New("宿主机采集器未安装或目录不可用")
	ErrAgentNoKey   = errors.New("未配置采集器签名密钥（DIAG_AGENT_HMAC_KEY）")
	ErrAgentTimeout = errors.New("等待采集器响应超时")
)

// AgentClient 通过共享目录与宿主机采集器通信：inbox 写签名任务，outbox 读结果，snapshot 读定时快照。
type AgentClient struct {
	Dir string
	Key []byte
	Now func() time.Time

	// 仅测试调整；零值使用默认。
	pollEvery time.Duration
	timeout   time.Duration
}

// NewAgentClientFromEnv 读取 DIAG_AGENT_DIR 与 DIAG_AGENT_HMAC_KEY；密钥为空时 Key=nil。
func NewAgentClientFromEnv() *AgentClient {
	dir := os.Getenv("DIAG_AGENT_DIR")
	if dir == "" {
		dir = agentDefaultDir
	}
	var key []byte
	if k := os.Getenv("DIAG_AGENT_HMAC_KEY"); k != "" {
		key = []byte(k)
	}
	return &AgentClient{Dir: dir, Key: key, Now: time.Now}
}

func (c *AgentClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// HostDriftEnv 是单个环境变量的漂移项；敏感值只给 Sensitive=true，不带值。
type HostDriftEnv struct {
	Key       string `json:"key"`
	Sensitive bool   `json:"sensitive"`
	Chain     string `json:"chain,omitempty"`
	Running   string `json:"running,omitempty"`
}

type HostDrift struct {
	Service    string         `json:"service"`
	ImageMatch bool           `json:"image_match"`
	NotRunning bool           `json:"not_running,omitempty"`
	EnvDiff    []HostDriftEnv `json:"env_diff"`
}

type HostContainer struct {
	Name         string `json:"name"`
	Service      string `json:"service"`
	State        string `json:"state"`
	Health       string `json:"health"`
	RestartCount int    `json:"restart_count"`
	Image        string `json:"image"`
	ImageID      string `json:"image_id"`
	StartedAt    string `json:"started_at"`
}

type HostDisk struct {
	Mount      string `json:"mount"`
	UsedPct    int    `json:"used_pct"`
	AvailBytes uint64 `json:"avail_bytes"`
}

type HostCert struct {
	Path     string `json:"path"`
	NotAfter string `json:"not_after"`
	DaysLeft int    `json:"days_left"`
}

// HostSnapshot 与 diag-agent 的 snapshot/latest.json 一一对应。
// 采集器的 drift 成功时是数组，失败时是 {"error":"..."}；后者落在 DriftError。
type HostSnapshot struct {
	At           string          `json:"at"`
	AgentVersion string          `json:"agent_version"`
	Containers   []HostContainer `json:"containers"`
	Drift        []HostDrift     `json:"drift"`
	DriftError   string          `json:"drift_error,omitempty"`
	Disk         []HostDisk      `json:"disk"`
	Certs        []HostCert      `json:"certs"`
	Errors       []string        `json:"errors"`

	Fresh bool          `json:"fresh"`
	Age   time.Duration `json:"-"`
}

// UnmarshalJSON 兼容 drift 的数组 / {"error":...} 两种形态。
func (s *HostSnapshot) UnmarshalJSON(b []byte) error {
	type plain HostSnapshot
	aux := struct {
		*plain
		Drift json.RawMessage `json:"drift"`
	}{plain: (*plain)(s)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	s.Drift, s.DriftError = nil, ""
	raw := aux.Drift
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	switch raw[0] {
	case '[':
		return json.Unmarshal(raw, &s.Drift)
	case '{':
		var e struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		s.DriftError = e.Error
		if s.DriftError == "" {
			s.DriftError = "未知错误"
		}
	}
	return nil
}

// Snapshot 读取最新快照；文件不存在返回 ErrAgentMissing；超过 3 分钟未更新时 Fresh=false。
func (c *AgentClient) Snapshot() (*HostSnapshot, error) {
	b, err := os.ReadFile(filepath.Join(c.Dir, "snapshot", "latest.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrAgentMissing
		}
		return nil, err
	}
	var s HostSnapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, errors.New("采集器快照无法解析: " + err.Error())
	}
	if at, err := time.Parse(time.RFC3339, s.At); err == nil {
		s.Age = c.now().Sub(at)
		s.Fresh = s.Age >= -diagsign.MaxFutureSkew && s.Age <= agentSnapshotMaxAge
	}
	return &s, nil
}

func agentTaskID() (string, error) {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return "", err
	}
	return "t_" + hex.EncodeToString(r[:]), nil
}

// Do 签名并下发任务，轮询 outbox 取结果。读到后尽力删除 outbox 文件（只读挂载时会失败，忽略）。
func (c *AgentClient) Do(ctx context.Context, action string, params map[string]any) (diagsign.Result, error) {
	if len(c.Key) == 0 {
		return diagsign.Result{}, ErrAgentNoKey
	}
	inbox := filepath.Join(c.Dir, "inbox")
	if st, err := os.Stat(inbox); err != nil || !st.IsDir() {
		return diagsign.Result{}, ErrAgentMissing
	}
	if err := ctx.Err(); err != nil {
		return diagsign.Result{}, err
	}
	id, err := agentTaskID()
	if err != nil {
		return diagsign.Result{}, err
	}
	if params == nil {
		params = map[string]any{}
	}
	issued := c.now().UTC().Format(time.RFC3339)
	task := diagsign.Task{ID: id, Action: action, Params: params, IssuedAt: issued,
		Sig: diagsign.Sign(c.Key, id, action, issued, params)}
	body, err := json.Marshal(task)
	if err != nil {
		return diagsign.Result{}, err
	}
	taskPath := filepath.Join(inbox, id+".json")
	tmp := filepath.Join(inbox, "."+id+".tmp")
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return diagsign.Result{}, err
	}
	if err := os.Rename(tmp, taskPath); err != nil {
		_ = os.Remove(tmp)
		return diagsign.Result{}, err
	}

	timeout, every := c.timeout, c.pollEvery
	if timeout <= 0 {
		timeout = agentDoTimeout
	}
	if every <= 0 {
		every = agentPollInterval
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(every)
	defer tick.Stop()
	outPath := filepath.Join(c.Dir, "outbox", id+".json")
	for {
		if b, err := os.ReadFile(outPath); err == nil {
			var res diagsign.Result
			if json.Unmarshal(b, &res) == nil && res.ID == id {
				_ = os.Remove(outPath)
				return res, nil
			}
		}
		select {
		case <-ctx.Done():
			_ = os.Remove(taskPath)
			return diagsign.Result{}, ctx.Err()
		case <-deadline.C:
			_ = os.Remove(taskPath)
			return diagsign.Result{}, ErrAgentTimeout
		case <-tick.C:
		}
	}
}
