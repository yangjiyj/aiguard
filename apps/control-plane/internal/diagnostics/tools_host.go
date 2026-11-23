package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// 宿主机工具：经采集器读取容器、日志、配置漂移。全部仅管理员可用。

// HostTools 返回宿主机类只读工具。
func HostTools(c *AgentClient) []Tool {
	return []Tool{t12Snapshot{c}, t12ContainerLogs{c}, t12Drift{c}}
}

func t12Marshal(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	return json.RawMessage(b), err
}

// t12AgentErr 把采集器客户端错误转成给模型看的中文。
func t12AgentErr(err error) error {
	switch {
	case errors.Is(err, ErrAgentMissing):
		return errors.New("宿主机采集器未安装，无法读取宿主机信息")
	case errors.Is(err, ErrAgentNoKey):
		return errors.New("未配置采集器签名密钥，无法向宿主机采集器下发任务")
	case errors.Is(err, ErrAgentTimeout):
		return errors.New("宿主机采集器响应超时（15 秒），采集器可能未运行")
	}
	return err
}

type t12Snapshot struct{ c *AgentClient }

func (t12Snapshot) Name() string { return "host_snapshot" }
func (t12Snapshot) Description() string {
	return "读取宿主机采集器最近一次快照（每分钟更新）：各容器状态、健康、重启次数、镜像，磁盘用量与证书剩余天数。fresh=false 表示快照已超过 3 分钟未更新，数据可能过期。配置漂移请用 host_drift。无参数。"
}
func (t12Snapshot) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)
}
func (t12Snapshot) AdminOnly() bool { return true }
func (t t12Snapshot) Run(_ context.Context, _ Querier, _ Scope, _ json.RawMessage) (json.RawMessage, error) {
	s, err := t.c.Snapshot()
	if err != nil {
		return nil, t12AgentErr(err)
	}
	return t12Marshal(map[string]any{
		"fresh": s.Fresh, "age_seconds": int(s.Age.Seconds()), "at": s.At,
		"agent_version": s.AgentVersion, "containers": s.Containers,
		"disk": s.Disk, "certs": s.Certs, "errors": s.Errors,
	})
}

type t12Drift struct{ c *AgentClient }

func (t12Drift) Name() string { return "host_drift" }
func (t12Drift) Description() string {
	return "读取宿主机采集器最近一次配置漂移比对结果：按开机链渲染的配置与运行中容器逐服务对比镜像与环境变量。敏感变量只标记 sensitive=true 不含值；not_running=true 表示该服务当前没有运行容器；drift_error 非空表示比对本身失败。无参数。"
}
func (t12Drift) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)
}
func (t12Drift) AdminOnly() bool { return true }
func (t t12Drift) Run(_ context.Context, _ Querier, _ Scope, _ json.RawMessage) (json.RawMessage, error) {
	s, err := t.c.Snapshot()
	if err != nil {
		return nil, t12AgentErr(err)
	}
	drift := s.Drift
	if drift == nil {
		drift = []HostDrift{}
	}
	return t12Marshal(map[string]any{
		"fresh": s.Fresh, "age_seconds": int(s.Age.Seconds()), "at": s.At,
		"drift": drift, "drift_error": s.DriftError,
	})
}

type t12ContainerLogs struct{ c *AgentClient }

func (t12ContainerLogs) Name() string { return "host_container_logs" }
func (t12ContainerLogs) Description() string {
	return "经宿主机采集器读取某个服务最近的容器日志（已脱敏，最多 64KB，保留尾部）。参数：service 服务名（必填，如 gateway-core）；grep 过滤关键字（可选，只允许字母数字和 _.:-，如请求编号）；since_minutes 回溯分钟数（可选，1-60，默认 10）。"
}
func (t12ContainerLogs) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"service":{"type":"string","description":"compose 服务名"},"grep":{"type":"string","description":"包含该关键字的行才返回，只允许 [A-Za-z0-9_.:-]"},"since_minutes":{"type":"integer","minimum":1,"maximum":60}},"required":["service"],"additionalProperties":false}`)
}
func (t12ContainerLogs) AdminOnly() bool { return true }
func (t t12ContainerLogs) Run(ctx context.Context, _ Querier, _ Scope, args json.RawMessage) (json.RawMessage, error) {
	var in struct {
		Service      string `json:"service"`
		Grep         string `json:"grep"`
		SinceMinutes *int   `json:"since_minutes"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return nil, fmt.Errorf("参数不是合法 JSON: %v", err)
	}
	if strings.TrimSpace(in.Service) == "" {
		return nil, errors.New("缺少参数 service")
	}
	params := map[string]any{"service": in.Service}
	if in.Grep != "" {
		params["grep"] = in.Grep
	}
	if in.SinceMinutes != nil {
		if *in.SinceMinutes < 1 || *in.SinceMinutes > 60 {
			return nil, errors.New("since_minutes 范围为 1-60")
		}
		params["since_minutes"] = *in.SinceMinutes
	}
	res, err := t.c.Do(ctx, "container_logs", params)
	if err != nil {
		return nil, t12AgentErr(err)
	}
	if !res.OK {
		return nil, fmt.Errorf("采集器拒绝或执行失败: %s", res.Error)
	}
	// 采集器已脱敏；控制面再兜底一次（Registry.Call 还会对整体输出再做一次）。
	return t12Marshal(map[string]any{
		"service": in.Service, "output": Redact(res.Output), "truncated": res.Truncated,
	})
}
