package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// 宿主机类检查：只读 host.Snapshot。快照缺失或过期时只产生 agent_missing，其余检查跳过。

func t6HostUsable(h *HostView) bool {
	return h != nil && h.Err == nil && h.Snapshot != nil && h.Snapshot.Fresh
}

func t6CheckAgentMissing(_ context.Context, _ *t6Env, _ Querier, s Scope, _ Input, h *HostView) (t6Result, error) {
	if t6HostUsable(h) {
		return t6Result{Data: map[string]any{"fresh": true, "agent_version": h.Snapshot.AgentVersion, "at": h.Snapshot.At}}, nil
	}
	reason := "未找到宿主机快照"
	data := map[string]any{"fresh": false}
	switch {
	case h == nil:
	case h.Err != nil && !errors.Is(h.Err, ErrAgentMissing):
		reason = "读取快照失败：" + h.Err.Error()
		data["error"] = h.Err.Error()
	case h.Err != nil:
		data["error"] = "agent_missing"
	case h.Snapshot != nil:
		reason = "快照超过 3 分钟未更新"
		data["at"] = h.Snapshot.At
		data["age_seconds"] = int64(h.Snapshot.Age / time.Second)
	}
	return t6Result{Data: data, Findings: []Finding{t6Find("agent_missing", SevWarn, LevelUnknown,
		"未安装或未运行宿主机采集器",
		"无法检查容器、磁盘、证书和配置漂移，其余项目不受影响",
		[]Advice{{Text: "在宿主机上安装或启动诊断采集器，安装脚本见部署包中的采集器目录"}},
		nil, []Evidence{{Kind: "host", Ref: "diag-agent", Summary: reason}})}}, nil
}

func t6HostGate(h *HostView) (*HostSnapshot, error) {
	if !t6HostUsable(h) {
		return nil, t6ErrSkip
	}
	return h.Snapshot, nil
}

func t6CheckHostContainer(_ context.Context, _ *t6Env, _ Querier, s Scope, _ Input, h *HostView) (t6Result, error) {
	snap, err := t6HostGate(h)
	if err != nil {
		return t6Result{}, err
	}
	now := time.Now()
	if t, e := time.Parse(time.RFC3339, snap.At); e == nil {
		now = t
	}
	var fs []Finding
	for _, c := range snap.Containers {
		name := c.Service
		if name == "" {
			name = c.Name
		}
		var problems []string
		sev := SevError
		if c.State != "running" {
			problems = append(problems, "容器状态为"+t6StateLabel(c.State))
		}
		if c.Health == "unhealthy" {
			problems = append(problems, "健康检查未通过")
		}
		if c.RestartCount >= 3 {
			if st, e := time.Parse(time.RFC3339Nano, c.StartedAt); e == nil && now.Sub(st) <= time.Hour {
				problems = append(problems, fmt.Sprintf("1 小时内已重启 %d 次", c.RestartCount))
				if c.State == "running" && c.Health != "unhealthy" {
					sev = SevWarn
				}
			}
		}
		if len(problems) == 0 {
			continue
		}
		fs = append(fs, t6Find("host_container", sev, LevelConfirmed,
			fmt.Sprintf("服务「%s」运行异常", name),
			strings.Join(problems, "，"),
			[]Advice{t6Adv(s, "在服务健康页查看该服务日志，必要时重启服务", "/system/service-health")},
			nil, []Evidence{{Kind: "host", Ref: name, Summary: strings.Join(problems, "，")}}))
	}
	return t6Result{Findings: fs, Data: map[string]any{"containers": snap.Containers}}, nil
}

func t6CheckHostDrift(_ context.Context, _ *t6Env, _ Querier, s Scope, _ Input, h *HostView) (t6Result, error) {
	snap, err := t6HostGate(h)
	if err != nil {
		return t6Result{}, err
	}
	data := map[string]any{"drift": snap.Drift, "drift_error": snap.DriftError}
	if snap.DriftError != "" {
		return t6Result{Data: data, Findings: []Finding{t6Find("host_drift", SevWarn, LevelUnknown,
			"无法比对运行配置与开机链配置",
			"配置漂移检查未能完成，需要人工核对",
			[]Advice{{Text: "在宿主机上检查开机链部署目录是否完整，然后重新诊断"}},
			nil, []Evidence{{Kind: "host", Ref: "drift", Summary: "漂移比对失败", Raw: t6Raw(snap.DriftError)}})}}, nil
	}
	var fs []Finding
	for _, d := range snap.Drift {
		var diffs []string
		var ev []Evidence
		if d.NotRunning {
			continue
		}
		if !d.ImageMatch {
			diffs = append(diffs, "镜像与开机链不一致")
			ev = append(ev, Evidence{Kind: "host", Ref: d.Service, Summary: "运行镜像与开机链配置不一致"})
		}
		for _, e := range d.EnvDiff {
			if e.Sensitive {
				diffs = append(diffs, "一项敏感配置不一致")
				ev = append(ev, Evidence{Kind: "host", Ref: d.Service, Summary: "敏感环境变量「" + e.Key + "」与开机链不一致"})
				continue
			}
			diffs = append(diffs, "环境变量「"+e.Key+"」不一致")
			ev = append(ev, Evidence{Kind: "host", Ref: d.Service, Summary: "环境变量「" + e.Key + "」与开机链不一致",
				Raw: t6Raw("开机链=" + e.Chain + " 运行=" + e.Running)})
		}
		if len(diffs) == 0 {
			continue
		}
		fs = append(fs, t6Find("host_drift", SevError, LevelConfirmed,
			fmt.Sprintf("服务「%s」的运行配置与开机链不一致", d.Service),
			"服务重启或重建后配置会回退，可能导致登录、转发等行为突然变化："+strings.Join(diffs, "，"),
			[]Advice{{Text: "按开机链重建该服务使配置一致，不要单独改运行中的容器"}},
			nil, ev))
	}
	return t6Result{Findings: fs, Data: data}, nil
}

func t6CheckHostDisk(_ context.Context, _ *t6Env, _ Querier, s Scope, _ Input, h *HostView) (t6Result, error) {
	snap, err := t6HostGate(h)
	if err != nil {
		return t6Result{}, err
	}
	var fs []Finding
	for _, d := range snap.Disk {
		if d.UsedPct < 80 {
			continue
		}
		sev := SevWarn
		if d.UsedPct >= 90 {
			sev = SevError
		}
		fs = append(fs, t6Find("host_disk", sev, LevelConfirmed,
			fmt.Sprintf("磁盘「%s」使用率过高", d.Mount),
			fmt.Sprintf("已使用 %d%%，写满后数据库与日志将无法写入", d.UsedPct),
			[]Advice{{Text: "清理该磁盘上的旧日志、镜像和备份，或扩容"}},
			nil, []Evidence{{Kind: "host", Ref: d.Mount, Summary: fmt.Sprintf("使用率 %d%%", d.UsedPct)}}))
	}
	return t6Result{Findings: fs, Data: map[string]any{"disk": snap.Disk}}, nil
}

func t6CheckHostCert(_ context.Context, _ *t6Env, _ Querier, s Scope, _ Input, h *HostView) (t6Result, error) {
	snap, err := t6HostGate(h)
	if err != nil {
		return t6Result{}, err
	}
	var fs []Finding
	certs := append([]HostCert(nil), snap.Certs...)
	sort.SliceStable(certs, func(i, j int) bool { return certs[i].DaysLeft < certs[j].DaysLeft })
	for _, c := range certs {
		if c.DaysLeft > 15 {
			continue
		}
		if c.DaysLeft <= 0 {
			fs = append(fs, t6Find("host_cert", SevError, LevelConfirmed,
				fmt.Sprintf("证书「%s」已过期", c.Path), "使用该证书的加密访问会被浏览器和客户端拒绝",
				[]Advice{{Text: "更换新证书并重载对应服务"}}, nil,
				[]Evidence{{Kind: "host", Ref: c.Path, Summary: "证书已过期"}}))
			continue
		}
		fs = append(fs, t6Find("host_cert", SevWarn, LevelConfirmed,
			fmt.Sprintf("证书「%s」即将过期", c.Path), fmt.Sprintf("剩余 %d 天，过期后加密访问将失败", c.DaysLeft),
			[]Advice{{Text: "提前更换新证书并重载对应服务"}}, nil,
			[]Evidence{{Kind: "host", Ref: c.Path, Summary: fmt.Sprintf("剩余 %d 天", c.DaysLeft)}}))
	}
	return t6Result{Findings: fs, Data: map[string]any{"certs": snap.Certs}}, nil
}

func t6StateLabel(st string) string {
	switch st {
	case "exited":
		return "已退出"
	case "restarting":
		return "反复重启中"
	case "paused":
		return "已暂停"
	case "dead":
		return "已终止"
	case "created":
		return "已创建但未启动"
	case "":
		return "未知"
	}
	return "异常（" + st + "）"
}
