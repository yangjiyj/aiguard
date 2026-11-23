package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// docker 只通过 exec.Command 的参数数组调用，从不经过 shell。
// 只用到 ps / logs / inspect（含 image inspect）。

const maxCaptureBytes = 16 << 20

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.buf.Len() < l.max {
		room := l.max - l.buf.Len()
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

// runCmd 执行外部命令，返回 stdout。stderr 只在失败时作为错误信息的一部分。
func runCmd(ctx context.Context, timeout time.Duration, dir, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	out := &limitedBuffer{max: maxCaptureBytes}
	errb := &limitedBuffer{max: 4096}
	cmd.Stdout = out
	cmd.Stderr = errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return out.buf.Bytes(), fmt.Errorf("timeout")
	}
	if err != nil {
		return out.buf.Bytes(), fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.buf.String()))
	}
	return out.buf.Bytes(), nil
}

type container struct {
	ID         string
	Name       string
	Service    string
	Project    string
	WorkingDir string
	State      string
	Image      string
}

func parseLabels(s string) map[string]string {
	m := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		if i := strings.Index(kv, "="); i > 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

// listAllContainers 列出所有容器（含已停止），解析 compose 标签。
func listAllContainers(ctx context.Context) ([]container, error) {
	out, err := runCmd(ctx, 15*time.Second, "", "docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}")
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	var res []container
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var raw struct {
			ID     string `json:"ID"`
			Names  string `json:"Names"`
			State  string `json:"State"`
			Image  string `json:"Image"`
			Labels string `json:"Labels"`
		}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		lb := parseLabels(raw.Labels)
		res = append(res, container{
			ID:         raw.ID,
			Name:       strings.Split(raw.Names, ",")[0],
			Service:    lb["com.docker.compose.service"],
			Project:    lb["com.docker.compose.project"],
			WorkingDir: lb["com.docker.compose.project.working_dir"],
			State:      raw.State,
			Image:      raw.Image,
		})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res, nil
}

type inspectInfo struct {
	ID           string `json:"Id"`
	Image        string `json:"Image"`
	Name         string `json:"Name"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Status    string `json:"Status"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image string   `json:"Image"`
		Env   []string `json:"Env"`
	} `json:"Config"`
}

func (i inspectInfo) health() string {
	if i.State.Health == nil {
		return ""
	}
	return i.State.Health.Status
}

// inspectContainers 返回 id -> 详情。docker 在部分容器缺失时仍会输出其余部分，所以先解析再看错误。
func inspectContainers(ctx context.Context, ids []string) (map[string]inspectInfo, error) {
	res := map[string]inspectInfo{}
	if len(ids) == 0 {
		return res, nil
	}
	args := append([]string{"inspect"}, ids...)
	out, err := runCmd(ctx, 20*time.Second, "", "docker", args...)
	var arr []inspectInfo
	if jerr := json.Unmarshal(out, &arr); jerr != nil {
		if err != nil {
			return nil, fmt.Errorf("docker inspect: %w", err)
		}
		return nil, fmt.Errorf("docker inspect: 输出无法解析")
	}
	for _, i := range arr {
		res[i.ID] = i
	}
	return res, nil
}

// imageID 返回镜像引用对应的镜像 ID；不存在时返回 "missing:<ref>"。
func imageID(ctx context.Context, ref string) string {
	if ref == "" || strings.HasPrefix(ref, "-") {
		return "missing:" + ref
	}
	out, err := runCmd(ctx, 10*time.Second, "", "docker", "image", "inspect", "--format", "{{.Id}}", ref)
	if err != nil {
		return "missing:" + ref
	}
	return strings.TrimSpace(string(out))
}
