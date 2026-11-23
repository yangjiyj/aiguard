package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var projectRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

const driftValueMax = 200

// collectDrift 按开机链渲染 compose 配置，与运行中的容器逐服务比对镜像 ID 与环境变量。
// 失败时返回错误描述（写入快照 drift.error），不返回部分结果。
func (a *agent) collectDrift(ctx context.Context) ([]driftRow, string) {
	up := filepath.Join(a.deployDir, ".upgrade")
	if st, err := os.Stat(up); err != nil || !st.IsDir() {
		return nil, ".upgrade 目录不存在，无法按开机链渲染"
	}
	pdb, err := os.ReadFile(filepath.Join(up, "project-directory"))
	if err != nil {
		return nil, "读取 .upgrade/project-directory 失败"
	}
	projectDir := strings.TrimSpace(string(pdb))
	if projectDir == "" {
		return nil, ".upgrade/project-directory 为空"
	}
	cfb, err := os.ReadFile(filepath.Join(up, "compose-files"))
	if err != nil {
		return nil, "读取 .upgrade/compose-files 失败"
	}
	cs, err := listAllContainers(ctx)
	if err != nil {
		return nil, "docker ps 失败"
	}
	proj := a.inferProject(cs)

	args := []string{"./compose-wrapper.sh", "--project-name", proj, "--project-directory", projectDir,
		"--env-file", ".env", "-f", "docker-compose.offline.yml"}
	for _, l := range strings.Split(string(cfb), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		args = append(args, "-f", l)
	}
	args = append(args, "config", "--format", "json")
	out, err := runCmd(ctx, 60*time.Second, a.deployDir, "sh", args...)
	if err != nil {
		return nil, "开机链渲染失败: " + truncate(redactText(err.Error()), 300)
	}
	var cfg struct {
		Services map[string]struct {
			Image       string             `json:"image"`
			Environment map[string]*string `json:"environment"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		return nil, "开机链渲染输出无法解析"
	}

	byService := map[string]container{}
	for _, c := range cs {
		if c.Project != proj || c.Service == "" {
			continue
		}
		if old, ok := byService[c.Service]; !ok || (old.State != "running" && c.State == "running") {
			byService[c.Service] = c
		}
	}
	var ids []string
	for _, c := range byService {
		ids = append(ids, c.ID)
	}
	info, err := inspectContainers(ctx, ids)
	if err != nil {
		return nil, "docker inspect 失败"
	}

	rows := []driftRow{}
	for _, svc := range sortedKeys(cfg.Services) {
		spec := cfg.Services[svc]
		row := driftRow{Service: svc, EnvDiff: []envDiff{}}
		c, ok := byService[svc]
		if !ok {
			row.NotRunning = true
			rows = append(rows, row)
			continue
		}
		var ci inspectInfo
		found := false
		for id, i := range info {
			if id == c.ID || strings.HasPrefix(id, c.ID) {
				ci, found = i, true
				break
			}
		}
		if !found {
			row.NotRunning = true
			rows = append(rows, row)
			continue
		}
		row.ImageMatch = imageID(ctx, spec.Image) == ci.Image
		run := map[string]string{}
		for _, e := range ci.Config.Env {
			if i := strings.Index(e, "="); i >= 0 {
				run[e[:i]] = e[i+1:]
			}
		}
		for _, k := range sortedKeys(spec.Environment) {
			want := ""
			if spec.Environment[k] != nil {
				want = *spec.Environment[k]
			}
			if want == run[k] {
				continue
			}
			d := envDiff{Key: k, Sensitive: isSensitiveEnvKey(k)}
			if !d.Sensitive {
				d.Chain = truncate(redactText(want), driftValueMax)
				d.Running = truncate(redactText(run[k]), driftValueMax)
			}
			row.EnvDiff = append(row.EnvDiff, d)
		}
		rows = append(rows, row)
	}
	return rows, ""
}
