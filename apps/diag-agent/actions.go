package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/packages/shared-go/diagsign"
)

// actionError 携带给控制面的错误码（固定枚举，不含敏感信息）。
type actionError struct {
	Code string
	Msg  string
}

func (e *actionError) Error() string { return e.Code + ": " + e.Msg }

func aerr(code, format string, a ...any) *actionError {
	return &actionError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

var (
	grepRe    = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	serviceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
	taskIDRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

const (
	logsTimeout         = 10 * time.Second
	defaultSinceMinutes = 10
)

// allowedParams 每个动作允许的参数名；出现其它名字一律拒绝。
var allowedParams = map[string]map[string]bool{
	"container_logs":    {"service": true, "grep": true, "since_minutes": true},
	"container_inspect": {"service": true},
	"drift_now":         {},
	"disk":              {},
	"certs":             {},
	"ping":              {},
}

// checkParams 严格校验参数，返回规范化后的值。
type checkedParams struct {
	Service string
	Grep    string
	Since   int
}

func checkParams(action string, params map[string]any) (checkedParams, *actionError) {
	var cp checkedParams
	allowed, ok := allowedParams[action]
	if !ok {
		return cp, aerr("unknown_action", "动作不在白名单")
	}
	for k := range params {
		if !allowed[k] {
			return cp, aerr("bad_params", "不允许的参数 %q", truncate(k, 32))
		}
	}
	if allowed["service"] {
		v, ok := params["service"]
		if !ok {
			return cp, aerr("bad_params", "缺少 service")
		}
		s, ok := v.(string)
		if !ok || !serviceRe.MatchString(s) || strings.Contains(s, "..") {
			return cp, aerr("bad_params", "service 格式不合法")
		}
		cp.Service = s
	}
	if allowed["grep"] {
		if v, ok := params["grep"]; ok {
			s, ok := v.(string)
			if !ok || !grepRe.MatchString(s) {
				return cp, aerr("bad_params", "grep 只允许 [A-Za-z0-9_.:-]{1,128}")
			}
			cp.Grep = s
		}
	}
	if allowed["since_minutes"] {
		cp.Since = defaultSinceMinutes
		if v, ok := params["since_minutes"]; ok {
			f, ok := v.(float64)
			if !ok || f != float64(int(f)) || f < 1 || f > 60 {
				return cp, aerr("bad_params", "since_minutes 范围 1-60 的整数")
			}
			cp.Since = int(f)
		}
	}
	return cp, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// capOutput 脱敏后的文本限制到 diagsign.MaxOutputBytes。
func capOutput(s string) (string, bool) {
	if len(s) <= diagsign.MaxOutputBytes {
		return s, false
	}
	s = s[:diagsign.MaxOutputBytes]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s, true
}

// execute 执行已验签且参数合法的动作，返回脱敏、限长后的输出。
func (a *agent) execute(ctx context.Context, action string, cp checkedParams) (string, bool, *actionError) {
	var out string
	var truncated bool
	var err *actionError
	switch action {
	case "ping":
		out = fmt.Sprintf("pong agent_version=%s at=%s", agentVersion, a.now().UTC().Format(time.RFC3339))
	case "disk":
		b, _ := jsonIndent(a.collectDisk())
		out = string(b)
	case "certs":
		b, _ := jsonIndent(a.collectCerts())
		out = string(b)
	case "drift_now":
		items, derr := a.collectDrift(ctx)
		if derr != "" {
			out = "drift 失败: " + derr
		} else {
			b, _ := jsonIndent(items)
			out = string(b)
		}
	case "container_inspect":
		out, err = a.containerInspect(ctx, cp.Service)
	case "container_logs":
		out, truncated, err = a.containerLogs(ctx, cp)
	default:
		return "", false, aerr("unknown_action", "动作不在白名单")
	}
	if err != nil {
		return "", false, err
	}
	out = redactText(out)
	o, t := capOutput(out)
	return o, truncated || t, nil
}

// resolveService 在当前项目的容器里找 service；service 必须在实际存在的服务枚举内。
func (a *agent) resolveService(ctx context.Context, service string) (container, *actionError) {
	cs, err := listAllContainers(ctx)
	if err != nil {
		return container{}, aerr("exec_failed", "无法列出容器")
	}
	proj := a.inferProject(cs)
	var found *container
	for i := range cs {
		c := cs[i]
		if c.Project != proj || c.Service == "" || c.Service != service {
			continue
		}
		if found == nil || (found.State != "running" && c.State == "running") {
			found = &cs[i]
		}
	}
	if found == nil {
		return container{}, aerr("unknown_service", "当前项目内没有该服务")
	}
	return *found, nil
}

func (a *agent) containerInspect(ctx context.Context, service string) (string, *actionError) {
	c, e := a.resolveService(ctx, service)
	if e != nil {
		return "", e
	}
	m, err := inspectContainers(ctx, []string{c.ID})
	if err != nil {
		return "", aerr("exec_failed", "inspect 失败")
	}
	var info inspectInfo
	for _, v := range m {
		info = v
	}
	// 只输出状态类字段，不输出 env。
	var b strings.Builder
	fmt.Fprintf(&b, "service=%s\nname=%s\nstate=%s\nhealth=%s\nrestart_count=%d\nimage=%s\nimage_id=%s\nstarted_at=%s\n",
		service, strings.TrimPrefix(info.Name, "/"), info.State.Status, info.health(),
		info.RestartCount, info.Config.Image, info.Image, info.State.StartedAt)
	return b.String(), nil
}

// containerLogs 执行 docker logs --since Nm <id>，在 Go 里逐行过滤，保留尾部 64KB。
func (a *agent) containerLogs(ctx context.Context, cp checkedParams) (string, bool, *actionError) {
	c, e := a.resolveService(ctx, cp.Service)
	if e != nil {
		return "", false, e
	}
	ctx, cancel := context.WithTimeout(ctx, logsTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "logs", "--since", fmt.Sprintf("%dm", cp.Since), c.ID)
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return "", false, aerr("exec_failed", "无法启动 docker logs")
	}
	waitErr := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		_ = pw.CloseWithError(err)
		waitErr <- err
	}()

	var red redactor
	var lines []string
	total := 0
	truncated := false
	readLines(pr, func(raw string) {
		if cp.Grep != "" && !strings.Contains(raw, cp.Grep) {
			return
		}
		l, keep := red.line(raw)
		if !keep {
			return
		}
		lines = append(lines, l)
		total += len(l) + 1
		for total > diagsign.MaxOutputBytes && len(lines) > 1 {
			total -= len(lines[0]) + 1
			lines = lines[1:]
			truncated = true
		}
	})
	_ = pr.Close()
	err := <-waitErr
	if ctx.Err() == context.DeadlineExceeded {
		return "", false, aerr("timeout", "docker logs 超过 %d 秒", int(logsTimeout.Seconds()))
	}
	if err != nil && len(lines) == 0 {
		return "", false, aerr("exec_failed", "docker logs 失败")
	}
	return strings.Join(lines, "\n"), truncated, nil
}

// readLines 逐行读取；超长行只保留前 maxLineBytes，其余丢弃。
func readLines(r io.Reader, fn func(string)) {
	br := bufio.NewReaderSize(r, 64*1024)
	var cur []byte
	over := false
	for {
		chunk, err := br.ReadSlice('\n')
		if len(cur) < maxLineBytes {
			room := maxLineBytes - len(cur)
			if len(chunk) > room {
				cur = append(cur, chunk[:room]...)
				over = true
			} else {
				cur = append(cur, chunk...)
			}
		} else {
			over = true
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(cur) > 0 || err == nil {
			s := strings.TrimRight(string(cur), "\r\n")
			if over {
				s += "...<截断>"
			}
			if !utf8.ValidString(s) {
				s = strings.ToValidUTF8(s, "?")
			}
			fn(s)
		}
		cur, over = cur[:0], false
		if err != nil {
			return
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
