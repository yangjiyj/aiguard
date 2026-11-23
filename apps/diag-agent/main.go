// jjdguard-diag-agent：宿主机诊断采集器。不开端口，只通过共享目录与控制面通信。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/diagsign"
)

const (
	agentVersion   = "0.1.0"
	maxTaskBytes   = 8 * 1024
	outboxKeepFor  = 10 * time.Minute
	snapshotPeriod = 60 * time.Second
	inboxPeriod    = 2 * time.Second
)

type agent struct {
	dir       string
	deployDir string
	key       []byte
	seen      *seenStore
	now       func() time.Time
}

func newAgent(dir, deployDir string, key []byte) (*agent, error) {
	for _, sub := range []string{"inbox", "outbox", "snapshot"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o700); err != nil {
		return nil, err
	}
	a := &agent{dir: dir, deployDir: deployDir, key: key, now: time.Now}
	s, err := loadSeen(filepath.Join(dir, "state", "seen.log"), a.now())
	if err != nil {
		return nil, err
	}
	a.seen = s
	return a, nil
}

func readKey(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("密钥文件权限过宽（%v），应为 0600", st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k := []byte(strings.TrimSpace(string(b)))
	if len(k) < 16 {
		return nil, errors.New("密钥太短（至少 16 字节）")
	}
	return k, nil
}

// readTaskFile 以 O_NOFOLLOW 打开并限制大小，只接受普通文件。
func readTaskFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxTaskBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxTaskBytes {
		return nil, errors.New("task too large")
	}
	return b, nil
}

func (a *agent) writeResult(id string, res diagsign.Result) {
	res.ID = id
	res.FinishedAt = a.now().UTC().Format(time.RFC3339)
	b, err := json.Marshal(res)
	if err != nil {
		return
	}
	_ = atomicWrite(filepath.Join(a.dir, "outbox", id+".json"), b, 0o644)
}

func (a *agent) reject(id, code string) {
	a.writeResult(id, diagsign.Result{OK: false, Error: code, Output: ""})
}

// processFile 处理 inbox 中的一个任务文件：验签 -> 防重放 -> 校验 -> 执行 -> 写 outbox -> 删除任务。
func (a *agent) processFile(ctx context.Context, name string) {
	path := filepath.Join(a.dir, "inbox", name)
	defer os.Remove(path)
	stem := strings.TrimSuffix(name, ".json")
	if !taskIDRe.MatchString(stem) {
		return // 文件名不合法：直接删除，不写结果
	}
	raw, err := readTaskFile(path)
	if err != nil {
		a.reject(stem, "bad_request")
		return
	}
	var t diagsign.Task
	if err := json.Unmarshal(raw, &t); err != nil || t.ID != stem {
		a.reject(stem, "bad_request")
		return
	}
	if err := diagsign.VerifyAt(a.key, t, a.now()); err != nil {
		switch {
		case errors.Is(err, diagsign.ErrExpired):
			a.reject(stem, "expired")
		default:
			a.reject(stem, "bad_signature")
		}
		return
	}
	// 验签通过后才记录，避免未认证输入撑大 seen.log。
	if a.seen.has(t.ID) {
		a.reject(stem, "replay")
		return
	}
	if err := a.seen.add(t.ID, a.now()); err != nil {
		a.reject(stem, "internal_error")
		return
	}
	cp, aerrv := checkParams(t.Action, t.Params)
	if aerrv != nil {
		a.reject(stem, aerrv.Code)
		return
	}
	out, trunc, aerrv := a.execute(ctx, t.Action, cp)
	if aerrv != nil {
		a.reject(stem, aerrv.Code)
		return
	}
	a.writeResult(stem, diagsign.Result{OK: true, Output: out, Truncated: trunc})
}

// scanInbox 处理一轮 inbox，并清理过期的 outbox 与 seen 记录。
func (a *agent) scanInbox(ctx context.Context) {
	ents, err := os.ReadDir(filepath.Join(a.dir, "inbox"))
	if err == nil {
		for _, e := range ents {
			if ctx.Err() != nil {
				return
			}
			n := e.Name()
			if !strings.HasSuffix(n, ".json") || strings.HasPrefix(n, ".") {
				continue
			}
			a.processFile(ctx, n)
		}
	}
	a.cleanOutbox()
	a.seen.prune(a.now())
}

func (a *agent) cleanOutbox() {
	ents, err := os.ReadDir(filepath.Join(a.dir, "outbox"))
	if err != nil {
		return
	}
	for _, e := range ents {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if a.now().Sub(info.ModTime()) > outboxKeepFor {
			_ = os.Remove(filepath.Join(a.dir, "outbox", e.Name()))
		}
	}
}

func main() {
	dir := flag.String("dir", "/var/lib/jjdguard/diag", "共享目录")
	keyFile := flag.String("key-file", "/etc/jjdguard/diag-agent.key", "HMAC 密钥文件")
	deployDir := flag.String("deploy-dir", "/opt/jjdguard/current/deploy/docker-compose", "开机链目录")
	once := flag.Bool("once", false, "只写一次快照并处理一轮 inbox 后退出（供 cron 使用）")
	flag.Parse()

	key, err := readKey(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取密钥失败:", err)
		os.Exit(1)
	}
	a, err := newAgent(*dir, *deployDir, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "初始化失败:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *once {
		if err := a.writeSnapshot(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "写快照失败:", err)
		}
		a.scanInbox(ctx)
		return
	}

	go func() {
		t := time.NewTicker(snapshotPeriod)
		defer t.Stop()
		for {
			if err := a.writeSnapshot(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "写快照失败:", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	t := time.NewTicker(inboxPeriod)
	defer t.Stop()
	for {
		a.scanInbox(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
