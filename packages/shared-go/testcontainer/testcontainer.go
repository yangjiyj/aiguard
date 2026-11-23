// Package testcontainer 是测试辅助起一次性 docker 容器（临时 PostgreSQL 等）的公共约定，只给 *_test.go 用。
//
//   - 清理一律 docker rm -fv（RemoveArgs）：postgres 等镜像声明了 VOLUME，每次 docker run 都会建一个匿名卷；
//     不带 -v 时，即使容器是 --rm 起的，被 rm -f 删掉后匿名卷也会留下（home 的 /fast 曾因此被撑满）。
//   - 容器打 LabelArgs 的标签（owner_pid、created、host、kind）。测试进程被杀、t.Cleanup 没跑时容器会一直运行，
//     下一次辅助启动前调 ReapOrphans，只回收本套标签、同一台主机、owner 进程已不存在、创建超过 OrphanMinAge 的容器。
//     别的进程正在用的容器（owner 还活着）、标签不全或来自别的主机的容器一律不碰。
//
// shell 与 Python 测试用同一套标签和规则，见 deploy/tests/lib/test-containers.sh。
package testcontainer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// 标签键。
const (
	LabelOwnerPID = "jjdguard.test.owner_pid"
	LabelCreated  = "jjdguard.test.created"
	LabelHost     = "jjdguard.test.host"
	LabelKind     = "jjdguard.test.kind"
)

// OrphanMinAge 是回收前容器至少已经存在的时间，给慢启动、长用例留足余量。
const OrphanMinAge = 30 * time.Minute

// Runner 执行一条 docker 子命令（args 不含 "docker"），返回合并输出。
type Runner func(ctx context.Context, args ...string) (string, error)

// DockerRunner 返回每条命令限时 timeout 的默认 Runner。
func DockerRunner(timeout time.Duration) Runner {
	return func(parent context.Context, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
}

// LabelArgs 返回 docker run 要带的 --label 参数；kind 标明是哪个测试辅助（如 routing-status）。
func LabelArgs(kind string) []string {
	return labelArgs(kind, currentPID(), time.Now(), hostname())
}

func labelArgs(kind string, pid int, now time.Time, host string) []string {
	return []string{
		"--label", LabelOwnerPID + "=" + strconv.Itoa(pid),
		"--label", LabelCreated + "=" + strconv.FormatInt(now.Unix(), 10),
		"--label", LabelHost + "=" + host,
		"--label", LabelKind + "=" + kind,
	}
}

// RemoveArgs 返回删除容器连同匿名卷的参数：rm -fv（与仓库里其他 Go 测试辅助同一写法）。
func RemoveArgs(ids ...string) []string {
	return append([]string{"rm", "-fv"}, ids...)
}

// Remove 删除容器连同匿名卷。
func Remove(ctx context.Context, run Runner, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	if out, err := run(ctx, RemoveArgs(ids...)...); err != nil {
		return fmt.Errorf("docker rm -fv %s: %w: %s", strings.Join(ids, " "), err, out)
	}
	return nil
}

// ReapOrphans 回收本机上 owner 进程已不存在、创建超过 OrphanMinAge 的测试容器（rm -fv），返回删掉的容器 ID。
// 列不出容器时返回错误、什么都不删；单个容器删除失败时继续处理其余容器，最后返回第一个错误。
func ReapOrphans(ctx context.Context, run Runner) ([]string, error) {
	return reapOrphans(ctx, run, time.Now(), hostname(), processAlive)
}

func reapOrphans(ctx context.Context, run Runner, now time.Time, host string, alive func(int) bool) ([]string, error) {
	format := fmt.Sprintf("{{.ID}}\t{{.Label %q}}\t{{.Label %q}}\t{{.Label %q}}", LabelOwnerPID, LabelCreated, LabelHost)
	out, err := run(ctx, "ps", "-a", "--filter", "label="+LabelOwnerPID, "--format", format)
	if err != nil {
		return nil, fmt.Errorf("list labeled test containers: %w: %s", err, out)
	}
	var removed []string
	var firstErr error
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) != 4 || fields[0] == "" || fields[3] != host {
			continue
		}
		pid, pidErr := strconv.Atoi(fields[1])
		created, createdErr := strconv.ParseInt(fields[2], 10, 64)
		if pidErr != nil || createdErr != nil || pid <= 0 {
			continue
		}
		if now.Sub(time.Unix(created, 0)) < OrphanMinAge || alive(pid) {
			continue
		}
		if err := Remove(ctx, run, fields[0]); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		removed = append(removed, fields[0])
	}
	return removed, firstErr
}

func currentPID() int { return os.Getpid() }

func hostname() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "unknown"
	}
	return name
}
