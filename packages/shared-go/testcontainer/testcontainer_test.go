package testcontainer

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLabelArgsCarryOwnerCreatedHostAndKind(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	got := labelArgs("routing-status", 4242, now, "home")
	want := []string{
		"--label", "jjdguard.test.owner_pid=4242",
		"--label", "jjdguard.test.created=1800000000",
		"--label", "jjdguard.test.host=home",
		"--label", "jjdguard.test.kind=routing-status",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("labels=%v want %v", got, want)
	}
}

func TestRemoveArgsAlwaysDropAnonymousVolumes(t *testing.T) {
	if got := RemoveArgs("abc", "def"); !reflect.DeepEqual(got, []string{"rm", "-fv", "abc", "def"}) {
		t.Fatalf("remove args=%v", got)
	}
}

type fakeDocker struct {
	listing string
	listErr error
	calls   [][]string
}

func (f *fakeDocker) run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if len(args) > 0 && args[0] == "ps" {
		return f.listing, f.listErr
	}
	return "", nil
}

// 只回收：带本套标签、同一台主机、owner 进程已不在、创建超过 30 分钟的容器；其余一律不碰。
func TestReapOrphansRemovesOnlyDeadOwnersOlderThanThirtyMinutes(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	old := now.Add(-31 * time.Minute).Unix()
	young := now.Add(-29 * time.Minute).Unix()
	rows := []string{
		fmt.Sprintf("dead-old\t101\t%d\thome", old),     // 回收
		fmt.Sprintf("alive-old\t202\t%d\thome", old),    // owner 还活着：别的进程正在用
		fmt.Sprintf("dead-young\t303\t%d\thome", young), // 不到 30 分钟
		fmt.Sprintf("other-host\t404\t%d\tother", old),  // 别的主机（PID 不在同一命名空间）
		fmt.Sprintf("bad-pid\tabc\t%d\thome", old),      // 标签不完整：不碰
		"bad-created\t505\tyesterday\thome",             // 标签不完整：不碰
		fmt.Sprintf("zero-pid\t0\t%d\thome", old),       // 非法 PID：不碰
		"",
	}
	docker := &fakeDocker{listing: strings.Join(rows, "\n")}
	alive := func(pid int) bool { return pid == 202 }
	removed, err := reapOrphans(context.Background(), docker.run, now, "home", alive)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed, []string{"dead-old"}) {
		t.Fatalf("removed=%v", removed)
	}
	wantPS := []string{"ps", "-a", "--filter", "label=jjdguard.test.owner_pid", "--format",
		`{{.ID}}	{{.Label "jjdguard.test.owner_pid"}}	{{.Label "jjdguard.test.created"}}	{{.Label "jjdguard.test.host"}}`}
	if len(docker.calls) != 2 || !reflect.DeepEqual(docker.calls[0], wantPS) || !reflect.DeepEqual(docker.calls[1], []string{"rm", "-fv", "dead-old"}) {
		t.Fatalf("docker calls=%q", docker.calls)
	}
}

func TestReapOrphansReportsListFailureWithoutRemoving(t *testing.T) {
	docker := &fakeDocker{listErr: errors.New("daemon down")}
	if _, err := reapOrphans(context.Background(), docker.run, time.Now(), "home", func(int) bool { return false }); err == nil {
		t.Fatal("list failure must be reported")
	}
	if len(docker.calls) != 1 {
		t.Fatalf("nothing may be removed when listing fails: %q", docker.calls)
	}
}

func TestProcessAliveSeesThisProcess(t *testing.T) {
	if !processAlive(currentPID()) {
		t.Fatal("the current test process must count as alive")
	}
	if processAlive(0) || processAlive(-1) {
		t.Fatal("non-positive PIDs are never alive")
	}
}
