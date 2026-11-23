package handler

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 带 updated_at 语义的系统设置替身：Set/SetMultiple 与真实仓储一样刷新 updated_at。
type modeWatchRepo struct {
	mu       sync.Mutex
	values   map[string]string
	updated  map[string]time.Time
	clock    time.Time
	setCalls int
}

func newModeWatchRepo(values map[string]string) *modeWatchRepo {
	r := &modeWatchRepo{values: map[string]string{}, updated: map[string]time.Time{}, clock: time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC)}
	for k, v := range values {
		r.values[k], r.updated[k] = v, r.clock
	}
	return r
}

func (r *modeWatchRepo) tick() time.Time { r.clock = r.clock.Add(time.Second); return r.clock }

// directWrite 模拟绕过控制台直接写库：只改值和 updated_at，不动 modified_by/at。
func (r *modeWatchRepo) directWrite(key, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values[key], r.updated[key] = value, r.tick()
}

func (r *modeWatchRepo) remove(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.values, key)
	delete(r.updated, key)
}

func (r *modeWatchRepo) Get(_ context.Context, key string) (*repository.SystemSetting, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.values[key]; ok {
		return &repository.SystemSetting{Key: key, Value: v, UpdatedAt: r.updated[key]}, nil
	}
	return nil, nil
}

func (r *modeWatchRepo) GetAll(context.Context) ([]*repository.SystemSetting, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*repository.SystemSetting, 0, len(r.values))
	for k, v := range r.values {
		out = append(out, &repository.SystemSetting{Key: k, Value: v, UpdatedAt: r.updated[k]})
	}
	return out, nil
}

func (r *modeWatchRepo) Set(_ context.Context, key, value string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setCalls++
	r.values[key], r.updated[key] = value, r.tick()
	return nil
}

func (r *modeWatchRepo) SetMultiple(_ context.Context, settings map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.tick()
	for k, v := range settings {
		r.values[k], r.updated[k] = v, now
	}
	return nil
}

func (r *modeWatchRepo) CreateAuditOperation(context.Context, *repository.AuditOperation) error {
	return nil
}
func (r *modeWatchRepo) ListAuditOperations(context.Context, int, int, string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (r *modeWatchRepo) GetBool(context.Context, string) (bool, error) { return false, nil }

type recordingModeSink struct {
	inputs []repository.AlertGroupUpsertInput
	fail   bool
}

func (s *recordingModeSink) UpsertOpen(_ context.Context, in repository.AlertGroupUpsertInput) (*repository.AlertGroup, bool, error) {
	if s.fail {
		return nil, false, errors.New("inbox unavailable")
	}
	s.inputs = append(s.inputs, in)
	return &repository.AlertGroup{}, true, nil
}

func (s *recordingModeSink) kinds() []string {
	var out []string
	for _, in := range s.inputs {
		out = append(out, in.BodyJSON["change_kind"].(string))
	}
	return out
}

func modeWatchFixture(t *testing.T, values map[string]string) (*modeWatchRepo, *recordingModeSink, *executionModeWatcher, *Dependencies) {
	t.Helper()
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	repo := newModeWatchRepo(values)
	return repo, &recordingModeSink{}, newExecutionModeWatcher("unit-test-internal-secret"), &Dependencies{SystemRepo: repo}
}

// 审查 #10：两次巡检之间 record→protect→record 来回切换，生效值没变，但
// 模式键的 updated_at 推进了——必须告警，而不是静默漏掉。
func TestModeWatchDetectsTransientSwitchBetweenTicks(t *testing.T) {
	repo, sink, w, deps := modeWatchFixture(t, map[string]string{
		securityExecutionModeSettingKey: "record", securityAuditOnlySettingKey: "true",
	})
	modeWatchTick(context.Background(), deps, sink, w) // 建基线
	if len(sink.inputs) != 0 {
		t.Fatalf("baseline tick must not alert: %v", sink.kinds())
	}
	repo.directWrite(securityExecutionModeSettingKey, "protect")
	repo.directWrite(securityExecutionModeSettingKey, "record")
	modeWatchTick(context.Background(), deps, sink, w)
	if got := sink.kinds(); len(got) != 1 || got[0] != modeChangeKindRewritten {
		t.Fatalf("transient switch must raise one rewrite alert, got %v", got)
	}
	if sink.inputs[0].BodyJSON["attributed"] != false {
		t.Fatal("a direct database write must be flagged unattributed")
	}
	modeWatchTick(context.Background(), deps, sink, w)
	if len(sink.inputs) != 1 {
		t.Fatalf("the same rewrite must not alert twice: %v", sink.kinds())
	}
}

func TestModeWatchDetectsBaselineDeletionAndTampering(t *testing.T) {
	repo, sink, w, deps := modeWatchFixture(t, map[string]string{securityExecutionModeSettingKey: "record"})
	modeWatchTick(context.Background(), deps, sink, w)

	repo.remove(executionModeBaselineKey)
	modeWatchTick(context.Background(), deps, sink, w)
	if got := sink.kinds(); len(got) != 1 || got[0] != modeChangeKindDeleted {
		t.Fatalf("deleted baseline must alert, got %v", got)
	}
	if _, ok := repo.values[executionModeBaselineKey]; !ok {
		t.Fatal("baseline must be rewritten after deletion")
	}

	// 改库者同时改模式和基线（伪造成"一直是 protect"）：签名不对，必须告警，
	// 并且之后的模式比对仍以本进程确认的 record 为准。
	repo.directWrite(securityExecutionModeSettingKey, "protect")
	repo.directWrite(executionModeBaselineKey, "protect/protect|2026-09-27T08:00:00Z")
	modeWatchTick(context.Background(), deps, sink, w)
	got := sink.kinds()
	if len(got) != 3 || got[1] != modeChangeKindTampered || got[2] != modeChangeKindChanged {
		t.Fatalf("tampered baseline + mode change must raise tamper and change alerts, got %v", got)
	}
	if sink.inputs[2].BodyJSON["old_mode"] != "record" || sink.inputs[2].BodyJSON["new_mode"] != "protect" {
		t.Fatalf("change must be measured against the trusted baseline: %#v", sink.inputs[2].BodyJSON)
	}
}

func TestModeWatchSignedBaselineSurvivesRestartAndRejectsUnsignedAtStartup(t *testing.T) {
	repo, sink, w, deps := modeWatchFixture(t, map[string]string{securityExecutionModeSettingKey: "record"})
	// 配置了密钥时，启动读到未签名基线不能静默采信：告警，并按当前状态重建签名基线。
	repo.directWrite(executionModeBaselineKey, "record/record|2026-09-27T07:00:00Z")
	modeWatchTick(context.Background(), deps, sink, w)
	if got := sink.kinds(); len(got) != 1 || got[0] != modeChangeKindTampered {
		t.Fatalf("unsigned baseline at startup must alert, got %v", got)
	}
	if !strings.HasPrefix(repo.values[executionModeBaselineKey], "v2|") {
		t.Fatalf("baseline must be rebuilt signed, got %q", repo.values[executionModeBaselineKey])
	}
	modeWatchTick(context.Background(), deps, sink, w)
	if len(sink.inputs) != 1 {
		t.Fatalf("the rebuilt baseline must not alert again: %v", sink.kinds())
	}
	// 重启：新进程读到签名基线，未变化不告警；停机期间的变化照常告警。
	restarted := newExecutionModeWatcher("unit-test-internal-secret")
	modeWatchTick(context.Background(), deps, sink, restarted)
	if len(sink.inputs) != 1 {
		t.Fatalf("restart with a valid signed baseline must not alert: %v", sink.kinds())
	}
	repo.directWrite(securityExecutionModeSettingKey, "protect")
	again := newExecutionModeWatcher("unit-test-internal-secret")
	modeWatchTick(context.Background(), deps, sink, again)
	if got := sink.kinds(); len(got) != 2 || got[1] != modeChangeKindChanged {
		t.Fatalf("a change during downtime must alert after restart, got %v", got)
	}
	// 进程运行中读到未签名基线 = 被改写。
	repo.directWrite(executionModeBaselineKey, "protect/protect|2026-09-27T09:00:00Z")
	modeWatchTick(context.Background(), deps, sink, again)
	if got := sink.kinds(); got[len(got)-1] != modeChangeKindTampered {
		t.Fatalf("an unsigned baseline appearing at runtime is tampering, got %v", got)
	}
}

// 没有签名密钥的部署只能信任未签名基线（检测边界），不产生告警。
func TestModeWatchWithoutSecretAcceptsUnsignedBaseline(t *testing.T) {
	repo, sink, _, deps := modeWatchFixture(t, map[string]string{securityExecutionModeSettingKey: "record"})
	repo.directWrite(executionModeBaselineKey, "record/record|2026-09-27T07:00:00Z")
	unsigned := newExecutionModeWatcher("")
	modeWatchTick(context.Background(), deps, sink, unsigned)
	if len(sink.inputs) != 0 {
		t.Fatalf("unsigned deployment must accept its own baseline format: %v", sink.kinds())
	}
}

// 审查：回放一条更早的合法签名基线，再把模式键 updated_at 回拨，不能零告警。
func TestModeWatchDetectsReplayedSignedBaselineAndClockRollback(t *testing.T) {
	repo, sink, w, deps := modeWatchFixture(t, map[string]string{securityExecutionModeSettingKey: "record"})
	modeWatchTick(context.Background(), deps, sink, w)
	oldBaseline := repo.values[executionModeBaselineKey]
	oldWrite := repo.updated[securityExecutionModeSettingKey]

	// 控制台正常切到 protect 再切回 record：两次都告警，基线推进。
	repo.directWrite(securityExecutionModeSettingKey, "protect")
	modeWatchTick(context.Background(), deps, sink, w)
	repo.directWrite(securityExecutionModeSettingKey, "record")
	modeWatchTick(context.Background(), deps, sink, w)
	base := len(sink.inputs)

	// 攻击：两次巡检之间切到 protect 又切回，写回装机时那条合法签名基线，回拨 updated_at。
	repo.directWrite(securityExecutionModeSettingKey, "protect")
	repo.directWrite(securityExecutionModeSettingKey, "record")
	repo.mu.Lock()
	repo.updated[securityExecutionModeSettingKey] = oldWrite
	repo.values[executionModeBaselineKey] = oldBaseline
	repo.mu.Unlock()
	modeWatchTick(context.Background(), deps, sink, w)
	got := sink.kinds()[base:]
	if len(got) == 0 || got[0] != modeChangeKindTampered {
		t.Fatalf("a replayed older signed baseline must raise a tamper alert, got %v", got)
	}
	if repo.values[executionModeBaselineKey] == oldBaseline {
		t.Fatal("the replayed baseline must be replaced by the trusted one")
	}

	// 只回拨 updated_at（不动基线）同样告警。
	before := len(sink.inputs)
	repo.mu.Lock()
	repo.updated[securityExecutionModeSettingKey] = oldWrite.Add(-time.Hour)
	repo.mu.Unlock()
	modeWatchTick(context.Background(), deps, sink, w)
	got = sink.kinds()[before:]
	if len(got) != 1 || got[0] != modeChangeKindTampered {
		t.Fatalf("a rolled-back updated_at must raise a tamper alert, got %v", got)
	}

	// 复审 #1：之后每次"切过去→切回→再把 updated_at 回拨到同一个值"都不能被静默吸收。
	rb := repo.updated[securityExecutionModeSettingKey]
	for i := 0; i < 3; i++ {
		before = len(sink.inputs)
		repo.directWrite(securityExecutionModeSettingKey, "protect")
		repo.directWrite(securityExecutionModeSettingKey, "record")
		repo.mu.Lock()
		repo.updated[securityExecutionModeSettingKey] = rb
		repo.mu.Unlock()
		modeWatchTick(context.Background(), deps, sink, w)
		if len(sink.inputs) == before {
			t.Fatalf("repeated rollback to the same value #%d must still alert", i+1)
		}
	}
}

// 停机期间删掉基线：只要控制台改过模式（modified_by 非空），重启后必须告警；
// 全新安装（从未改过）静默建立基线。
func TestModeWatchStartupWithoutBaseline(t *testing.T) {
	repo, sink, w, deps := modeWatchFixture(t, map[string]string{
		securityExecutionModeSettingKey:           "protect",
		securityExecutionModeModifiedBySettingKey: "user_admin",
		securityExecutionModeModifiedAtSettingKey: "2026-09-27T08:00:00Z",
	})
	modeWatchTick(context.Background(), deps, sink, w)
	if got := sink.kinds(); len(got) != 1 || got[0] != modeChangeKindDeleted {
		t.Fatalf("missing baseline after console changes must alert, got %v", got)
	}
	if _, ok := repo.values[executionModeBaselineKey]; !ok {
		t.Fatal("baseline must be rebuilt")
	}
	_, freshSink, fresh, freshDeps := modeWatchFixture(t, map[string]string{securityExecutionModeSettingKey: "record"})
	modeWatchTick(context.Background(), freshDeps, freshSink, fresh)
	if len(freshSink.inputs) != 0 {
		t.Fatalf("a fresh install must not alert: %v", freshSink.kinds())
	}
}

// 伪造成 v2 格式的基线：MAC 错、MAC 为空、或用别的密钥签名，启动时都不能被采信。
func TestModeWatchRejectsForgedSignedBaseline(t *testing.T) {
	forger := newExecutionModeWatcher("attacker-guessed-secret")
	forger.restore("protect/protect", "2026-09-27T08:00:00Z")
	forger.pending = forger.encodeLocked()
	otherKey, _ := forger.baseline()
	cases := map[string]string{
		"wrong_mac": "v2|protect/protect|2026-09-27T08:00:00Z||deadbeef",
		"empty_mac": "v2|protect/protect|2026-09-27T08:00:00Z||",
		"other_key": otherKey,
	}
	for name, forged := range cases {
		t.Run(name, func(t *testing.T) {
			repo, sink, _, deps := modeWatchFixture(t, map[string]string{securityExecutionModeSettingKey: "record"})
			repo.directWrite(executionModeBaselineKey, forged)
			fresh := newExecutionModeWatcher("unit-test-internal-secret")
			modeWatchTick(context.Background(), deps, sink, fresh)
			got := sink.kinds()
			if len(got) == 0 || got[0] != modeChangeKindTampered {
				t.Fatalf("forged v2 baseline %q must raise a tamper alert, got %v", forged, got)
			}
			for _, input := range sink.inputs {
				if input.BodyJSON["change_kind"] == modeChangeKindChanged && input.BodyJSON["old_mode"] == "protect" {
					t.Fatalf("a forged baseline must not become the comparison point: %#v", input.BodyJSON)
				}
			}
			if !strings.HasPrefix(repo.values[executionModeBaselineKey], "v2|") || repo.values[executionModeBaselineKey] == forged {
				t.Fatalf("forged baseline must be replaced by a trusted one, got %q", repo.values[executionModeBaselineKey])
			}
		})
	}
}

// 直接写库留下的是上一次控制台操作者；modified_at 与这次写入对不上就不能算归因。
func TestModeWatchDoesNotAttributeStaleModifiedBy(t *testing.T) {
	repo, sink, w, deps := modeWatchFixture(t, map[string]string{
		securityExecutionModeSettingKey:           "record",
		securityExecutionModeModifiedBySettingKey: "codex_restore_user_configuration",
		securityExecutionModeModifiedAtSettingKey: "2026-09-20T01:00:00Z",
	})
	modeWatchTick(context.Background(), deps, sink, w)
	// 首轮：控制台改过模式却没有基线 → 启动告警（见 TestModeWatchStartupWithoutBaseline），这里只看后续。
	sink.inputs = nil
	repo.directWrite(securityExecutionModeSettingKey, "protect")
	modeWatchTick(context.Background(), deps, sink, w)
	if len(sink.inputs) != 1 || sink.inputs[0].BodyJSON["attributed"] != false {
		t.Fatalf("stale modified_by must not attribute a direct write: %#v", sink.inputs)
	}
	if sink.inputs[0].BodyJSON["modified_by"] != "codex_restore_user_configuration" {
		t.Fatal("the stale value is still shown for investigation")
	}

	// 控制台写入：modified_by/at 与模式同一语句写下，归因成立。
	now := repo.clock.Add(time.Second)
	_ = repo.SetMultiple(context.Background(), map[string]string{
		securityExecutionModeSettingKey:           "record",
		securityExecutionModeModifiedBySettingKey: "user_admin",
		securityExecutionModeModifiedAtSettingKey: now.Format(time.RFC3339Nano),
	})
	modeWatchTick(context.Background(), deps, sink, w)
	last := sink.inputs[len(sink.inputs)-1].BodyJSON
	if last["attributed"] != true || last["modified_by"] != "user_admin" {
		t.Fatalf("a console change must be attributed: %#v", last)
	}
}

// 告警写不进收件箱时不能推进基线，否则这次变更就永远丢了。
func TestModeWatchKeepsBaselineWhenAlertWriteFails(t *testing.T) {
	repo, sink, w, deps := modeWatchFixture(t, map[string]string{securityExecutionModeSettingKey: "record"})
	modeWatchTick(context.Background(), deps, sink, w)
	stored := repo.values[executionModeBaselineKey]
	repo.directWrite(securityExecutionModeSettingKey, "protect")
	sink.fail = true
	modeWatchTick(context.Background(), deps, sink, w)
	if repo.values[executionModeBaselineKey] != stored {
		t.Fatal("baseline must not advance past an unrecorded change")
	}
	sink.fail = false
	modeWatchTick(context.Background(), deps, sink, newExecutionModeWatcher("unit-test-internal-secret"))
	if got := sink.kinds(); len(got) != 1 || got[0] != modeChangeKindChanged {
		t.Fatalf("the unrecorded change must be reported on a later tick, got %v", got)
	}
}

// 同一个进程重试：写告警失败后内存也要回滚，否则下一轮认为"已确认"而漏报。
func TestModeWatchSameProcessRetriesAfterAlertWriteFails(t *testing.T) {
	repo, sink, w, deps := modeWatchFixture(t, map[string]string{securityExecutionModeSettingKey: "record"})
	modeWatchTick(context.Background(), deps, sink, w)
	repo.directWrite(securityExecutionModeSettingKey, "protect")
	sink.fail = true
	modeWatchTick(context.Background(), deps, sink, w)
	sink.fail = false
	modeWatchTick(context.Background(), deps, sink, w)
	if got := sink.kinds(); len(got) != 1 || got[0] != modeChangeKindChanged {
		t.Fatalf("the same watcher must re-report the change after a failed write, got %v", got)
	}
}

// 基线写库失败时内存不能领先于库，否则下一轮会把库里的旧基线误判为回放。
func TestModeWatchBaselinePersistFailureDoesNotCauseReplayAlert(t *testing.T) {
	repo, sink, w, deps := modeWatchFixture(t, map[string]string{securityExecutionModeSettingKey: "record"})
	modeWatchTick(context.Background(), deps, sink, w)
	repo.directWrite(securityExecutionModeSettingKey, "protect")
	failing := &failingSetRepo{modeWatchRepo: repo}
	modeWatchTick(context.Background(), &Dependencies{SystemRepo: failing}, sink, w)
	if got := sink.kinds(); len(got) != 1 || got[0] != modeChangeKindChanged {
		t.Fatalf("the change must still be alerted, got %v", got)
	}
	modeWatchTick(context.Background(), deps, sink, w)
	for _, kind := range sink.kinds() {
		if kind == modeChangeKindTampered {
			t.Fatalf("a failed baseline write must not later look like a replay: %v", sink.kinds())
		}
	}
}

type failingSetRepo struct{ *modeWatchRepo }

func (r *failingSetRepo) Set(context.Context, string, string) error {
	return errors.New("database unavailable")
}

func (r *modeWatchRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}
