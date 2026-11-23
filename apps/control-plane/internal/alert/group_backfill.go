package alert

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const (
	backfillCheckpointKey = "secevent_group_backfill_checkpoint"
	backfillDoneKey       = "secevent_group_backfill_done"
	backfillBatchSize     = 5000
	backfillBatchPause    = 500 * time.Millisecond
)

// backfillCheckpoint 是断点续跑游标：keyset 分页 (created_at, id)，存 system_settings。
type backfillCheckpoint struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

func marshalBackfillCheckpoint(cp backfillCheckpoint) string {
	raw, _ := json.Marshal(cp)
	return string(raw)
}

func parseBackfillCheckpoint(raw string) backfillCheckpoint {
	zero := backfillCheckpoint{CreatedAt: time.Unix(0, 0).UTC()}
	if raw == "" {
		return zero
	}
	var cp backfillCheckpoint
	if err := json.Unmarshal([]byte(raw), &cp); err != nil || cp.CreatedAt.IsZero() {
		return zero
	}
	return cp
}

type backfillSettings interface {
	Get(ctx context.Context, key string) (*repository.SystemSetting, error)
	Set(ctx context.Context, key, value string) error
}

// GroupBackfill 是 P1-D 存量回算一次性后台任务（设计 3a"回填与计数"）：
// 给历史 security_events 回填 alert_group_id，并重算各组主指标。
//   - group_key 指纹算法只存在于 Go 侧（复用 eventGroupKey），security_events 百万行级，
//     故不进 SQL 迁移，走后台任务；
//   - 分批 5000 行、批间 500ms 限速；断点 (created_at,id) 存 system_settings，可断点续跑；
//   - 只回填「已进桥」的事件（alerted_at IS NOT NULL）：被抑制/FP 静默事件本就没有组，
//     与在线路径口径一致（UI 注明"明细仅含进组事件"）；
//   - 完成后写 done 标记，重启不再执行；单行失败跳过不阻塞（宁可漏回填等下轮，不 crash）。
type GroupBackfill struct {
	db       *pgxpool.Pool
	groups   *repository.AlertGroupRepository
	settings backfillSettings
	batch    int
	pause    time.Duration
}

func NewGroupBackfill(db *pgxpool.Pool, groups *repository.AlertGroupRepository, settings backfillSettings) *GroupBackfill {
	return &GroupBackfill{db: db, groups: groups, settings: settings, batch: backfillBatchSize, pause: backfillBatchPause}
}

func (g *GroupBackfill) Run(ctx context.Context) error {
	if g == nil || g.settings == nil {
		return nil
	}
	if done, _ := g.settings.Get(ctx, backfillDoneKey); done != nil && done.Value == "true" {
		return nil // 已完成：一次性任务不重跑
	}
	if g.db == nil || g.groups == nil {
		return nil
	}
	cp := backfillCheckpoint{CreatedAt: time.Unix(0, 0).UTC()}
	if saved, _ := g.settings.Get(ctx, backfillCheckpointKey); saved != nil {
		cp = parseBackfillCheckpoint(saved.Value)
	}
	totalAttached := 0
	for {
		events, err := g.fetchBatch(ctx, cp)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			break
		}
		touched := map[[2]string]bool{}
		for _, ev := range events {
			cp = backfillCheckpoint{CreatedAt: ev.CreatedAt, ID: ev.ID}
			groupID, lerr := g.lookupEventGroup(ctx, ev)
			if lerr != nil {
				log.Printf("[group_backfill] lookup group for %s failed: %v (skip)", ev.ID, lerr)
				continue
			}
			if groupID == "" {
				continue // 该事件从未成组（历史上被折叠进旧收件箱前即无组），保持 NULL
			}
			if aerr := g.groups.AttachEvent(ctx, ev.TenantID, ev.ID, groupID); aerr != nil {
				log.Printf("[group_backfill] attach %s -> %s failed: %v (skip)", ev.ID, groupID, aerr)
				continue
			}
			touched[[2]string{ev.TenantID, groupID}] = true
			totalAttached++
		}
		for key := range touched {
			if _, _, rerr := g.groups.RecalcCounters(ctx, key[0], key[1]); rerr != nil {
				log.Printf("[group_backfill] recalc %s failed: %v", key[1], rerr)
			}
		}
		if serr := g.settings.Set(ctx, backfillCheckpointKey, marshalBackfillCheckpoint(cp)); serr != nil {
			log.Printf("[group_backfill] save checkpoint failed: %v", serr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err() // 断点已存，下次启动续跑
		case <-time.After(g.pause):
		}
	}
	log.Printf("[group_backfill] done: %d events attached", totalAttached)
	return g.settings.Set(ctx, backfillDoneKey, "true")
}

// fetchBatch 按 keyset (created_at, id) 拉取一批待回填事件。
// LEFT JOIN rules 补 rule_name/rule_type，保证 eventGroupKey 的无 findings 回退分支
// 与在线路径（ListUnalerted 同款 JOIN）产出完全一致的 group_key。
func (g *GroupBackfill) fetchBatch(ctx context.Context, cp backfillCheckpoint) ([]*repository.SecurityEvent, error) {
	rows, err := g.db.Query(ctx, `
		SELECT se.id, se.request_id, se.tenant_id, COALESCE(se.project_id, ''),
		       COALESCE(se.user_id, ''), se.event_type, se.severity,
		       COALESCE(se.rule_id, ''), COALESCE(r.name, ''), COALESCE(r.rule_type, ''),
		       se.action_taken, COALESCE(se.matched_summary, '{}'::jsonb),
		       COALESCE(se.evidence_ref, ''), COALESCE(se.principal_key, ''), se.created_at
		FROM security_events se
		LEFT JOIN rules r ON r.id = se.rule_id
		WHERE se.alert_group_id IS NULL
		  AND se.alerted_at IS NOT NULL
		  AND (se.created_at, se.id) > ($1, $2)
		ORDER BY se.created_at, se.id
		LIMIT $3
	`, cp.CreatedAt, cp.ID, g.batch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []*repository.SecurityEvent{}
	for rows.Next() {
		var ev repository.SecurityEvent
		var matchedJSON []byte
		if err := rows.Scan(&ev.ID, &ev.RequestID, &ev.TenantID, &ev.ProjectID, &ev.UserID,
			&ev.EventType, &ev.Severity, &ev.RuleID, &ev.RuleName, &ev.RuleType,
			&ev.ActionTaken, &matchedJSON, &ev.EvidenceRef, &ev.PrincipalKey, &ev.CreatedAt); err != nil {
			return nil, err
		}
		ev.MatchedSummary = map[string]interface{}{}
		if len(matchedJSON) > 0 {
			_ = json.Unmarshal(matchedJSON, &ev.MatchedSummary)
		}
		events = append(events, &ev)
	}
	return events, rows.Err()
}

// lookupEventGroup 优先 v2 组键，并仅在已知 project/stage 完全相同时兼容历史键。
// 不限状态：已关闭的 FP 组也算——
// 明细归属看指纹同一性，不看组生命周期）。找不到返回空。
func (g *GroupBackfill) lookupEventGroup(ctx context.Context, ev *repository.SecurityEvent) (string, error) {
	var id string
	err := g.db.QueryRow(ctx, `
		SELECT id FROM alert_groups
		WHERE tenant_id = $1
          AND COALESCE(project_id, '') = $4 AND COALESCE(stage, '') = $5
          AND group_key IN ($2, $3)
        ORDER BY (group_key = $2) DESC, updated_at DESC
		LIMIT 1
	`, ev.TenantID, eventGroupKey(ev), legacyEventGroupKey(ev), ev.ProjectID, eventStage(ev)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return id, nil
}
