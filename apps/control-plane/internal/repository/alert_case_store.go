package repository

import (
	"os"
	"strings"
	"time"
)

// ── 告警排查问题（案件）物化 ───────────────────────────────────────────────────
//
// 迁移 1002/1003 建了 alert_case_members（每条命中一行）、alert_cases（每个案件按 all / customer 两种范围
// 各一行）、alert_case_dirty（待重算队列，由触发器写入）、alert_case_backfill（历史回填进度）。
//
// 口径：命中行由 buildAlertOccurrenceQuery 的同一段 SQL（events → … → keyed）算出，只是限定到要重算的事件；
// 案件聚合与实时查询的 case_totals / case_novelty / case_representatives / case_review 逐项对应；读的时候把
// 物化结果拼成实时查询里的 case_rows（或命中视图的 keyed），后面的车道窗口、处置页签、分页、投影、计数
// 原样复用实时查询的 SQL。等价测试见 alert_case_store_test.go。
//
// 只有两类读走物化表：按案件分组的列表/汇总/处置授权，以及单个案件的命中明细；并且请求里不带只作用于部分
// 命中的筛选（事件、请求、会话键、会话、用户）。其余读法照旧实时查询。截止时间（end_time）落在某个案件的
// 时间跨度里时，这个案件按截止时间之前的命中现场重聚合，结果与实时查询一致。

// alertCaseStoreOff：JJD_ALERT_CASE_STORE=off（现场紧急回退）时告警读一律实时查询、处置后不同步消化。启动时读一次。
var alertCaseStoreOff = strings.EqualFold(strings.TrimSpace(os.Getenv("JJD_ALERT_CASE_STORE")), "off")

const (
	// 处置授权（要判断“有无新证据”）读之前必须把队列消化完；超过这个数就改走实时查询，由后台任务慢慢消化。
	alertCaseReadBacklogLimit = 2000
	// 列表、汇总、命中明细读之前在这个时间内按小批消化队列（只取事件、请求、处置条目，最新登记的先消化）；
	// 下一块预计放不进预算就停，没消化完的（大批量写入、凭据改标记、告警组状态等）留给后台，本次读用已物化
	// 的结果，最多落后几秒。积压超过 alertCaseStaleLimit 时改走实时查询。一块 25 条约 0.1 秒（670 万条正文的量级）。
	alertCaseReadDrainBudget = 150 * time.Millisecond
	alertCaseReadDrainChunk  = 25
	alertCaseStaleLimit      = 20000
	// 处置授权读前消化：等租户锁最多 alertCaseExactLockWait，总共最多 alertCaseExactDrainBudget、最多
	// alertCaseExactDrainRounds 批，超出就用实时查询授权。
	alertCaseExactLockWait    = time.Second
	alertCaseExactDrainBudget = time.Second
	alertCaseExactDrainRounds = 20
	// 历史回填每批事件数（每批一个事务）。
	alertCaseBackfillBatch = 500
	// 处置后同步消化每条语句的上限。
	alertCaseSyncStatementTimeout = 2 * time.Second
	// 同类日志（读前消化失败、隔离条目等）每个租户最多每这么久记一条。
	alertCaseLogInterval = 5 * time.Minute
	// 用物化表前的可用性检查（表、触发器摘要）结果在进程内缓存这么久。
	alertCaseStoreCheckTTL = 3 * time.Second
	// alertCaseReadSmallFanout 是读前消化（以及处置后同步消化）也顺带处理的告警组、凭据条目的事件数上限。
	alertCaseReadSmallFanout = 200
	// alertCaseSyncLockWait 是处置后同步消化等租户锁的上限；后台这一块还没做完就把条目留给后台。
	alertCaseSyncLockWait = 3 * time.Second
)

// 后台按批消化（变量便于测试调小）：窄条目每批最多 alertCaseBackgroundNarrowBatch 条；告警组、凭据条目展开后的
// 事件每个事务最多 alertCaseBackgroundEventBatch 条（670 万条正文的量级下约 1 秒以内持锁）。隔离的坏条目每隔
// alertCaseQuarantineRetryAfter 重试一次。
var (
	alertCaseBackgroundNarrowBatch = 200
	alertCaseBackgroundEventBatch  = 400
	alertCaseQuarantineRetryAfter  = 10 * time.Minute
)
