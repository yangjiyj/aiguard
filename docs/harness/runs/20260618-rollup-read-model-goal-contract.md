# Goal Contract: Rollup Read Model

## Loop ID

20260618-rollup-read-model

## Owner

产品/工程负责人：yj

## 目标

建立 Rollup Read Model V1，把控制台高频统计从实时扫描 `request_logs`、`security_events` 和访问留存明细，迁到按小时汇总的可索引读模型。

本轮优先覆盖用量/成本看板与访问留存 summary。明细列表仍保留按条件分页读取原始表；大导出只定义异步入口边界，不在本轮实现完整导出队列。

## 为什么现在做

Loop 2 已把大对象留存从 Postgres 主路径拆出，Loop 3 已把告警运营主列表切到 alert groups。剩余大规模瓶颈集中在控制台统计：用量、成本、访问趋势和风险分布如果继续实时 `COUNT/GROUP BY` 大表，会在客户数据量增长后拖慢首页、费用页和留证页。

## 允许修改

- `deploy/migrations/**`
- `apps/control-plane/**`
- `apps/worker/**`
- `apps/web-console/**`
- `docs/harness/runs/**`
- `docs/superpowers/plans/**`

## 禁止修改

- `apps/security-engine/**`
- 运行时阻断逻辑
- 上游供应商凭证处理逻辑
- `apps/gateway-core/**`
- `apps/proxy-server/**`
- `go.work`

## 输入

- Playbook：`docs/harness/playbooks/04-rollup-read-model.md`
- 用量/成本实时统计：`apps/control-plane/internal/repository/usage_governance.go`
- 访问留存 summary：`apps/control-plane/internal/repository/forward_proxy_access.go`
- worker 启动入口：`apps/worker/cmd/worker/main.go`
- 控制台费用页：`apps/web-console/src/pages/Usage.tsx`
- 控制台留证页：`apps/web-console/src/pages/AccessRetention.tsx`

## 完成标准

- [x] 新增 hourly rollup 表，覆盖用量/成本和访问留存 summary 所需指标，并具备 tenant、bucket_start 和维度索引。
- [x] rollup repository 支持幂等刷新同一时间桶，重复刷新不会重复计数。
- [x] refresh 逻辑可按时间窗口补偿，支持从原始 `request_logs` 重新计算并 upsert rollup。
- [x] worker 提供周期刷新入口，控制面仍可在测试中直接调用 refresh 服务。
- [x] 用量/成本 summary 与主要维度接口优先读取 rollup，不再默认实时聚合 `request_logs`。
- [x] 访问留存 summary 优先读取 access rollup；明细列表仍分页读取原始表。
- [x] web-console 保持现有客户可读展示，不暴露 rollup 表名、bucket id 或内部工程字段。
- [x] 大导出只保留为后续异步任务入口设计，不阻塞本轮闭环。

## 验证命令

```bash
scripts/harness/preflight.sh --goal docs/harness/runs/20260618-rollup-read-model-goal-contract.md
scripts/harness/scope-check.sh --goal docs/harness/runs/20260618-rollup-read-model-goal-contract.md
cd apps/control-plane && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/worker && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/web-console && npm run build
git diff --check
git diff --cached --check
```

## 停止条件

- rollup 结果无法追溯到原始请求窗口。
- 同一时间桶重复刷新会重复计数。
- 查询接口仍默认对大表执行无界 `COUNT` 或大范围 `GROUP BY`。
- worker 刷新任务没有 tenant/time window 边界。
- 控制台需要展示内部 rollup 工程字段才能使用。

## 证据

- Evidence directory: `.harness/runs/20260618-rollup-read-model`

## 决策

- Decision: `complete`
- Reason: Rollup Read Model V1 已完成用量/成本与访问留存 summary 的 hourly 读模型迁移、幂等窗口刷新、worker 周期入口和客户可读新鲜度展示；明细检索与完整异步导出保持在 V1 边界外。

## 经验回灌

- 2026-06-18 完成 Rollup Read Model V1：新增 `usage_rollup_hourly`、`access_rollup_hourly` 读模型，refresh service 支持窗口重刷，worker 周期刷新入口可通过 `ROLLUP_REFRESH_INTERVAL=0` 关闭。
- 用量/成本 summary 与主要维度接口、访问留存 summary 已切换为 rollup 优先，legacy 查询保留为空数据兜底；明细列表和大对象留存路径不在本轮扩改。
- web-console 只展示客户可理解的“数据更新至”，不暴露 rollup 表名、bucket id 或内部刷新字段；空 summary 用 0 值兜底。
- 最终验证：`scripts/harness/preflight.sh --goal docs/harness/runs/20260618-rollup-read-model-goal-contract.md`、`scripts/harness/scope-check.sh --goal docs/harness/runs/20260618-rollup-read-model-goal-contract.md`、`cd apps/control-plane && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...`、`cd apps/worker && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...`、`cd apps/web-console && npm run build` 均通过。
