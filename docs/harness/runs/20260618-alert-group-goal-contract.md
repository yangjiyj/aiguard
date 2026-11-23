# Goal Contract: Alert Group

## Loop ID

20260618-alert-group

## Owner

产品/工程负责人：yj

## 目标

建立客户可处置的 Alert Group V1，把 `security_events` 原始证据日志、`alert_inbox` 通知收件箱和控制台告警视图拆开。

本轮交付可幂等聚合、可关闭、可误报标记、可重开的告警组读模型，避免控制台在大规模场景中实时扫描和聚合原始安全事件。

## 为什么现在做

Loop 2 已经把大对象留存从 Postgres 主路径拆出。下一步瓶颈会出现在告警侧：原始事件数量会随请求量线性增长，客户真正需要处理的是“同一风险的一组发生记录”，不是每条 `security_events`。Alert Group 是告警降噪、通知节流、SLA 和运营处置的产品边界。

## 允许修改

- deploy/migrations/**
- apps/control-plane/**
- apps/worker/**
- apps/web-console/**
- docs/harness/runs/**
- docs/superpowers/plans/**

## 禁止修改

- apps/gateway-core/**，除非目标契约补充要求事件发布字段
- apps/proxy-server/**
- apps/security-engine/**
- packages/shared-go/**，除非仅复用已有 eventbus/db helper
- 与告警无关的模型供应商配置、认证和计费代码
- go.work

## 输入

- Playbook：`docs/harness/playbooks/03-alert-group.md`
- 当前原始事件表：`security_events`
- 当前通知收件箱：`alert_inbox`
- 当前桥接逻辑：`apps/control-plane/internal/alert/secevent_bridge.go`
- 当前控制台页：`apps/web-console/src/pages/UnifiedAlerts.tsx` 和 `AlertInbox.tsx`

## 完成标准

- [x] 新增 `alert_groups` 迁移，包含 tenant、group_key、severity、status、occurrence_count、first_seen、last_seen、representative_event_id、body_json 和可索引字段。
- [x] 聚合逻辑对同一 group_key 幂等，重复事件只更新同一 open group 的次数和 last_seen。
- [x] 告警组支持 `open`、`acknowledged`、`resolved`、`false_positive`，且已关闭告警再次命中可重开或新建。
- [x] worker 或可迁移到 worker 的聚合入口负责从 `security_events` 生成/更新 `alert_groups`，control-plane 不再依赖控制台实时聚合原始事件。
- [x] control-plane 提供 alert group 列表、详情和状态流转 API，并保持租户隔离。
- [x] web-console 告警页读取 alert group 读模型，详情页再按需读取原始事件证据。
- [x] 既有 `alert_inbox` 保留为通知/消息中心，不再承载主要告警分组语义。

## 验证命令

```bash
scripts/harness/preflight.sh --goal docs/harness/runs/20260618-alert-group-goal-contract.md
scripts/harness/scope-check.sh --goal docs/harness/runs/20260618-alert-group-goal-contract.md
cd apps/control-plane && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/worker && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/web-console && npm run build
git diff --check
git diff --cached --check
```

## 停止条件

- 聚合 key 无法稳定复现，导致重复告警无法幂等。
- 状态流转无法表达误报、关闭、重开。
- 查询主路径依赖不可索引 JSONB 扫描。
- control-plane/API 无法证明 tenant 隔离。
- web-console 需要暴露内部工程字段才能使用。

## 证据

- Evidence directory: `.harness/runs/20260618-alert-group`

## 决策

- Decision: `complete`
- Reason: Alert Group V1 已完成迁移、幂等聚合、租户隔离 API、web-console 读模型接入和旧留存查询门控；最新 HEAD 通过本契约验证命令。

## 经验回灌

- 2026-06-18 验证通过：preflight、scope-check、control-plane `go test ./...`、worker `go test ./...`、web-console `npm run build`、`git diff --check`、`git diff --cached --check`。
- 当前聚合入口落在 control-plane bridge，已通过 repository 和接口边界隔离；后续可平滑迁到 worker 消费事件总线。
- web-console 有 alert groups 时不再触发旧 access-retention 风险/阻断查询，仅在空读模型时兜底，避免告警运营主路径压原始日志表。
