# Goal Contract: Worker + Event Bus

## Loop ID

20260618-worker-event-bus

## Owner

产品/工程负责人：yj

## 目标

建立 `JJDGUARD` 的 Worker + Event Bus V1 底座，为运行时审计事件、访问留存事件、告警派生和汇总读模型提供异步处理入口。

本轮只交付底座，不迁移现有 gateway/proxy/control-plane 的同步审计写入路径。

## 为什么现在做

产品架构规格已经明确运行时网关不能同步承担日志留存、告警聚合和报表统计。Loop 0 已经建立 Harness 控制面，下一轮必须先补齐 `apps/worker` 和事件接口，否则后续 Retention Store、Alert Group、Rollup Read Model 都没有统一异步入口。

## 允许修改

- apps/worker/**
- packages/shared-go/**
- deploy/docker-compose/**
- docs/harness/runs/**
- docs/superpowers/plans/**

## 禁止修改

- apps/gateway-core/**
- apps/proxy-server/**
- apps/control-plane/**，除非只修改与 worker 运行说明相关的文档
- apps/web-console/**
- apps/security-engine/**
- migrations/**
- go.work

## 输入

- 关联规格：`docs/superpowers/specs/2026-06-18-agent-security-gateway-product-architecture-design.md`
- 关联规格：`docs/superpowers/specs/2026-06-18-loop-harness-transformation-design.md`
- Playbook：`docs/harness/playbooks/01-worker-event-bus.md`
- 现状：`apps/worker` 当前只有 `go.mod`

## 完成标准

- [x] `packages/shared-go/eventbus` 定义事件 envelope、验证规则和 publisher 接口。
- [x] Redis Streams 发布适配器具备单元测试，不把大正文/base64 放入事件体。
- [x] `apps/worker/cmd/worker` 可以启动、读取配置、响应 SIGTERM。
- [x] `apps/worker` 有配置测试和可运行的 `go test ./...`。
- [x] `deploy/docker-compose/docker-compose.yml` 包含 worker 服务，默认连接同一 PostgreSQL 与 Redis。
- [x] 本轮不改动 gateway/proxy/control-plane 的业务写入路径。

## 验证命令

```bash
scripts/harness/preflight.sh --goal docs/harness/runs/20260618-worker-event-bus-goal-contract.md
scripts/harness/scope-check.sh --goal docs/harness/runs/20260618-worker-event-bus-goal-contract.md
cd packages/shared-go && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/worker && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/worker && PATH=/usr/local/go/bin:$PATH GOWORK=off go build -o /tmp/newapi-worker ./cmd/worker
git diff --check
git diff --cached --check
```

## 停止条件

- 需要迁移 gateway/proxy/control-plane 热路径审计写入。
- 事件模型无法表达 request、security、access 三类事实的公共字段。
- worker 失败会影响现有 gateway 请求。
- 需要新增业务数据库迁移。
- 需要引入非 Go 标准库和现有 Redis 客户端之外的新运行时依赖。

## 证据

- Evidence directory: `.harness/runs/20260618-worker-event-bus`

## 决策

- Decision: `complete`
- Reason: Worker + Event Bus V1 已完成事件 envelope、Redis Streams publisher、worker 启动/config/SIGTERM、compose 服务接入和范围约束验证；本轮未迁移 gateway/proxy/control-plane 的业务写入路径。

## 经验回灌

- 事件 envelope 必须拒绝大正文和 base64 形态 payload，事件总线只承载事实索引与可追溯字段。
- Worker V1 先交付启动、配置和生命周期底座，后续 Retention Store、Alert Group、Rollup Read Model 可以在此基础上接入异步消费。
- 最终验证：Harness preflight/scope-check、`packages/shared-go go test ./...`、`apps/worker go test ./...`、worker build、diff check 均通过。
