# Goal Contract: Retention Store

## Loop ID

20260618-retention-store

## Owner

产品/工程负责人：yj

## 目标

建立访问内容留存的 Retention Store V1，把附件、截图、base64 等大对象从 `access_content_logs.file_metadata_json` 的主写入路径拆出，Postgres 只保存可追溯、可清理、可审计的对象引用与元数据。

本轮优先交付统一接口、本地文件后端和 proxy 新增留存写入路径；MinIO/S3 只定义配置边界，不把 SDK 直接扩散到业务处理链路。

## 为什么现在做

Loop 1 已经建立 Worker + Event Bus 底座。继续堆同步日志和大对象到 Postgres，会让日志留存、告警聚合、审计查询在大规模客户场景里互相拖慢。Retention Store 是把“证据对象”与“查询索引”拆开的第一刀，也是后续告警分组和汇总读模型的前置条件。

## 允许修改

- packages/shared-go/**
- apps/proxy-server/**
- apps/control-plane/**
- deploy/migrations/**
- deploy/docker-compose/**
- docs/harness/runs/**
- docs/superpowers/plans/**

## 禁止修改

- apps/gateway-core/**
- apps/security-engine/**
- apps/web-console/**，除非只做对象引用兼容展示
- 与访问留存无关的模型路由、计费和认证代码
- go.work

## 输入

- 关联规格：`docs/superpowers/specs/2026-06-18-agent-security-gateway-product-architecture-design.md`
- 关联规格：`docs/superpowers/specs/2026-06-18-loop-harness-transformation-design.md`
- Playbook：`docs/harness/playbooks/02-retention-store.md`
- 当前写入路径：`apps/proxy-server/internal/handler/audit.go`
- 当前数据库结构：`deploy/migrations/061_access_retention.sql`

## 完成标准

- [x] `packages/shared-go/retentionstore` 定义对象元数据、写入接口、本地文件后端和路径隔离测试。
- [x] 本地文件后端写入时计算 `sha256`、`size`、`content_type`、`retention_until`，并阻止跨租户或路径穿越访问。
- [x] `apps/proxy-server` 的新增访问内容留存路径把附件 `data_base64` 写入 Retention Store，只在 `file_metadata_json` 保存对象引用和红acted 预览。
- [x] 新路径不把原始 base64、大正文或敏感附件内容写入 Postgres JSON。
- [x] 旧数据中已经存在的 `data_base64` 仍保持兼容，不阻断 control-plane 已有读取和测试。
- [x] 留存对象可以通过 tenant、request、stage、field、sha256 与原始请求链路追溯。
- [x] 失败时不影响代理请求主链路；留存失败只记录日志并保留红acted 元数据。

## 验证命令

```bash
scripts/harness/preflight.sh --goal docs/harness/runs/20260618-retention-store-goal-contract.md
scripts/harness/scope-check.sh --goal docs/harness/runs/20260618-retention-store-goal-contract.md
cd packages/shared-go && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/proxy-server && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/control-plane && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
git diff --check
git diff --cached --check
```

## 停止条件

- 无法保证 tenant 级对象路径隔离。
- 新写入路径仍会把附件原始 base64 放入 Postgres JSON。
- 对象引用无法与 request/security/alert 证据链关联。
- 清理策略存在误删未过期证据的风险。
- 需要引入对象存储 SDK 并扩散到 proxy 业务 handler。

## 证据

- Evidence directory: `.harness/runs/20260618-retention-store`

## 决策

- Decision: `complete`
- Reason: Retention Store V1、本地后端、proxy 对象引用写入路径、配置入口和 compose 留存卷已实现，并通过 shared-go、proxy-server、control-plane 与 Harness 验证。

## 经验回灌

- 本地后端必须在 key 层携带 tenant/request/stage/field，同时在读取和删除时校验 tenant 前缀，避免对象路径被跨租户复用。
- proxy 落库前一律清空 `data_base64`：store 成功时写对象引用，store 未配置或失败时写 `retention_status` 降级状态，不把原始字节放回 Postgres。
- read-only 容器需要显式挂载 retention-data 卷，否则本地 store 无法在生产形态中落对象。
