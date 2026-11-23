# Worker + Event Bus

## 目标

建立 `apps/worker` 一等服务和事件总线接口，让运行时审计、告警派生和汇总任务进入异步处理链路。

## 允许修改

- apps/worker/**
- packages/shared-go/**
- deploy/docker-compose/**
- docs/superpowers/plans/**
- docs/harness/runs/**

## 禁止修改

- apps/web-console/**
- apps/security-engine/**
- migrations/** 之外的无关数据库结构

## 输入

- 产品架构规格。
- 事件模型目标契约。
- 当前 control-plane 后台任务清单。

## 执行顺序

1. 定义事件 envelope 与 publisher/consumer 接口。
2. 为接口写单元测试，确认红灯。
3. 实现 Redis Streams V1。
4. 创建 `apps/worker/cmd/worker`。
5. 增加 worker 启动配置和 docker-compose 服务。
6. 跑 worker、shared-go 和 compose 配置验证。

## 验证命令

```bash
cd apps/worker && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd packages/shared-go && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
git diff --check
```

## 停止条件

- 事件模型无法覆盖 request、security、access 三类事实。
- 消费失败会直接导致 gateway 请求失败且无配置控制。
- 需要一次性重写 gateway 热路径。

## 交付物

- worker 服务入口。
- 事件接口与测试。
- Redis Streams 实现。
- 部署配置变更。
