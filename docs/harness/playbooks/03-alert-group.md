# Alert Group

## 目标

把原始安全事件和客户可处置告警分组拆开，避免控制台实时聚合原始事件。

## 允许修改

- apps/control-plane/**
- apps/worker/**
- migrations/**
- apps/web-console/**
- docs/superpowers/plans/**
- docs/harness/runs/**

## 禁止修改

- apps/gateway-core/**，除非目标契约要求调整事件发布字段
- apps/security-engine/**
- 与告警无关的模型供应商配置

## 输入

- 当前 `security_events` 和 `alert_inbox` 数据模型。
- 告警生命周期规格。
- 控制台告警页面交互要求。

## 执行顺序

1. 设计 alert group 表结构和索引。
2. 写 repository 单元测试，确认红灯。
3. 实现幂等聚合逻辑。
4. 用 worker 消费 security events 生成 alert groups。
5. 控制台读取 alert groups。
6. 验证误报、关闭、重开状态。

## 验证命令

```bash
cd apps/control-plane && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/worker && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/web-console && npm run build
git diff --check
```

## 停止条件

- 告警分组无法幂等。
- 误报、关闭、重开状态无法表达。
- 聚合主路径依赖不可索引 JSONB 字段。

## 交付物

- alert group 迁移。
- 聚合 worker。
- 控制台查询路径。
- 状态流转测试。
