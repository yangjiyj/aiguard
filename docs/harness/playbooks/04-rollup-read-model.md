# Rollup Read Model

## 目标

把成本、用量、风险和访问趋势从实时扫大表改为汇总读模型。

## 允许修改

- apps/control-plane/**
- apps/worker/**
- apps/web-console/**
- migrations/**
- docs/superpowers/plans/**
- docs/harness/runs/**

## 禁止修改

- apps/security-engine/**
- 运行时阻断逻辑
- 上游供应商凭证处理逻辑

## 输入

- 当前 dashboard、访问留存、成本治理统计查询。
- 请求量、保留周期和控制台性能目标。

## 执行顺序

1. 定义 hourly/daily rollup 表。
2. 写 rollup repository 测试，确认红灯。
3. 实现增量更新和补偿逻辑。
4. worker 定时刷新 rollup。
5. 控制台统计卡片读取 rollup。
6. 大导出改为异步任务入口。

## 验证命令

```bash
cd apps/control-plane && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/worker && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/web-console && npm run build
git diff --check
```

## 停止条件

- 汇总结果无法追溯到原始请求。
- 查询接口仍默认全量 COUNT 大表。
- 增量任务不具备幂等补偿能力。

## 交付物

- rollup 表和索引。
- worker 汇总任务。
- 控制台读模型切换。
- 查询性能证据。
