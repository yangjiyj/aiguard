# Gateway Hot Path Split

## 目标

拆分 `chat_completions.go` 的运行时职责，降低鉴权、路由、安全、审计和响应处理的耦合。

## 允许修改

- apps/gateway-core/**
- packages/shared-go/**
- docs/superpowers/plans/**
- docs/harness/runs/**

## 禁止修改

- apps/control-plane/**，除非目标契约要求新增接口适配
- apps/web-console/**
- apps/security-engine/**
- 客户 API 响应结构的不兼容变更

## 输入

- 当前 `/v1/chat/completions` 行为。
- 网关热路径拆分目标。
- 现有鉴权、路由、安全和审计测试。

## 执行顺序

1. 为当前行为补回归测试。
2. 提取 request parsing。
3. 提取 runtime context builder。
4. 提取 routing decision。
5. 提取 policy/security adapter。
6. 提取 audit publisher 和 response finalizer。
7. 逐步保持测试绿灯。

## 验证命令

```bash
cd apps/gateway-core && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/gateway-core && PATH=/usr/local/go/bin:$PATH GOWORK=off go build -o /tmp/newapi-gateway-core ./cmd/server
git diff --check
```

## 停止条件

- 需要同时修改多个模型 API 入口。
- 现有客户 API 返回结构不兼容。
- 无法用测试证明行为保持一致。

## 交付物

- 拆分后的热路径组件。
- 回归测试。
- 行为兼容证据。
