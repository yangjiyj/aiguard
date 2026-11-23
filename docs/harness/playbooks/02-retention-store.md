# Retention Store

## 目标

把访问留存大内容从 Postgres 主路径拆出，数据库只保存证据对象的元数据和引用。

## 允许修改

- packages/shared-go/**
- apps/proxy-server/**
- apps/control-plane/**
- migrations/**
- docs/superpowers/plans/**
- docs/harness/runs/**

## 禁止修改

- apps/security-engine/**
- apps/web-console/**，除非目标契约明确要求展示对象引用
- 与留存无关的模型路由代码

## 输入

- 当前 `access_content_logs` 写入路径。
- 留存策略和租户隔离要求。
- 对象存储后端配置要求。

## 执行顺序

1. 定义 retention-store 接口和对象元数据结构。
2. 写本地文件后端测试，确认红灯。
3. 实现本地文件后端。
4. 定义 MinIO 配置边界，不把 SDK 接入扩散到业务代码。
5. 改造新增留存路径只写对象引用。
6. 跑 proxy-server、control-plane 和迁移验证。

## 验证命令

```bash
cd apps/proxy-server && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/control-plane && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
git diff --check
```

## 停止条件

- 无法保证租户隔离。
- 证据对象无法与请求、安全事件、告警追溯关联。
- 清理策略存在误删未过期证据的风险。

## 交付物

- retention-store 接口。
- 对象元数据模型。
- 新留存写入路径。
- 清理和追溯测试。
