# Harness Bootstrap

## 目标

建立仓库内 Loop/Harness V1 控制面，包括协议、模板、playbook、检查脚本和运行证据忽略规则。

## 允许修改

- docs/harness/**
- scripts/harness/**
- .gitignore
- docs/superpowers/plans/**

## 禁止修改

- apps/**
- packages/**
- deploy/**
- migrations/**
- go.work

## 输入

- `docs/superpowers/specs/2026-06-18-loop-harness-transformation-design.md`
- `docs/superpowers/plans/2026-06-18-harness-bootstrap.md`

## 执行顺序

1. 写脚本自测并确认红灯。
2. 创建 Harness 文档、模板和 playbook。
3. 创建 preflight、scope-check、evidence、verify 脚本。
4. 更新 `.gitignore` 忽略 `.harness/runs/`。
5. 运行脚本自测、Harness 总体验证和 `git diff --check`。
6. 更新计划复选框并提交。

## 验证命令

```bash
bash scripts/harness/tests/test_harness_scripts.sh
scripts/harness/verify.sh harness
git diff --check
```

## 停止条件

- 需要修改业务代码。
- 需要引入新服务或第三方依赖。
- 脚本会删除、移动或重写用户文件。
- 验证失败且无法在 docs/scripts 范围内修复。

## 交付物

- `docs/harness/**`
- `scripts/harness/**`
- `.gitignore`
- 更新后的实现计划
