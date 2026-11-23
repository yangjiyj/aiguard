# Goal Contract

## Loop ID


## Owner


## 目标


## 为什么现在做


## 允许修改

- path/prefix/**

## 禁止修改

- apps/**
- packages/**
- deploy/**
- migrations/**
- go.work

## 输入

- 关联规格：
- 关联计划：
- 相关截图或证据：

## 完成标准

- [ ] 标准 1
- [ ] 标准 2

## 验证命令

```bash
scripts/harness/preflight.sh --goal <this-file>
scripts/harness/verify.sh harness
git diff --check
```

## 停止条件

- 范围超出允许修改路径。
- 验证失败且无法在本轮边界内修复。
- 需要修改安全敏感路径但没有补充验证命令。
- 发现密钥、客户数据或大文件可能进入 git。

## 证据

- Evidence directory:

## 决策

- Decision: `pass | continue | rollback | handoff`
- Reason:

## 经验回灌
