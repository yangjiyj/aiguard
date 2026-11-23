# Loop/Harness

本目录是 `JJDGUARD` 的工程控制面。所有高风险、多模块、长周期改造都必须先写目标契约，再执行 Loop。

Loop 的目标不是让 Agent 多跑几轮，而是让每一轮都有边界、证据、停止条件和经验回灌。

## 执行顺序

1. 复制 `templates/goal-contract.md` 填写目标契约。
2. 用 `scripts/harness/preflight.sh --goal <file>` 做开始前检查。
3. 按 playbook 编写 Loop 计划。
4. 执行任务并用 `scripts/harness/evidence.sh <loop-id>` 采集证据。
5. 用 `scripts/harness/verify.sh <module>` 运行验证。
6. 填写停止决策与经验回灌。

## 核心文件

- `loop-protocol.md`：Loop 生命周期、角色和停止决策。
- `templates/goal-contract.md`：每轮执行前必须填写的目标契约。
- `templates/loop-plan.md`：把目标拆成可验证步骤的计划模板。
- `templates/evidence-report.md`：证据摘要模板。
- `templates/stop-decision.md`：继续、通过、回滚或交给人的决策模板。
- `templates/retrospective.md`：经验回灌模板。
- `playbooks/`：针对具体改造领域的执行手册。

## 运行证据

原始运行证据放在 `.harness/runs/<loop-id>/`，该目录不入库。需要长期沉淀的摘要写到 `docs/harness/runs/<loop-id>-summary.md`。

证据摘要不得保存密钥、客户请求正文、原始大日志、截图原图或数据库敏感数据。

## 默认停止条件

以下情况必须停止当前 Loop：

- 改动超出目标契约允许范围。
- 验证命令失败且无法在本轮边界内修复。
- 需要修改安全敏感路径但目标契约没有验证命令。
- 发现密钥、客户数据或大文件可能进入 git。
- 需要人判断产品语义、客户呈现或安全边界。

## 与现有规则关系

Harness 不替代 `AGENTS.md`、TDD、完成前验证或中文提交规范。它把这些规则组织成可复用的工程闭环。
