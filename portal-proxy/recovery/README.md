# Portal Proxy 恢复记录

本目录记录 2026-08-08 的源码恢复边界。恢复目标是保全已经运行过的
Portal Proxy 业务实现，并把后续离线镜像改为从 JJDGuard 主仓源码构建。

## 恢复来源

- 确定镜像：`chat-portal/portal-proxy:0.1.0`
- 镜像 ID：`sha256:23fe08580b00c71339b0dbe3dd4dffc9a3e5a55654c4f0137c069e2830842edc`
- 镜像内文件：`/app/package.json`、`/app/pnpm-lock.yaml`、`/app/prisma/**`、`/app/dist/**`
- 原始会话：`a6414252-127b-4a09-a1b8-eec28a11a350`、
  `d1fcd50a-3d02-4e62-90c5-22b7a7de310b`
- 离线套壳证据会话：`019fb5d0-4fdc-72d3-af53-25fc3b757ee1`

镜像中的 35 个 JavaScript 模块原样保存在 `original-dist/`。当前
`src/**/*.ts` 是对应 JavaScript 文件的逐字节恢复副本，仅把扩展名从
`.js` 改为 `.ts`；这保证运行逻辑先完整保全，但不代表找回了原始的
TypeScript 类型标注。

原仓曾记录 `2656ec8`、`fa2ca4a`、`b3c70ff` 等提交号，但现有对象库中
已经找不到这些 Git 对象。因此本次只能准确称为「从确定镜像和原始会话
恢复源码」，不能称为恢复了原 Git 历史。

## 已保全内容

- 35 个服务端模块，共 3,122 行；
- 管理后台单页，共 975 行；
- Prisma schema 和 5 组迁移；
- `package.json` 与锁文件；
- 镜像内原始编译快照；
- 员工 Key、OIDC、部门映射、模型权限、三级角色、管理后台、告警、
  用量、Responses、Embeddings、模型别名和整站开关等业务逻辑。

## Git 外证据

以下材料保存在 home，权限为 `0600`，不会进入 Git 或客户离线包：

`/home/dev/jjdguard-deliverables/portal-proxy-recovery-20260808/evidence-v1/`

- 恢复前工作区归档 SHA-256：
  `f32d2909949535984ca17401d7077ade132bcdd2bbf4997158aea9c363feee5f`
- 原始镜像归档 SHA-256：
  `ad55c49454fa043f1c7f035847534376d5b904d1f06bc20eff31ab03d229df18`
- 三份原始会话及各自 SHA-256；
- 镜像 inspect、history 和逐文件 SHA-256 清单。

镜像中的 `prisma/dev.db` 只有 0 条 `EmployeeKey` 记录和 1 条迁移记录。
它仍属于运行态数据库，已进入 Git 外证据归档，并由 `.gitignore` 明确
排除，不能提交到源码仓。

## 可复现性边界

恢复提交只负责保全。只有在补齐 TypeScript 配置、测试、Dockerfile，
并完成源码构建产物与 `original-dist/` 对照后，才可以声明源码构建链已
恢复。离线包也必须通过仓库规定的 `package-offline-bundle.sh` 和验收门，
不能把本目录的镜像归档当成交付包。
