# Portal Proxy

Portal Proxy 是 JJDGuard 企业 AI 门户的服务端代理。它位于门户后端与
JJDGuard 网关之间，负责可信身份归因、员工专属网关 Key 映射、部门与
模型权限收窄，以及 OpenAI 兼容数据面的受控转发。

## 主要能力

- 校验门户内部 Token，只接受可信服务注入的直接身份；
- 兼容历史 `body.user` 与 Responses API 的 `safety_identifier` 归因；
- 使用 AES-256-GCM 加密保存员工网关 Key，明文不落库、不进日志；
- 按部门规则映射网关项目，支持员工、部门主管、管理员三级角色；
- 只转发 `/v1/chat/completions`、`/v1/responses`、`/v1/embeddings`；
- 提供 OIDC 管理入口、用量看板、安全告警和系统开关；
- `chat_portal_enabled` 获取失败时按关闭处理。

## 本地验证

需要 Node.js 22 和 Corepack。不要使用真实 Token 或生产数据库验证。

```bash
corepack pnpm install --frozen-lockfile
DATABASE_URL=file:/tmp/portal-proxy-verify.db corepack pnpm run verify
```

`verify` 会依次生成 Prisma Client、执行 TypeScript 类型检查、运行单元
测试并生成 `dist/`。`dist/`、`node_modules/` 和本地 SQLite 数据库均被
忽略，不能提交到 Git。

## 运行配置

运行时至少需要以下环境变量：

- `DATABASE_URL`
- `PORTAL_INTERNAL_TOKEN`
- `PORTAL_KEY_ENC_SECRET`
- `NEWAPI_PORTAL_API_SECRET`
- `LOBE_DATABASE_URL`

OIDC、租户、默认项目、模型别名和管理后台开关等可选变量，以
`src/config.ts` 为准。所有密钥只能从部署环境注入，禁止写入源码、镜像
层或日志。

## 镜像构建

```bash
docker build -t chat-portal/portal-proxy:0.1.0 .
```

Dockerfile 在 `build` 阶段从 `src/` 编译，在 `runtime` 阶段只安装生产
依赖并复制新生成的 `dist/`。`recovery/` 保存的旧编译快照不会进入构建
上下文，也不能作为新镜像的种子。

客户离线包必须从 JJDGuard `main` 分支运行
`deploy/docker-compose/package-offline-bundle.sh`，并通过内置漂移审计和
隔离安装验收门。禁止手工 `docker save` 拼客户交付包。

## 当前源码与历史恢复边界

本目录是当前可发布的 Portal Proxy 权威源码：离线构建只从 JJDGuard 主仓
的已验证 Git revision/tree 取 Dockerfile、上下文、锁文件和测试。归属、
当前仓库锚点，以及历史恢复证据见 `SOURCE-ATTESTATION.json`；专有使用边界
见 `LICENSE`。

历史独立仓库的 Git 对象已不可恢复。当前基线由原始用户工作区会话和确定
镜像保全后正式纳入主仓，因此不会把它表述为找回了原 Git 历史；完整历史
证据、SHA-256 和恢复范围见 `recovery/README.md`。
