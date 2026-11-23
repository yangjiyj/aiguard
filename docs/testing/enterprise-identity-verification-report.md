# 企业身份、Chat 登录与统一部门归属 — 最终验证报告

> 任务 14（收官任务）交付物。本报告记录 14 个任务 / 4 个检查点（A/B/C/D）全部完成后的全量验证、安全自查与变更范围证据。
>
> 本报告区分任务 13 已完成的真实实验室验收与任务 14 新鲜执行的文档收口门禁。任务 14 不伪造未重跑项目的时间戳或耗时。
> 所有验证均在隔离环境完成，不触碰客户或生产。

## 1. 执行摘要

| 维度 | 状态 |
|------|------|
| 14 个任务交付 | 全部完成 |
| 4 个检查点（A/B/C/D） | 全部通过 |
| 后端 Go 测试 | 核心四包、race、vet、build 和 `go test -count=1 ./...` 全部 PASS |
| web-console 测试（本功能文件） | 6 文件 58 测试全绿 |
| web-console 全量观察与归因 | fresh 四分片完整覆盖 67 文件、526 测试；518 pass、8 fail，另有 1 个 unhandled error，失败均在本功能未修改文件，未完成精确基线归因 |
| web-console 构建 | 成功 |
| enterprise-ai-portal 单元测试 | 113 tests / 112 pass / 0 fail / 1 todo |
| enterprise-ai-portal lint | PASS |
| enterprise-ai-portal 构建 | 成功，13/13 pages |
| 隔离 PG16 身份 DB gate | 迁移到 137；16 个精确测试全部 PASS，0 skip |
| 真实 identity-lab | mandatory；真实 `up -> smoke -> down` 已完成，AP1–AP10 10/10 PASS |
| 安全自查 | LDAP 出站、filter、最小角色、发布补偿等收口项已关闭 |
| 部署/客户状态 | 未 push、未 merge、未部署、未重启、未修改客户或生产 |

**结论**：代码与隔离实验室证据达到交付候选状态。后端和 Portal 门禁通过；web-console 已 fresh 完整覆盖全量测试，但仍有 8 项失败和 1 个 unhandled error 未完成精确基线归因，因此不得表述为全量全绿。真实客户 AD/LDAP 联调和生产验收尚未执行，不能把实验室通过表述为客户或生产通过。

## 2. 测试证据

### 2.1 步骤 1：fmt + vet（apps/control-plane）

```
$ /usr/local/go/bin/go fmt ./internal/identitybinding ./internal/localidentity ./internal/handler ./internal/repository ./internal/permission ./internal/directoryruntime
# fmt 对本功能范围内的 .go 文件无修改需求（输出文件名均为非本功能文件，
# 系 main 既有格式漂移；本任务已还原所有非本功能修改，工作树 clean）

$ GOFLAGS=-buildvcs=false /usr/local/go/bin/go vet ./...
# exit 0，无输出
```

**注意**：规格步骤 1 用包路径 `./internal/handler` 等做 fmt 范围，会触及包内非本功能文件（main 既有格式漂移）。本任务只保留本功能范围内的格式修正，已 `git checkout` 还原 55 个非本功能文件，最终工作树对本功能文件零修改（本功能文件本就符合 gofmt）。这一处理满足步骤 6 "无无关修复" 的硬要求。

### 2.2 步骤 2：后端全量测试（apps/control-plane，隔离 PG16）

环境变量：`CONTENT_LOGS_TEST_DATABASE_URL` / `AGENTGUARD_TEST_DATABASE_URL` / `RULES_TEST_DATABASE_URL` 均指向隔离 PG16 容器（迁移应用到 137）。

**核心四包串行验证**：

```
$ GOFLAGS=-buildvcs=false /usr/local/go/bin/go test -p 1 -count=1 \
    ./internal/identitybinding ./internal/repository ./internal/handler ./cmd/server
ok  internal/identitybinding  0.045s
ok  internal/repository       61.803s
ok  internal/handler          5.600s
ok  cmd/server                0.009s
```

**race、全量测试和构建**：

```
$ GOFLAGS=-buildvcs=false /usr/local/go/bin/go test -race -count=1 ./internal/identitybinding
ok  internal/identitybinding

$ GOFLAGS=-buildvcs=false /usr/local/go/bin/go test -count=1 ./...
# exit 0，全部 PASS

$ GOFLAGS=-buildvcs=false /usr/local/go/bin/go build -buildvcs=false ./cmd/server
# exit 0；生成的 apps/control-plane/server 已在验收后删除
```

**单调 revision 最终收口 fresh 验证**：

```
$ /usr/local/go/bin/go test -count=1 ./internal/permission ./internal/identitybinding \
    ./internal/repository ./internal/handler ./cmd/server
# 五包全部 PASS

$ /usr/local/go/bin/go test -race -count=1 ./internal/identitybinding
# PASS

$ /usr/local/go/bin/go build -buildvcs=false ./cmd/server
# exit 0；生成的 apps/control-plane/server 已删除

$ ./scripts/identity-db-test-test.sh
PASS: identity DB container ownership and concurrency cleanup
```

**任务 14 新鲜隔离 DB gate**：

```
$ make identity-db-test
PASS: identity DB exact tests=16 skipped=0
```

该 target 每次创建唯一名称的 `postgres:16` 容器，owner label 为
`com.jjdguard.identity-db-test.owner=<nonce>`；只在容器 label 精确匹配本次
nonce 时清理，拒绝复用同名容器。迁移 runner 从干净基线应用到本分支最终版
`137_enterprise_identity_department.sql`，随后以 `JJD_REQUIRE_IDENTITY_DB_TESTS=1`
运行 16 个精确测试，并解析 `go test -json`，任何 skip 或缺失 PASS 都会失败。
本次命令通过后，owner label 过滤结果为空，无残留测试容器。

新增的真实 PostgreSQL 用例不使用 fake store：首次 `EnsurePortalUser` 返回值必须
等于 trigger 持久化的正 revision；人工部门更新后再次 Ensure 必须返回不同的新
revision；随后 authorization-context 必须返回完全相同的新值。A→B→A 即使复用
同一个 `department_resolved_at`，三次 BIGINT revision 仍各不相同。

另两条真实 PostgreSQL 回归覆盖目录激活错误边界：仍出现在 preview 中的账号即使
发生单条 `ErrInvalidIdentity`，也会保留 seen stable ID、计为 conflict 且不会被
误禁用；未分类或存储层 `BindAndResolve` 错误会终止激活，并将 sync run 标为
`failed/activation_link_failed`，并在同一事务释放 preview activation claim，
不会以成功状态继续 finalize。恢复后同一 preview 可重试成功，且没有 running run
残留。

**只读审查门禁**：

- 最终规格复审覆盖 `63b1af3..d33ee519`：Critical / Important / Minor 剩余项均为 0，
  结论 `SPEC COMPLIANT`。
- 独立代码质量复审覆盖同一范围：Critical / Important / Minor 剩余项均为 0，
  结论 `QUALITY APPROVED`。

### 2.3 步骤 3：web-console

**本功能测试文件（6 文件 58 测试全绿）**：

```
$ npx vitest run src/test/directory-preview.test.tsx src/test/identity-sources.test.tsx \
    src/test/layout-menu.test.tsx src/test/organizations-units.test.tsx \
    src/test/user-detail-drawer.test.tsx src/test/users-page.test.tsx
 Test Files  6 passed (6)
      Tests  58 passed (58)
# exit 0
```

**全量四分片 fresh 结果**：

仓库配置 `fileParallelism: false`，单条 `npm test` 在此前验证中运行超过 20 分钟，未得到完整摘要。为避免把工具超时误报为测试结论，本轮使用 Vitest 4.1.7 原生 shard，在 `apps/web-console` 中串行执行四个互斥分片：

```
npx vitest run --shard=1/4 --reporter=dot
npx vitest run --shard=2/4 --reporter=dot
npx vitest run --shard=3/4 --reporter=dot
npx vitest run --shard=4/4 --reporter=dot
```

| 分片 | 文件 | tests | pass | fail | unhandled errors | exit | duration |
|------|------|-------|------|------|------------------|------|----------|
| 1/4 | 17 | 113 | 112 | 1 | 0 | 1 | 485.76s |
| 2/4 | 17 | 140 | 138 | 2 | 0 | 1 | 478.32s |
| 3/4 | 17 | 145 | 140 | 5 | 1 | 1 | 877.83s |
| 4/4 | 16 | 128 | 128 | 0 | 0 | 0 | 282.90s |
| 合计 | 67 | 526 | 518 | 8 | 1 | — | 2124.81s |

fresh 失败分布：

- `src/test/model-management.test.tsx`：1 项 60 秒超时；
- `src/test/content-audit-detail.test.tsx`：1 项 60 秒超时；
- `src/test/unified-alerts.test.tsx`：1 项断言失败；
- `src/test/agentguard.test.tsx`：4 项超时，并产生 1 个 `MutationObserver is not a constructor` unhandled rejection；
- `src/test/models-sync.test.tsx`：1 项 30 秒超时。

此前一次四分片记录为 515 pass / 11 fail，本轮 fresh 变为 518 pass / 8 fail，且失败文件集合也发生变化，说明这些无关 UI 用例存在明显时序波动。最终结论以本轮 fresh 结果为准，不混用旧计数。

该次对照运行使用的 main 快照为 `44044d8a`；最终报告时本地 `main` 与 `origin/main` 已推进到 `b11c7509`。此前在该 main 快照同环境运行 `agentguard`、`content-audit-detail`、`model-management` 和 `unified-alerts` 时，AgentGuard 有 5 项超时，`content-audit-detail` 有 2 项失败，后两者通过。由于该快照已修改 `content-audit-detail` / `unified-alerts`，结果不是 `63b1af3` 的精确基线复现，也未覆盖本轮出现的 `models-sync`，不能据此把 8 项失败归类为既有失败。

`git diff 63b1af3...HEAD` 显示这五个失败测试文件及其对应主要页面均未被本功能修改；这只能证明变更范围，不替代精确失败归因。最终结论明确保留 8 项失败和 1 个 unhandled error，不声称全绿。

**构建**：

```
$ npm run build
# exit 0
```

### 2.4 步骤 4：enterprise-ai-portal

```
$ npm run test:unit
# tests 113
# pass 112
# fail 0
# todo 1
# exit 0

$ npm run lint
# exit 0

$ npm run build
# 13/13 pages
# exit 0
```

测试、lint 和构建均通过。构建只报告 Next middleware 命名弃用警告，不影响本次门禁；报告未把该警告写成 0 warning。

### 2.5 任务 13 mandatory 真实身份实验室

AP1–AP10 不是 optional 或 check-only 验收。完整门禁必须依次执行：

```
make identity-lab-check
make identity-lab-up
make identity-lab-smoke
make identity-lab-down
```

本轮在隔离实验室 fresh 执行上述四条命令，静态门禁、启动、真实 smoke 和清理全部 PASS，AP1–AP10 10/10 PASS。运行态包含真实 Go Control Plane、Next Portal、OpenLDAP、Samba AD、企业 Keycloak、JJDGuard Keycloak、PostgreSQL 16、Redis，以及只承担最小认证转发职责并在读取 body 前限制 64 KiB 的 portal-proxy。`--check-only` 仅是前置静态校验，不能替代真实验收。

关键运行态断言：

- AP1–AP4 分别完成本地账号、LDAP、AD 和企业 OIDC 的真实 Portal callback；
- AP5 以相同 email、不同 stable subject 登录，数据库中得到两个 user 和两个 `user_identity_links`，没有 email 合并；
- AP6–AP7 验证未映射用户无模型，映射用户只得到本部门模型；
- AP8 保存一份 Auth.js cookie，在部门从 research 迁移到 marketing 后复用同一 cookie：旧 research 模型立即 403，新 marketing 模型可用；恢复部门后同一 cookie 再次反向验证；
- AP9 验证目录用户禁用后登录失败、恢复后可登录；
- AP10 通过真实控制面 API 独立停用/恢复目录与企业 SSO，另一路和本地登录保持可用；
- 运行时以真实 client-credentials token 解码 `resource_access.realm-management.roles`，分别精确等于 `manage-identity-providers` 和 `manage-realm/manage-users/view-realm`，不是只检查 realm JSON。

本轮验收未伪造时间戳或耗时；`identity-lab-down` 已删除本轮容器、网络和卷。

## 3. 安全自查（9 项逐条取证）

### 3.1 BOLA / BFLA — 浏览器与机器接口采用各自认证和租户边界

证据：
- 浏览器 admin 身份与目录路由位于 `cmd/server/main.go` 的受保护路由组，依次使用 `auth.Middleware`、`permission.Middleware` 和 `handler.LicenseGuard`；handler 从已认证用户 context 取 `user.TenantID`，不信任客户端提交的租户标识。
- 浏览器写接口继续用 `validateTargetDepartmentBelongsToTenant` / `validateIdentityMappingTargets` 等校验目标部门、团队和项目属于当前租户；服务端 permission middleware 才是 BFLA 边界，前端显隐不作为授权依据。
- `/admin/v1/portal-integration/*` 机器接口不走浏览器 session/RBAC/LicenseGuard，而由独立 `PortalIntegrationAPIMiddleware` 校验共享密钥。
- 涉及租户身份数据的 portal-integration handler 要求 `X-JJDGuard-Tenant-Id`，并把该 tenant ID 传给 repository；用户、团队、项目等对象按租户查询或显式比对 `TenantID`，跨租户/不存在按接口契约拒绝或 404 掩蔽。
- 机器接口还在 handler 边界校验 JSON、稳定 subject、显式 scopes、资源 ID 等请求字段；共享密钥通过不等于可绕过对象归属与输入校验。

通过。

### 3.2 密钥 — 无 secret/token/测试口令进入 Git 或响应

证据：
- `git diff 63b1af3...HEAD -- "*.env"` 为空（无 .env 入库）。
- `deploy/identity-lab/.env.example` 全部是 `lab-*-only` 占位值，明确标注"绝对不可用于生产"。
- `.gitignore` 显式 `!deploy/identity-lab/.env.example`（白名单只允许此占位模板），真实 `.env` 由 `.env*` 规则忽略。
- 扫描本功能新增 `.go` 代码：`grep -iE "password\s*=\s*[a-zA-Z0-9]{8,}"` 无真实密钥命中。

通过。

### 3.3 SSRF — OIDC/LDAP/Keycloak 管理目标只能来自受控配置

证据：
- **LocalIdentityClient**（`internal/localidentity/client.go`）：
  - `NewClient` 严格校验 BaseURL：必须 http/https、无 user info / query / fragment、hostname 非空。
  - `transport.Proxy = nil`（禁用代理，防 `HTTP_PROXY` 重定向到内网）。
  - `CheckRedirect = http.ErrUseLastResponse`（不跟随重定向）。
  - `subjectFromLocation` 校验 Location header 必须与 baseURL 同 scheme/host。
  - BaseURL 来自服务端环境变量（受控配置），非用户输入。
- **LDAP 出站策略**（`internal/directoryldap/policy.go` / `connector.go`）：仅接受
  `DIRECTORY_LDAP_TARGET_ALLOWLIST` 中的 exact FQDN，且每个 DNS 地址都必须落入
  `DIRECTORY_LDAP_ALLOWED_CIDRS` 的批准网段；两项任一为空都 fail closed。拒绝
  metadata、loopback、link-local、literal IP 和非批准 CIDR。连接 pin 到批准 IP，
  TLS `ServerName` 仍使用原 FQDN，避免 DNS rebinding 且保持 SNI/证书校验。

通过；旧报告中的“黑名单而非 allowlist”偏差已关闭。

### 3.4 输入 — DN、filter、issuer、subject、group、department ID 均在边界校验

证据：
- `identity_sources_handler.go` `saveDraftReq.validate()`：DisplayName ≤128、IssuerURL ≤512、ClientID ≤128，全部 TrimSpace 非空校验。
- `directoryldap/connector.go`：BindDN / UsersDN / StableIDAttribute / UsernameAttribute TrimSpace 非空校验；UserFilter 默认 `(objectClass=person)`；SizeLimit=30 限制结果集。
- `directoryldap/policy.go`：UserFilter 在保存前和同步前均调用 `ldap.CompileFilter`；控制字符和超过 4096 字节的值直接拒绝，空值只选择受控默认 filter。
- `localidentity/client.go`：realm 用 `realmPattern = ^[A-Za-z0-9._-]+$` 校验，externalSubject 用 `url.PathEscape` 防注入。

通过；旧报告中的“filter 未校验”偏差已关闭。

### 3.5 日志 — 不记录密码、token、LDAP 完整敏感属性

证据：
- 扫描本功能新增 `.go` 代码：`grep "log\.(Print|Error|Warn|Info)" | grep -iE "password|token|secret|credential"` 为空（无敏感日志输出）。
- `directory_preview_handler.go` 的 `PreviewDirectorySource` 在构造 digest 配置时把 BindPassword 固定为 `"[redacted]"`（当前行 114），真实密码不进入 digest 或 preview 持久化。
- `localidentity/client.go` `String()`/`GoString()` 输出 `Credentials:[redacted]`。

通过。

### 3.6 登录 — PKCE/state/nonce 固定开启，kc_idp_hint 不接受客户端任意值

证据：
- `enterprise-ai-portal/src/auth.ts` 的 `buildProviders` 对两个 OIDC provider 均硬编码 `checks: ['pkce', 'state', 'nonce']` 和 `code_challenge_method: 'S256'`（当前行 229-253），不可关闭。
- `kc_idp_hint` 值来自服务端环境变量 `OIDC_ENTERPRISE_IDP_HINT`（默认 `enterprise`）；`buildProviders` 不从 query string 或 request 透传该值。

通过。

### 3.7 身份合并 — 无 email fallback

证据：
- `user_identity_links` 唯一键为稳定键 `unique(tenant_id, issuer, source_type, external_subject)`（`137_enterprise_identity_department.sql`），不含 email。
- 迁移测试 `enterprise_identity_migration_test.go` 有专门负向断言：
  - `TestEnterpriseIdentityDepartmentMigrationHasStableIdentityKey`：`forbiddenEmailIdentityMerge(body)` 必须返回空。
  - `TestForbiddenEmailIdentityMergeIsTargeted`：对 9 种 email-based 合并/索引/upsert 风险 SQL 全部检出。
- `grep -rniE "email.*fallback|fallback.*email|matchByEmail" internal/identitybinding/ internal/localidentity/` 为空。

通过。

### 3.8 授权 — 未分配部门和应急管理员无模型权限

证据：
- **应急管理员 chat_allowed=false**：`identitybinding/service.go:271` `Mode: ModeEmergency, ChatAllowed: false`。
- **应急降级清空模型权限**：`localidentity/provisioner.go:211-224` 应急降级时先 `DELETE FROM permission_grants WHERE scope_type=tenant`，再仅重建一个 tenant 级 grant（无 model scope grant），模型权限因此为空。
- **未分配部门**：`teams` 表 `system_key=unassigned`（`137` 迁移），无模型权限挂载。
- **部门迁移缓存失效**：`internal/permission/cache.go` `GrantsCache` 用
  `users.department_version BIGINT` 单调 revision 绑定缓存条目。生产 checker
  每次 versioned cache hit 都查询数据库权威 revision；不一致即失效并重载。
  revision 为 0 时，无论 cache miss 还是 cache hit 后重载都清缓存并返回空 grants，
  不会把 loader 返回的权限放行。

- Portal 的 `/api/models` 与 `/api/chat` 每次请求都调用控制面 `authorization-context`，不使用 30 秒权限缓存；控制面不可用、用户 inactive、emergency 或 `chat_allowed=false` 都 fail closed，且不会到达 proxy。
- 模型列表与 chat 都只接受控制面当前返回的 `model_ids`；没有 GLM 或其他模型 fallback。AP8 以同一旧 cookie 实证旧模型 403、新模型可用。
- Portal 拒绝 revision 0、非安全整数或缺失的授权 revision；未授权 token/session
  会同时清除业务 user ID、department、department revision 和 role，避免旧字段残留。

通过。

### 3.9 迁移 — 部门变化后旧权限缓存和 session 失效

证据：
- `identity_cache_invalidation_outbox` 表（`137` 迁移）+ `identity_cache_invalidation_outbox.go` worker：部门变化写入 outbox，异步失效缓存。
- `permission/cache.go` `departmentVersion` 绑定（同 3.8）。
- `identitybinding/service.go` `PermissionCacheInvalidatorAdapter` + `UncachedModelAuthorizationInvalidator`：部门迁移触发权限缓存与模型授权双失效。
- 迁移测试 `identity_cache_invalidation_outbox_test.go` 验证 outbox 行为。

- 目录 activate 必须引用 `status=succeeded` 且未过期的 preview，并显式 `confirm:true`；`/directory/sources/activate` 与 `/directory/sources/previews/{id}/activate` 统一进入同一生命周期实现。
- tenant advisory lock 覆盖目录配置保存、激活和停用，避免 draft mutation、activation 与 disable 竞态。
- 发布失败补偿使用 5 秒 bounded restore；随后尽可能按旧配置执行 full sync。restore/full sync 任一步失败都会持久化 `runtime_reconciliation_required` 与稳定 reason，不会静默吞掉 restore 错误；identity overview 将其显示为异常并纳入 `reconciliation_required` 计数。

通过。

## 4. 变更范围

```
$ git rev-list --count 63b1af3..HEAD
86

$ git diff --shortstat 63b1af3...HEAD
 190 files changed, 30448 insertions(+), 1279 deletions(-)

$ git diff --check 63b1af3...HEAD
# 最终提交后 fresh 重跑

$ git diff 63b1af3...HEAD --name-only | grep -iE "\.env$|secret|\.pem$|\.key$|id_rsa|credentials"
# 空（无密钥文件）
```

**文件分类**（全部归属身份功能）：

- `apps/control-plane`：身份、目录、权限、组织和用户后端；
- `apps/web-console`：身份源、目录预览、用户和组织界面；
- `enterprise-ai-portal`：双登录、请求时授权和 Portal 测试；
- `deploy/identity-lab`、`scripts/identity-*`、`Makefile`：真实隔离实验室与 DB gate；
- `deploy/migrations/137_enterprise_identity_department.sql`：本未合并分支的最终迁移。

**无 .env / 密钥 / 构建产物 / 无关修复**。验收后已删除 `apps/web-console/dist`、`enterprise-ai-portal/.next` 与 `apps/control-plane/server`；`jjdguard-identity-lab*` 容器/网络/卷为 0，`jjdguard-identity-db-test-pg-*` 容器为 0，无 Vitest/npm 测试进程。

## 5. 实现偏差 / 最终决策（design.md 补充点汇总）

以下现实约束在任务 5/9/13 审查中确认，已追加到 design.md §19：

1. **directoryruntime 是 federation 层非读模型层**：`internal/directoryruntime` 管理 Keycloak 组件生命周期（Status/Snapshot/Apply/Restore）；Preview/Activate/Incremental 状态机由 `directory_preview_handler.go` 承担。这是任务 14 接受的最终实现偏差。
2. **source_type 用 draft.Kind**：身份源类型复用目录草稿的 Kind 字段，避免引入并行枚举。
3. **冲突项只展示脱敏计数**：当前实现无冲突 entries 列表端点，目录预览/同步运行只返回 `Conflict int` 计数，不暴露冲突条目详情；这是任务 14 接受的最终展示边界。
4. **LDAP 出站为 exact allowlist + approved CIDR**，空配置 fail closed，并 pin IP、保留原始 SNI。
5. **LDAP filter 未校验偏差已关闭，编译校验已落实**：保存和同步前编译，拒绝控制字符与超长输入。
6. **目录生命周期 preview gated**：激活需要成功 preview 与 `confirm:true`，两条激活路由统一实现。
7. **授权为 request-time**：Portal 模型与 chat 每次取控制面当前授权，失败一律 closed，无 30 秒权限缓存和模型 fallback。
8. **发布补偿可观测**：bounded restore、尽可能旧配置 full sync、持久 reconciliation flag/reason 和 overview 异常计数。
9. **Keycloak 最小权限用真实 token 验证**；非受管 mapper 保留且不进入 managed digest。
10. **迁移版本决策**：137 是该未合并分支首次发布版本，不新增 138。任何曾应用中间版 137 的临时开发库必须重建；不得把该要求解释为触碰生产迁移。

## 6. 交付状态边界

| 层次 | 本报告结论 |
|------|------------|
| 代码状态 | 分支 `feat/enterprise-identity-chat-department` 已完成 14 个任务；单调授权 revision、零版本 fail-closed 与目录绑定失败补偿收口至 `d33ee519` |
| 测试证据 | 后端全量、race、vet、build、隔离 PG16 与 Portal 门禁通过；真实 lab AP1–AP10 10/10 通过；Web fresh 526 项中 518 pass、8 fail，另有 1 个 unhandled error，未完成精确基线归因 |
| 部署状态 | 未 push、未 merge、未部署、未重启 |
| 客户/生产验收 | 未修改客户或生产；真实客户 AD/LDAP 联调与生产验收尚未执行 |
