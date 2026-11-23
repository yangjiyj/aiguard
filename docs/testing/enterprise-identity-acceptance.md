# 企业身份源验收手册（identity-lab）

任务 13 交付物。隔离测试环境，覆盖三类外部身份源（OpenLDAP / Samba AD / 外部企业 OIDC IdP）+ 本地身份运行服务（JJDGuard Keycloak），并映射到 10 个企业身份验收点。

> **绝对禁止用于生产。** 所有口令与密钥都是 lab-only 占位，仅在本隔离目录的 `.env.example` 中提供；真实密钥请另存 `.env`（已被 `.gitignore` 忽略）。

## 1. 架构

```
 OpenLDAP --LDAPS--+                         +-- PostgreSQL 16 (身份/部门/模型)
 Samba AD --LDAPS--+--> JJDGuard Keycloak --> Portal (Auth.js) --> control-plane
 enterprise Keycloak --OIDC broker----------+                 +--> Redis

 account-login: 本地账号、LDAP、AD
 enterprise-sso: 服务端固定 kc_idp_hint=enterprise
```

Compose 还包含一次性迁移、种子和 Prisma 初始化服务。每个身份源使用同一 lab CA 签发的独立 leaf 证书；Portal 完成真实 Auth.js 回调后调用 control-plane EnsurePortalUser，稳定身份、唯一部门和模型授权最终写入隔离 PostgreSQL 16。

## 2. 启动与验证

### 2.1 静态验收（任务 13 强制项）

```bash
make identity-lab-check
# 等价于：
#   bash -n scripts/identity-lab-smoke.sh
#   docker compose -f deploy/identity-lab/docker-compose.identity-lab.yml config
#   ./scripts/identity-lab-smoke.sh --check-only
```

预期：`ALL CHECKS PASSED（check-only 模式）`，输出不含任何口令/token。

### 2.2 End-to-end acceptance (mandatory)

```bash
make identity-lab-up        # 先清空精确 lab 项目卷，再启动并等待全部服务健康
make identity-lab-smoke     # 真实执行 AP1-AP10
make identity-lab-down      # 销毁 lab（含卷）
```

容器健康后，可手动登录 JJDGuard Keycloak 管理控制台（`https://jjdguard-keycloak:8443`，仅 lab 网络内）观察 federation / broker 状态。员工门户登录走 NextAuth 双入口（account-login / enterprise-sso），见 `enterprise-ai-portal/src/auth.ts`。

## 3. 10 个验收点

| # | 验收点 | runtime smoke 的真实证据 |
|---|--------|--------------------------|
| 1 | 本地账号默认可登录 Chat | local-alice 完成 Portal 回调，并存在唯一 stable link |
| 2 | LDAP 用户从“账号登录”进入 | ldap-alice 经 LDAP federation 完成 Portal 回调，并存在唯一 stable link |
| 3 | AD 用户从“账号登录”进入 | ad-bob 完成 Portal 回调；ID token/userinfo 含受控 AD group/department，控制面仅授予 research 模型 |
| 4 | 外部 OIDC 用户从“企业 SSO 登录”进入 | enterprise-erin 经固定 broker 完成 Portal 回调；ID token/userinfo 含受控 group/department，控制面仅授予 research 模型 |
| 5 | 同邮箱不同 subject 不合并 | LDAP 与 enterprise OIDC 的两个真实登录返回不同 user ID，数据库中保留两个稳定四元组 |
| 6 | 未映射有效用户开箱可用 | 以 stable-link user ID 查询数据库，自动进入 Chat 默认部门，并获得该部门的活动模型 |
| 7 | 映射后获得对应部门模型 | 以 LDAP stable-link user ID 查询数据库，仅获得 research 部门及其模型 |
| 8 | 迁移部门后旧模型权限立即撤销 | 修改真实 LDAP 组并登录后切到唯一 marketing 模型；恢复源并再次登录后，同 user ID/version 前进且仅恢复 research 模型 |
| 9 | 禁用目录用户后登录失败 | 同一 LDAP 用户先登录成功，移入 Disabled OU 后失败，恢复后再次成功 |
| 10 | 两个管理卡片可独立启停 | 真实禁用/恢复 directory 与 enterprise SSO；另一入口保持可用，各入口恢复后重新登录成功 |

> 完整验收必须按 §2.2 执行；任一服务、登录探针或 fresh PostgreSQL 16 授权验收失败都会返回非零。

## 4. 安全红线

1. **口令/密钥**：所有 `${ENV}` 占位由 `.env.example` 注入；realm.json 不硬编码真实 secret。`.env.example` 仅 lab 占位，明示"绝对不可用于生产"。
2. **`.gitignore`**：`deploy/identity-lab/.env`、`*.key` 已被根 `.gitignore` 的 `.env*` / `*.key` 覆盖，永不入库。
3. **smoke 输出**：脚本不向 stdout/stderr 打印任何口令/token；敏感扫描失败只报告文件类别，不显示命中行或值。
4. **网络边界**：PG、Redis、control-plane、Portal、OpenLDAP、Samba AD 和两套 Keycloak 运行服务仅连接内部 identity-lab 网络，与生产 compose 网络名隔离。唯一例外是一次性 cert-init：它在启动阶段通过 Compose 默认网络执行 apk add --no-cache openssl 生成 lab CA/leaf，完成后退出；因此首次启动需要镜像拉取和 Alpine 包仓库访问。该 one-shot 不接触业务数据，私钥只写各自隔离 volume，运行态服务无外网出口。
5. **真实部署不复用**：lab 自签证书仅 30 天有效期，CA 名 `jjdguard-identity-lab-CA`，与生产 CA 不重叠；public CA 与四个服务 private TLS 卷分离，运行服务无法读取其他服务私钥。

## 5. 文件清单

| 文件 | 作用 |
|------|------|
| deploy/identity-lab/docker-compose.identity-lab.yml | 隔离 PG16、Redis、迁移/种子、control-plane、Portal、三类外部身份源和 JJDGuard Keycloak |
| deploy/identity-lab/postgres/*.sql | Portal 数据库创建与身份/部门/模型验收种子 |
| deploy/identity-lab/openldap/bootstrap.ldif | OpenLDAP 用户/组/嵌套 OU/禁用 OU 种子 |
| deploy/identity-lab/samba/entrypoint.sh、provision.sh | Samba AD TLS 启动与用户/禁用用户/组迁移幂等 provision |
| deploy/identity-lab/keycloak/enterprise-realm.json | 外部企业 OIDC IdP realm（含 broker client） |
| deploy/identity-lab/keycloak/jjdguard-realm.json | 本地身份运行服务 realm（本地账号 + LDAP/AD federation + enterprise broker） |
| deploy/identity-lab/.env.example | lab-only 占位口令/密钥模板 |
| scripts/identity-lab-smoke.sh | 静态安全门禁、check-only 与 runtime 验收入口 |
| scripts/identity-lab-runtime-acceptance.sh | 真实 Portal 回调、stable link 与数据库授权的 AP1–AP10 |
| scripts/identity-lab-portal-probe.py | 浏览器协议级 Auth.js/OIDC 登录与回调探针 |
| scripts/identity-lab-oidc-probe.py | 补充 OIDC token/userinfo claims 诊断（不是主验收证据） |
| scripts/identity-lab-admin-toggle.py | Keycloak directory/SSO 独立启停与失败回滚 |
| scripts/identity-lab-wait.sh | service-aware 健康门禁，包含一次性服务完成状态 |
| Makefile | identity-lab-check/up/smoke/down target |
