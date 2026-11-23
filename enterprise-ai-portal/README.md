# 企业 AI 对话门户

> 企业员工用公司 SSO 登录，在干净好看的网页里与审批过的大模型对话；流量经安全网关做「按人归因、分组限额、审计留存」。本仓库为门户前端 + 后端（Next.js 一体应用），替换原有的 LobeHub。

**当前阶段：M2/M3 已完成** — 真链路全通：OIDC 登录、真实对话流式、历史落库、按人限流、三级角色显隐、安全测试覆盖。

---

## 架构

```
浏览器 ──http──▶ 新门户(:3100)  ──容器网──▶ Keycloak(:8180, OIDC IdP)
                      │
                      ├──▶ chatportal-postgres(:5432, 对话历史 db=enterprise_ai_portal)
                      │
                      └──▶ portal-proxy(:8788)
                                │  Authorization: Bearer ${PORTAL_INTERNAL_TOKEN}
                                │  X-Portal-Direct-Sso-Subject/Email/Department
                                ▼
                            安全网关(gateway-core) ──▶ 上游模型(GLM/DeepSeek/Qwen…)
```

**身份归因安全铁律**：用户身份（OIDC sub/email/department）在服务端从 Auth.js 会话取，注入到 portal-proxy 请求头；浏览器永远无法设置或伪造这些头。请求体里客户端传来的任何身份字段一律被删除/忽略。

---

## 快速开始（Docker 一键起）

### 前置依赖
- 已运行 chat-portal dev 栈（postgres + keycloak + portal-proxy + gateway），网络名 `chatportal-net`
- Keycloak realm `chat-portal-dev` 里已建好 client `chat-portal-ui`

### 步骤

1. 复制环境变量模板并填值：
   ```bash
   cp .env.example .env
   # 编辑 .env，填入：
   #   POSTGRES_PASSWORD         来自 chat-portal/compose/.env
   #   AUTH_SECRET               openssl rand -base64 32 生成
   #   CHAT_PORTAL_UI_OIDC_SECRET Keycloak client chat-portal-ui 的 secret
   #   PORTAL_INTERNAL_TOKEN     来自 chat-portal/compose/.env
   ```

2. 启动：
   ```bash
   docker compose up -d --build
   ```

   Compose 前先创建/验证 Portal 到 control-plane 的专用 internal bridge（已存在但属性或 owner 不同会停止）：
   ```bash
   bash ../deploy/docker-compose/ensure-jjdguard-portal-cp-network.sh \
     --name "${JJD_PORTAL_CP_NETWORK:-jjdguard-portal-control-net}" --owner jjdguard
   ```
   `web` 通过 `JJD_CP_URL=http://jjdguard-portal-control-plane:8081` 访问控制面；该专网只允许一个 control-plane 与一个 Portal UI。

3. 访问 `http://home:3100`（或 `http://<宿主>:3100`），用 Keycloak 测试账号登录：
   - alice / Alice-d5b051a1f746cbdf （engineering 部门）
   - bob / `<KC_TEST_BOB_PASSWORD>` （sales 部门）

### 端口
- `3100`：门户 UI（浏览器访问）

---

## 配置（环境变量）

| 变量 | 必填 | 说明 |
|---|---|---|
| `DATABASE_URL` | 是 | postgres 连接串，库名 `enterprise_ai_portal` |
| `AUTH_SECRET` | 是 | Auth.js JWT 加密密钥 |
| `OIDC_ISSUER` | 是 | Keycloak realm issuer URL |
| `OIDC_CLIENT_ID` | 是 | OIDC client id（默认 `chat-portal-ui`） |
| `OIDC_CLIENT_SECRET` | 是 | OIDC client secret |
| `PORTAL_PROXY_URL` | 是 | portal-proxy 内部 URL |
| `PORTAL_INTERNAL_TOKEN` | 是 | portal-proxy 内部令牌（可信服务凭证） |
| `JJD_CP_URL` | 是 | control-plane 内部 URL；新值优先，兼容期可回退 `NEWAPI_CP_URL` |
| `JJD_PORTAL_API_SECRET` | 是 | Portal 集成通道密钥；新值优先，兼容期可回退旧键 |
| `BRAND_NAME` / `BRAND_SHORT_NAME` / `BRAND_ACCENT` | 否 | 品牌名/简称/强调色 |
| `PORTAL_MODELS` | 否 | 模型清单，逗号分隔，格式 `id=显示名` |
| `RATE_LIMIT_CAPACITY` | 否 | 每用户令牌桶容量，默认 5 |
| `RATE_LIMIT_REFILL_MS` | 否 | 令牌补充间隔毫秒，默认 3000 |
| `NEXT_PUBLIC_PORTAL_ADMIN_URL` | 否 | 管理后台入口 URL（仅 admin 角色看到） |
| `NEXT_PUBLIC_PORTAL_DEPT_URL` | 否 | 部门看板入口 URL（manager/admin 看到） |

---

## 本地开发

```bash
npm install --registry=https://registry.npmjs.org
npm run dev      # http://localhost:3000，但需要连通容器网络里的 postgres/keycloak/portal-proxy
# 或：用 docker compose up 跑容器，再挂载源码热重载（见 compose.yml）
```

### 设计系统走查页
`http://<host>:3100/style` — 色板、字阶、按钮、Markdown 渲染一览。

---

## 测试

```bash
# 单元测试（限流令牌桶）
npm run test:unit

# 安全集成测试（对运行中的服务发请求）
npm test
# 已登录场景：
COOKIE="authjs.session-token=xxx" npm test
```

**已覆盖的安全场景**（共 9 项）：
- 未登录访问受保护 API → 401（4 项）
- 已登录后请求体伪造 `user` 字段被服务端忽略（**核心铁律**）
- 越权访问/改/删别人的 conversation → 404（不泄露存在性）
- `/api/me` 返回的身份不含伪造字段

---

## 角色（三级显隐）

| 角色 | 能看到的入口 |
|---|---|
| employee（默认） | 对话主页、自己的会话历史 |
| manager | 上述 + 侧栏「部门看板」入口（链接到 portal-proxy `/portal/dept`） |
| admin | 上述 + 侧栏「管理后台」入口（链接到 portal-proxy `/admin`） |

角色由 OIDC `role` claim 决定，服务端强制；浏览器无法修改。

---

## 项目结构

```
src/
├── app/
│  ├─ api/
│  │  ├─ auth/[...nextauth]/route.ts   # Auth.js v5 OIDC handler
│  │  ├─ chat/route.ts                 # POST 对话（核心安全路径）
│  │  ├─ conversations/                # 会话 CRUD（按 user_id 隔离）
│  │  ├─ models/route.ts               # GET 模型清单
│  │  └─ me/route.ts                   # GET 当前用户身份
│  ├─ login/page.tsx                   # 登录页
│  ├─ page.tsx                         # 对话主页（鉴权）
│  ├─ style/page.tsx                   # 设计走查页
│  └─ layout.tsx                       # 根布局
├── auth.ts                            # Auth.js 配置（OIDC + JWT callback）
├── middleware.ts                      # 鉴权代理（未登录跳 /login）
├── components/
│  ├─ app-shell.tsx
│  ├─ chat/                            # store/chat-panel/composer/sidebar/...
│  └─ ui/                              # shadcn 组件
└── lib/
   ├─ prisma.ts                        # Prisma client 单例
   ├─ user-service.ts                  # 用户档案 upsert
   ├─ rate-limit.ts                    # 令牌桶限流
   └─ brand.ts                         # 品牌配置（env 覆盖）
prisma/
└─ schema.prisma                       # UserProfile / Conversation / Message
test/
├─ security-check.ts                  # 安全集成测试
└─ rate-limit.test.ts                 # 限流单测
```

---

## 关键文件速查

- **核心安全路径**：`src/app/api/chat/route.ts` — 身份从 Auth.js 会话取，注入 `X-Portal-Direct-*` 头
- **OIDC 配置**：`src/auth.ts` — Keycloak provider + department/role claim 落 JWT
- **数据隔离**：`src/app/api/conversations/` — 所有查询带 `userId`
- **限流**：`src/lib/rate-limit.ts` + `src/app/api/chat/route.ts` step 1.1
- **角色显隐**：`src/components/chat/sidebar.tsx` 用户菜单条件渲染

---

## 故障排查

| 现象 | 原因 / 解决 |
|---|---|
| 登录后 `Configuration` 错误 | `OIDC_ISSUER` 与 Keycloak 实际 issuer 不一致（注意 hostname） |
| 对话返回 401 | 未登录或 session 过期，清 cookie 重登 |
| 对话返回 429 | 触发限流，等几秒或调大 `RATE_LIMIT_CAPACITY` |
| 对话返回 502 upstream_unreachable | portal-proxy 不可达，检查容器网络 |
| 模型清单为空 | `PORTAL_MODELS` env 未配置 |
| 容器起来但 3100 访问不通 | chatportal-net 是 `internal: true`，需双网络（见 compose.yml `eap-edge`） |

---

## 与原 LobeHub 的差异

| 维度 | 原 LobeHub | 新门户 |
|---|---|---|
| 归因链路 | lobehub.users 表查 email | 直接身份头（OIDC sub/email） |
| 部门 claim 来源 | accounts.id_token JWT | Auth.js JWT callback |
| 数据库 | 共用 lobehub db | 独立 `enterprise_ai_portal` db |
| 功能 | LobeHub 全功能（大量收口） | 仅对话（按规格 §3 砍净） |
| 部署 | 依赖 lobehub 镜像 | 自持 Next.js 一体应用 |

---

## 许可证
私有项目。
