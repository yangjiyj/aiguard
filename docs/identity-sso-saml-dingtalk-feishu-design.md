# 控制台 SSO 扩展设计：SAML 2.0 / 钉钉 / 飞书（W9 9.3）

状态：设计稿，未实现。本期（W9）已实现 OIDC（9.1）、CAS 3.0 与企业微信（9.3）；本文给出其余三种登录方式的接入设计，供按客户需求排期。

## 1. 现状与复用点

W9 之后控制台 SSO 的公共骨架都在 `apps/control-plane/internal/identity/consolesso`，新协议只需要实现「浏览器跳转 + 服务端校验得到稳定主体」两段，其余全部复用：

| 能力 | 位置 | 新协议是否复用 |
|---|---|---|
| state 一次性存储（Redis GETDEL，10 分钟）+ 浏览器绑定 cookie（防登录 CSRF） | `state.go`、`Service.takeBoundFlow` | 是；`flowState.Provider` 区分协议，跨协议 state 不可互用 |
| 按绑定关系找账号（不按邮箱/手机号/用户名，不自动建号） | `ProviderSubjectResolver` → `user_identity_links(source_type, issuer, external_subject)` | 是；每种协议一个 `source_type` |
| 一次性票据（60 秒）→ 与本地登录同形的会话 | `Service.completeLogin`、`Redeem` | 是 |
| 准入角色（门户 JIT 的 developer 进不了控制台） | `consoleRoles` | 是 |
| 管理员显式绑定接口（跨租户、越级绑定拒绝，issuer 由服务端配置决定） | `handler/identity_console_sso_bindings.go` | 是；`provider` 白名单追加即可 |
| `status.providers` 列表（W3 登录页据此渲染按钮） | `Service.Status` | 是 |

每接一种协议需要：`consolesso/<proto>.go`（Login/Callback + 校验），`With<Proto>(cfg)` 挂载，新迁移（号段由当期工作流分配）把 `user_identity_links.source_type` 的 CHECK 再放开一项，绑定接口 `provider` 白名单追加一项，`MountConsoleSSOProviders` 注册两条公开路由。

主体键约定（写入 `user_identity_links`）：

| 协议 | source_type | issuer | external_subject |
|---|---|---|---|
| SAML 2.0 | `saml` | IdP EntityID | `NameID`（要求 persistent 格式）；若 IdP 只给 transient，则取配置指定的稳定属性（如 `employeeNumber`） |
| 钉钉 | `dingtalk` | `dingtalk:<corpId>` | 企业内 `userid`（不是 unionId/openId） |
| 飞书 | `feishu` | `feishu:<tenant_key>` | `user_id`（企业内稳定；不用 open_id，open_id 按应用变化） |

## 2. SAML 2.0（SP-initiated，HTTP-Redirect 请求 + HTTP-POST 响应）

适用：部分政企统一身份平台、ADFS、Shibboleth。

流程：

1. `GET /admin/v1/auth/sso/saml/login`：生成 `AuthnRequest`（ID = 随机 state，`AssertionConsumerServiceURL` 固定、`ForceAuthn` 可配），state 存 Redis 并绑定浏览器，302 到 IdP SSO URL（HTTP-Redirect 绑定，DEFLATE + base64 + 可选签名）。
2. `POST /admin/v1/auth/sso/saml/acs`：IdP 以表单 `SAMLResponse` 回传。
   - 这是跨站 POST：浏览器绑定 cookie 需 `SameSite=None; Secure`（只对 `/admin/v1/auth/sso/saml` 路径），否则 Lax cookie 不会随 POST 发送。这是与 OIDC/CAS 唯一不同的 cookie 策略，必须单独设置、单独测试。
   - 校验顺序（任一失败即拒绝）：
     1. XML 解析禁用 DTD/外部实体；
     2. 签名：只信任配置里的 IdP 证书（不信任报文内嵌 `KeyInfo`），要求 Assertion 签名（或 Response 签名且只含一个 Assertion），算法白名单 RSA-SHA256 及以上，拒绝 SHA-1；
     3. 防 XML 签名包装（XSW）：只读取「被签名引用的那个元素」里的 Assertion，按 ID 定位后再取内容，不用 XPath 在全文档里搜第一个 Assertion；
     4. `InResponseTo` 必须等于本次 state（一次性 GETDEL），拒绝 IdP-initiated（无 InResponseTo）；
     5. `Destination`/`Recipient` = 本 ACS URL，`Audience` = 本 SP EntityID，`Issuer` = 配置的 IdP EntityID；
     6. `NotBefore`/`NotOnOrAfter`/`SubjectConfirmationData.NotOnOrAfter` 校验，时钟偏差 ≤ 60 秒；
     7. Assertion ID 进 Redis 防重放（TTL 到 NotOnOrAfter）；
     8. 若 IdP 加密断言，先用 SP 私钥解密，再对解密出的 Assertion 做 2–6。
3. 取主体 → `completeLogin(ProviderSAML, entityID, nameID)`。

实现选型：Go 标准库没有 XML-DSig。建议引入 `github.com/russellhaering/goxmldsig`（仅签名校验，维护活跃，已处理 XSW 已知变体）并固定版本；不引入整套 `crewjam/saml`（其会话/中间件模型与现有票据流程重复）。SP 元数据（EntityID、ACS、签名证书）由 `GET /admin/v1/auth/sso/saml/metadata` 公开输出，便于客户在 IdP 侧登记。

配置：`JJD_CONSOLE_SAML_IDP_ENTITY_ID`、`_IDP_SSO_URL`、`_IDP_CERT`（PEM，可多张用于轮换）、`_SP_ENTITY_ID`、`_ACS_URL`、`_SUBJECT_ATTRIBUTE`（可选）、`_SP_KEY`/`_SP_CERT`（仅在需要签名请求或解密时）。

测试要求：单测覆盖签名缺失/错误证书/SHA-1/XSW 两种典型包装/InResponseTo 不匹配/IdP-initiated/Audience 错/过期/断言重放/DTD 实体；live 用一次性 Keycloak（SAML 客户端）或 SimpleSAMLphp 容器跑完整流程。

## 3. 钉钉（扫码 / 应用内免登，OAuth 2.0 新版接口）

流程：

1. `GET /admin/v1/auth/sso/dingtalk/login`：state 存 Redis + 浏览器绑定，302 到 `https://login.dingtalk.com/oauth2/auth?redirect_uri=…&response_type=code&client_id=<AppKey>&scope=openid corpid&state=…&prompt=consent&org_type=management`（`corpid` scope 用于拿到企业 ID 以校验）。
2. `GET /admin/v1/auth/sso/dingtalk/callback?authCode=…&state=…`：
   - 校验 state 与浏览器绑定（先于任何对外调用）；
   - `POST https://api.dingtalk.com/v1.0/oauth2/userAccessToken`（clientId/clientSecret/code）得到用户 token 与 `corpId`，`corpId` 必须等于配置值（防止其他企业用户登录）；
   - 取 `unionId`（`GET /v1.0/contact/users/me`），再用企业应用 access_token（`/gettoken`，缓存到期前 5 分钟刷新，失效码重取一次）调 `topapi/user/getbyunionid` 换企业内 `userid`；换不到（非本企业成员）即拒绝；
   - `completeLogin(ProviderDingTalk, "dingtalk:"+corpId, userid)`。

要点：不使用手机号/邮箱匹配；AppSecret 只在服务端请求体/头中出现，错误日志去掉 URL（复用 `unwrapURLError`）；请求均走 `newHTTPClient`（超时、不跟随重定向）。

配置：`JJD_CONSOLE_DINGTALK_CORP_ID`、`_APP_KEY`、`_APP_SECRET`、`_REDIRECT_URL`，可选 `_API_BASE_URL` 供私有化/测试覆盖。

测试：与企业微信相同的进程内假服务端模式（`wecom_test.go` 可作为模板），覆盖 corpId 不匹配、非成员、token 过期重取、state 重放/跨浏览器/跨协议。

## 4. 飞书 / Lark（网页应用 OAuth 2.0）

流程：

1. `GET /admin/v1/auth/sso/feishu/login`：state 存 Redis + 浏览器绑定，302 到 `https://accounts.feishu.cn/open-apis/authen/v1/authorize?client_id=<AppID>&redirect_uri=…&state=…`（国际版 Lark 使用 `larksuite.com` 域，按配置切换）。
2. `GET /admin/v1/auth/sso/feishu/callback?code=…&state=…`：
   - 校验 state 与浏览器绑定；
   - `POST /open-apis/authen/v2/oauth/token`（client_id/client_secret/code/redirect_uri，建议启用 PKCE）得到 `user_access_token`；
   - `GET /open-apis/authen/v1/user_info` 取 `tenant_key` 与 `user_id`；`tenant_key` 必须等于配置值；`user_id` 为空（应用未开通「获取用户 user ID」权限）时拒绝并在日志提示权限缺失，不回退到 open_id/union_id；
   - `completeLogin(ProviderFeishu, "feishu:"+tenant_key, user_id)`。

配置：`JJD_CONSOLE_FEISHU_APP_ID`、`_APP_SECRET`、`_TENANT_KEY`、`_REDIRECT_URL`、`_DOMAIN`（`feishu`/`lark`）。

测试：同上，另覆盖 tenant_key 不匹配、缺 user_id 权限、PKCE verifier 不匹配。

## 5. 共性安全约束（新协议必须满足，评审按此逐条核对）

1. 回调先校验 state（一次性）与浏览器绑定，再做任何对外请求；state 不能跨协议使用。
2. 主体只取 IdP 侧由企业管理员分配、不可被用户自改的标识；issuer 带企业/租户维度，防止同名用户跨企业撞号。
3. 只按管理员显式建立的绑定登录；不按邮箱/手机号/用户名匹配，不自动建号；同一外部主体只能绑定一个账号。
4. 外部请求：https（secure 模式）、超时、不跟随重定向、响应大小上限、错误日志不带 URL/密钥。
5. 配置不完整时该方式不挂载（入口 404、status 不列出），不影响本地管理员登录与其他 SSO 方式。
6. 每项实现需带：单测（含上表负向用例）、基线负样本、能用一次性容器跑的 live 测试。
