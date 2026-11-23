# 企业 AI 门户模块

此目录存在时，离线安装会启用员工门户、门户代理、门户数据库、SSO 边缘和内部身份运行服务。

- `Caddyfile`：Compose 内网的员工门户与 `/sso` 协议白名单；内部管理路径全部拒绝。
- `keycloak-realm/realm-jjdguard.json`：`jjdguard` 冷启动 realm，不含预置用户或真实密钥。
- `bootstrap-identity-runtime.sh`：创建 control-plane 最小权限服务账号，并写入 `0600` 专用环境文件。
- `SSO-企业对接指南.md`：客户仅通过 JJDGuard 页面完成企业 OIDC 对接。
- `SSO-内部恢复手册.md`：只供平台运维使用，不随客户操作流程展示。

`chat-idp` 和 `chat-edge` 都不发布宿主端口。员工浏览器只访问 Web 统一入口的 `/chat` 与 `/sso`；`web-console` 再转发到内网 `chat-edge`，客户无法访问内部身份管理面。
