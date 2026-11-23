# JJDGuard SSO 内部恢复手册

> 仅限平台运维。本文包含内部身份引擎 Keycloak 的容器名和管理命令，不应作为客户配置文档公开。客户只使用 JJDGuard“登录与单点登录”页面。

## 安全边界

- `chat-idp:8180` 仅在 `jjdguard-net` 容器网络内可达，没有宿主机 `ports`。
- `chat-edge:8180` 仅在 Compose 内网放行 `/sso/realms/jjdguard/*` 与 `/sso/resources/*`；公共流量从 Web 的 `/sso` 进入。
- `/admin`、原始 `/realms`、`/resources`、`/sso/admin` 和 master realm 均由边缘返回 404。
- control-plane 使用 `jjdguard-identity-orchestrator` 服务账号，仅持有 `manage-identity-providers` 与 `view-realm`。
- `KEYCLOAK_ADMIN_PASSWORD` 不传给 control-plane；运行凭据只在 `identity-runtime.env` 中保存，权限必须为 `0600`。

## 常规复核

在 `deploy/docker-compose` 目录执行：

```bash
bash tests/keycloak-routing_test.sh static
sudo bash chat/bootstrap-identity-runtime.sh
docker compose up -d --no-deps --force-recreate --wait control-plane
```

复核凭据文件时只看权限和键名，不打印值：

```bash
sudo stat -c '%U:%G %a %n' identity-runtime.env
sudo sed -n 's/=.*$/=[redacted]/p' identity-runtime.env
```

预期所有者为 `root:root`、权限为 `600`，且只包含 `JJD_SSO_*` 与 `JJD_IDENTITY_RUNTIME_*`。

## 服务账号丢失或凭据失效

1. 暂停 JJDGuard 页面中的 SSO 发布操作。
2. 确认 `chat-idp` 容器运行，备份 `.env`、`identity-runtime.env` 和身份数据卷。
3. 重新运行 `sudo bash chat/bootstrap-identity-runtime.sh`。脚本会幂等创建/收紧服务账号并读取当前 client secret，不输出密钥。
4. 强制重建 control-plane 使其重新加载专用 env 文件。
5. 在 JJDGuard 页面查看状态；如显示漂移，使用“按当前配置修复”。

## 内部管理 API 诊断

不得临时开放管理端口。确需诊断时，只通过容器执行：

```bash
docker compose exec -T chat-idp /opt/keycloak/bin/kcadm.sh \
  config credentials --server http://localhost:8180/sso \
  --realm master --user admin --password '[从受控密钥源读取]'
```

禁止把真实密码写进 shell 历史、脚本参数记录或工单。优先直接重跑引导脚本，不手工扩大服务账号角色。

## realm 或数据恢复

- 冷启动定义为 `chat/keycloak-realm/realm-jjdguard.json`，不含预置用户或真实明文密钥。
- 恢复前先备份 `chat-idp-data`；不得为解决回调问题直接删除生产数据卷。
- 若公开域名或 Web 端口变化，更新 `.env` 中 `JJD_SSO_PUBLIC_URL`（只写 origin，不带路径），重建 `web-console`、`chat-idp`、`chat-edge` 和门户服务，再重跑引导脚本。
- 只有在已验证备份可恢复且获得变更批准后，才允许重建身份数据卷。

## 回退

若新发布导致员工登录异常：

1. 保持 JJDGuard 本地管理员入口可用。
2. 在 JJDGuard 页面停用或恢复上一份企业身份配置。
3. 不回退公共路由拒绝规则，不开放 `/sso/admin`。
4. 对照 control-plane 发布事件、边缘访问日志和企业身份平台日志定位问题；日志不得记录 token 或 client secret。
