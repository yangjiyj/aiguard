# 网关发版 Runbook

本文定义私有化交付版本从切版到客户升级台账的标准动作。版本号唯一来源是仓库根 `VERSION`。

## 0. 日常修复合入与发布分开执行

日常功能修复先在隔离工作树完成组合验证，再合入 `main`，同步 Gitee 和
`/srv/git/jjdguard-src.git` 中心仓库，并核对三处完整 commit SHA 一致。
Gitee 是 `git@gitee.com:examplegw/agent-compute-gateway.git`；
旧路径 `/home/dev/newapi-enterprise.git` 不作为这里的中心发布基准。

合并、提交和普通 Git 推送本身不构建镜像，也不更新运行容器。不需要为了让源码
与运行环境暂时相同而立即部署。将“已经合入、等待发布”的修复记录在台账中即可。
如果以后增加会自动构建或部署的 CI、Git hook，须同步修改这里的流程说明。

确定发布范围后，再固定一个已经核验的 `main` revision，按下文适用的发布入口
构建候选、验收和晋级。已经验收的候选直接晋级，不在部署时从新的工作区重建同名制品。
数据库迁移单独列入发布计划；home 单服务入口不会代为执行数据库迁移。

源码台账记录 revision/tree；运行台账按服务记录完整 image ID（有 registry 时同时记录
digest）、镜像 revision 标签、配置快照、迁移版本和回滚锚点。版本号和 `latest` 标签
不能独立证明运行内容。部分服务保留旧制品时，应记录每个服务实际状态，不能用一个
新 revision 标签代表全部服务都已更新。

镜像数量与内容漂移分别处理。保留当前运行镜像和已验证回滚镜像；镜像清理应另行核对
引用关系、回滚需要及备份，不能把删除全部旧镜像作为合并修复的步骤。

2026-09-05 两批修复的组合验证和当前 VM 边界见
[修复集成记录](security-fixes-integration-20260905.md)。

## 1. 切版本

1. 修改 `VERSION`，使用 SemVer，例如 `1.4.0`。
2. 在 `CHANGELOG.md` 新增同版本段，记录面向客户可理解的新增、变更、修复和安全项。
3. 确认控制面版本接口、服务启动日志和离线包脚本均不硬编码版本号。

## 2. 全量验证

在发版分支执行对应模块测试与构建。至少包含：

```bash
cd apps/control-plane
GOFLAGS=-buildvcs=false GOWORK=off go test ./internal/handler ./internal/license

cd ../../
bash -n deploy/docker-compose/package-offline-bundle.sh
bash -n deploy/docker-compose/promote-offline-release.sh
bash -n deploy/docker-compose/upgrade.sh
bash -n deploy/docker-compose/deploy-offline.sh
bash -n deploy/docker-compose/deploy-oneclick.sh
bash deploy/tests/test_offline_promotion.sh
bash deploy/tests/test_self_extracting_installer.sh
bash deploy/tests/test_customer_installer_contract.sh
```

涉及数据面、审计、鉴权或计费改动时，按模块补跑完整测试。

### 2.1 home 单服务受控发布

本节只适用于 home 运行环境的 `control-plane` / `web-console` 小步更新，不替代客户
离线包的打包、验收和晋级流程。

发布前先确认当前目录是独立、干净的 `main` 工作树。禁止手工 docker build + Compose override，
也不得复用长期停留在功能分支的工作树。唯一入口如下：

```bash
release_id="home-release-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%dt%H%M%Sz)"

deploy/release/home-service-release.sh \
  --repo "$PWD" \
  --runtime-root /home/dev/jjdguard \
  --central-bare /srv/git/jjdguard-src.git \
  --service control-plane \
  --service web-console \
  --release-id "$release_id"
```

`--service` 可以只传一个，也可以同时传两个；只允许 `control-plane` 和
`web-console`。同时发布时固定按 `control-plane -> web-console` 顺序执行。

入口会依次验证：

1. 全局发布锁可用，源码工作树干净且等于实时 Gitee `main`。Git 信任链固定使用
   系统 Git、最小 `env -i` 环境并拒绝 replace refs，不继承调用者的 `GIT_*` 或 `PATH` shim。
2. `/srv/git/jjdguard-src.git main` 与源码完整 revision 一致，中心 bare 同样不得存在
   replace refs。
3. fixture 的 repo、runtime、central、lock、origin 和 fake Docker 必须同属一个临时根，
   且临时根不得与生产路径重叠；生产 Docker 固定为 `/usr/bin/docker` 和本机
   `/var/run/docker.sock`，不继承调用者的 Docker/Compose 环境。
4. 从已验证 revision 的不可变 `git archive` 构建，清除调用者的 Go、Node 和 Vite
   环境；`control-plane` 明确使用 `-buildvcs=false`。
5. 两个目标属于同一 Compose project 和 working directory，但各自保留自己的
   `config_files` 链。项目全部运行服务都会记录并复核容器 ID、image ID、status、
   health、restart、working directory、config files 和 live `config-hash`。非目标服务
   可以保留历史非负 `RestartCount`，但发布期间不得增加；目标服务发布前和重建后都必须为 0。
6. 候选覆盖完整运行时输入：`control-plane` 的二进制、`VERSION`、`deploy/seeds`，
   以及 `web-console` 的 `dist`、`server.js`。文件模式、完整运行树 SHA-256、基础镜像、
   候选 image ID、完整 revision/tree 和组件 tree 均经镜像导出回读复核。
7. 先把 Compose 渲染为规范化 JSON，并把目标服务的 `env_file`、文件型 `configs` /
   `secrets` 结构化枚举、限定在 runtime root、记录 SHA-256；解析后的环境值只保存在
   `0700/0600` 的受保护快照中。live `config-hash` 必须与该规范化模型回送 Compose
   后的 hash 一致。禁止把原始 Compose 文件链直接执行 `config --hash` 后与 live label
   比较；含 `env_file` 时两种口径并不等价，会制造假漂移。
8. 候选和回滚均从受保护快照使用完整 image ID 执行，不再让 Compose 读取可变 tag、
   `.env`、原始配置链或 service-level `env_file`。每次 apply 前重新核验实时 Gitee、
   中心 bare、所有受控文件哈希、不可变快照、全项目运行态、候选标签/运行树和 rollback
   锚点；两个服务之间出现任一漂移时停止后续服务并逆序回滚。
9. 每个服务替换后从真实运行容器复核健康、重启次数、Compose config-hash、完整产物树
   和全项目状态。
   `web-console` 只扫描 `index.html` 实际可达的 JS/CSS 资产，忽略 sourcemap 和未引用
   文件，再由浏览器强制刷新完成最终页面验收。
10. 任一步失败时，先恢复当前尝试服务，再逆序恢复本次已切换服务。

普通证据保存在 `/home/dev/jjdguard/home-deployments/<release-id>/`，只记录路径、哈希和
运行身份，不写入环境值。含解析后环境变量的 Compose 快照单独保存在
`/home/dev/jjdguard/home-compose-snapshots/<release-id>/`，目录必须为 `0700`、文件必须为
`0600`，并作为回滚输入保留。入口不执行数据库迁移，不清理旧镜像、旧快照、rollback tag
或失败证据。失败后先查看 `release.log` 和 `rollback-tags.tsv`；若出现
`manual intervention required`，停止继续发布并按回执中的完整 image ID 人工处理。

`JJDGUARD_HOME_RELEASE_FIXTURE=1`、`JJDGUARD_HOME_RELEASE_FIXTURE_ROOT`、
`JJDGUARD_HOME_RELEASE_LOCK_FILE` 和 `JJDGUARD_HOME_RELEASE_EXPECTED_REMOTE` 仅供自动化
测试创建同根临时 Git/fake-Docker fixture，生产发布禁止设置。

### 2.2 测试虚拟机开发更新

现有 jjdguard-gateway 的固定制品更新见 [测试 VM 更新入口](vm-development-release.md)。
该入口与客户安装包分开执行，记录开发发布 revision，不冒充正式交付验收。

## 3. 打包与正式晋级

1. 构建并锁定 Docker 镜像 digest。
2. 在 `deploy/docker-compose` 目录完成镜像准备。
3. 从经核验的 Gitee main 干净检出构建候选包：

```bash
BUNDLE_PROFILE=full INCLUDE_CHAT=1 \
bash deploy/docker-compose/package-offline-run.sh amd64 \
  /home/dev/jjdguard-deliverables/<release>/candidate
```

构建端可以使用受控发布 key 生成内部 provenance，但客户侧不需要 key、Python、
OpenSSL、独立 verifier 或任何签名操作。候选 .run 通过自身 SHA-256/清单校验后才进入验收。

4. 使用同一份候选 .run 在隔离 VM 完成全新安装、断网重启、从现网同构状态升级、
失败恢复、回滚、回滚后再升级、浏览器、模型、安全和 Chat 验收。所有必测场景必须为
PASS，并生成绑定这份 .run 字节的 receipt 和 evidence index。

### 开发发布部署接管矩阵（自 2.6.14 后的候选版起必测）

在**隔离验收 VM**，使用同一候选 .run 的 SHA-256 固定输入，单独运行：

1. 全新安装正式 N-1 包，保存数据库业务标记、迁移水位、Compose 配置中环境变量、
   端口、卷、网络与安全检测预算的指纹，不把敏感环境值写进普通报告。
2. 用 `deploy/release/deploy_vm_development.py` 的受控入口更新该 VM。验收
   `development-releases/current.json`、`receipt.json` 和运行容器的
   `active-config/dev-*.json` 一致；receipt 的 `compose_sha256` 必须等于
   运行配置的 SHA-256。
3. 用候选 .run 原字节升级。核对新旧业务标记、数据库迁移、服务 image ID、
   Compose 项目身份，以及第 1 步记录的客户环境、端口、卷、网络和检测预算。
   开发发布的完整规范化配置只在回执哈希绑定时继承，候选正式镜像 override
   必须是最后一层。篡改回执或配置哈希的负例必须在停写前拒绝。
4. 从升级后状态执行 `jjdctl rollback`，核对旧版本和旧完整配置恢复、业务写入
   保留；再用同一候选 .run 重升并重复关键核对。

这项矩阵必须与常规「正式 N-1 → 候选版」矩阵分别记录。候选代码在功能分支时
只跑合同测试；正式 .run 必须等合入 main、由受控打包入口生成后才运行此矩阵。
5. main 未前进且验收全部通过后，将候选 .run 原字节复制到 final 目录并重新计算
同名 .run.sha256；不重新构建、不混装、不通过客户侧 promotion/verifier。final 目录
同时保留发布回执、源码/镜像 provenance、SBOM 和验收证据。

离线包文件名必须包含 `VERSION` 中的版本号。候选包和正式包的内部内容都必须包含：

- `VERSION`
- `manifest.json`
- `RELEASE_NOTES.md`
- `deploy/docker-compose/manifest.json`
- `deploy/docker-compose/RELEASE_NOTES.md`

### 3.0 客户直装契约

客户交付只需要同目录的 .run 和 .run.sha256。客户主机不需要 Python、
pip、OpenSSL、独立 verifier、公钥或手工签名操作；.run 自己完成 payload、版本、
架构、清单、源码 provenance、SBOM 和文件 SHA-256 校验，然后进入首次安装或原地升级。

正式验收使用的就是交付的同一份 .run 字节。发布端保留源码、镜像、SBOM 和验收台账；
旧 promotion/verifier 工具只作为仓库内的历史兼容工具，不是客户安装前置。

适用矩阵为 Linux amd64/x86_64，包括海光 CPU 以及麒麟、统信、欧拉等 amd64 发行版。
ARM 和 loongarch64 需要单独的镜像、Docker 静态引擎和发布包，本版本不宣称支持。

### 3.1 客户直装边界（不需要签名前置）

客户交付只需要同目录的 `.run` 和 `.run.sha256`。客户主机不需要 Python、
pip、OpenSSL、独立 verifier、公钥、证书或手工签名操作。`.run` 自己完成 payload、
版本、架构、清单、源码 provenance、SBOM 和文件 SHA-256 校验，然后进入首次安装或原地升级。

发布端可以保留内部 provenance、验收回执和历史签名文件用于审计，但它们不进入客户
安装步骤，也不要求复制到客户主机。客户只需核对 SHA-256 后直接运行同一份 `.run`。

升级失败时，先保留失败日志、旧发布目录和数据库备份，再执行：

```bash
sudo jjdctl rollback
sudo jjdctl status
```

`rollback` 只适用于存在完整升级记录和备份的环境。不要通过删除数据卷、重建 PostgreSQL 或 Redis 来追求“干净”状态。

### 3.2 交付证据

发布台账至少记录：候选和正式 `.run` 的 SHA-256、source revision/tree、image provenance 与
SBOM 摘要、验收回执和证据索引摘要、晋级时间、客户安装/升级结果与回滚锚点。客户侧
只以 `.run` 自校验、同名 SHA-256 和真实运行态验收为准，不执行独立 verifier 或签名操作。

### 3.3 升级耗时和数据保留合同

- 制品校验、导入和一致性数据库备份在旧版运行期间完成；停止写入后只执行必要的 schema 与应用切换。
- 普通失败回退与 jjdctl rollback 均保留当前数据库、已提交迁移和新增业务数据，不自动导入旧备份。
- 不兼容历史变更须先验证旧应用在升级后 schema 上的行为；回退健康检查失败时保留证据，不能把在线备份当作无损自动撤销。
- jjdctl disaster-restore --confirm-data-loss 是独立的显式灾难恢复；在线备份之间的新增写入可能丢失。需要更低 RPO 时另行配置并演练 WAL/PITR。
- 历史日志后台任务继续使用同一任务版本与 checkpoint，服务恢复不等待历史回填。分别报告在线备份耗时、实际停机窗口和后台进度。
- 回滚验收必须检查旧应用版本、新迁移仍存在、升级后新写入仍可读；禁止以“迁移记录被删除”作为普通应用回滚通过条件。
- 构建与验收串行运行，生产恢复优先；开始前核实宿主机可用内存并关闭本任务空闲验收 VM。不能让出包占满生产宿主内存。

## 4. 打 tag

验证通过后打 tag：

```bash
git tag -a "v$(cat VERSION)" -m "JJDGUARD $(cat VERSION)"
```

不要在自动化检查未通过时打正式 tag。

## 5. 客户离线安装与升级

2.6.7 在客户 Linux amd64 主机上的直接步骤：

```bash
cd /交付目录
sha256sum -c JJDGuard-offline-2.6.7-amd64.run.sha256
chmod +x JJDGuard-offline-2.6.7-amd64.run
sudo bash JJDGuard-offline-2.6.7-amd64.run
```

首次执行会安装；已有 JJDGuard 时会保留数据、配置、权限和运行环境，执行原地升级。
安装器会自动完成包内校验、镜像导入、数据库迁移、健康检查和失败回滚准备。不要手动
解包 tar、执行内部 install.sh、安装 Python 或执行签名/verifier 命令。

升级失败时先保留完整终端输出和安装目录，然后在目标机执行 sudo jjdctl rollback
和 sudo jjdctl status；不要删除 PostgreSQL/Redis 数据卷来“重装”。

## 6. 客户版本台账

每个客户环境维护一行台账，建议字段：

| 字段 | 说明 |
| --- | --- |
| 客户名称 | 合同或项目名称 |
| 环境 ID | 生产、预发、灾备等 |
| 当前版本 | 来自 `/admin/v1/system/version` 的 `version` |
| 上一版本 | 升级前版本 |
| 升级时间 | ISO 8601 时间 |
| 正式交付物 | final `.run`、同名 `.run.sha256`、发布说明、安装/升级/回滚说明 |
| 镜像 digest | 来自 `.upgrade/current-digests.env` |
| 操作人 | 实施或运维负责人 |
| 备注 | 回滚、补丁、异常说明 |

现场验收时，用控制面版本接口和升级状态文件交叉确认客户当前版本。

## 7. 受控测试虚拟机的 Chat / 计费联动发布

控制面、网关、控制台、Chat 门户和 Chat 代理的联动变更使用
`deploy/release/build_vm_development.py --identity-chat-only` 构建。
若本次还修改了正向代理服务，必须显式追加 `--include-proxy-server`，并在
`--bases` 指定的冻结镜像映射中纳入 `proxy-server`；默认范围仍是原有五个服务。
该选项仅能与 `--identity-chat-only` 同时使用，不允许任意扩展服务或调整模型、安全容量配置。

构建入口校验实时 Gitee main 和中心 bare main，冻结源码、镜像及审阅过的迁移。
发布使用 `deploy/release/deploy_vm_development.py --persist-boot`，执行入口封锁、
写入排空、数据库备份、迁移、镜像替换、运行契约核验和启动配置持久化。
不得直接 Compose 构建或替换容器；发布回执必须包含全部五个或显式选择的六个服务。

失败时入口保持封锁，完成数据库和所有目标镜像的恢复后才重新开放。
已成功发布后的回退使用 `--rollback-identity-chat-release-id` 和固定回执 SHA256；
该回退保留发布后产生的业务数据，并同时恢复原有启动配置与目标服务镜像。
