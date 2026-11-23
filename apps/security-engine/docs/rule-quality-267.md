# 2.6.7 规则误报专项验收（A）

范围：apps/security-engine。开发基线 81633371（2.6.6 b1fb04c7 加既有前台模式成果 4cb69be6）。未部署、未改生产配置、未打包。

## 根因与改动

- 危化规则原先全文 subject + instruction 共现。现在逐危险主体的局部句子配对，并识别作用于该主体的拒绝；逗号后的明确请求会撤销拒绝解释。远处软件操作步骤不再支撑危化告警。
- 毒品预防/劝阻讨论与实际贩售请求区分；政治人物姓名只证明提及人物，作为 observation 保留，威胁由独立暴力依据承担。
- 暴力规则按每个匹配的局部句子计算，良性新闻句不再降低后面的真实风险。明确的影视描述保留观察证据，不构成安全事件。
- 注入规则从首个 search 改为逐匹配，局部明确引用、文档代码样例、否定不再制造安全事件；引用外的指令、执行样例请求仍触发。优先选择真实风险匹配的位置和证据。
- 观察证据明确携带 counts_as_security_finding=false、action=allow、triage.disposition=observation。绑定策略保留身份而不反向升格观察线索；观察线索不能补全 all 能力组合。运行故障 audit/fail-closed 先于观察分支。
- 保留原严重度和原始匹配，不全局关闭规则、不批量降严重度。规则证据加入 confidence_kind=heuristic_rule_score，数值不是校准攻击概率或实测准确率。

## 冻结样本与结果

完整正文与对照在 tests/test_rule_quality_267.py 的 CASES：附件五条良性、五条接近的真实风险请求、每对良性在前/在后的十条混合请求。样本均为人工构造请求，没有实际危险操作细节或客户正文。

比较用当前 SecurityEngine 加真实 CompiledPolicy DTO、明确 block 绑定、source=user、source-aware 开、confidence gating 开、观察关闭，语义明确跳过。修前替换为基线 81633371 的两个检测器原实现，其他条件相同。

| 指标 | 修前 | 修后 |
|---|---:|---:|
| 良性请求总数 | 5 | 5 |
| 良性中至少一个计安全 finding 的请求 | 5 | 0 |
| 良性最终 allow / audit / block | 0 / 1 / 4 | 5 / 0 / 0 |
| 风险与混合请求总数 | 15 | 15 |
| 风险与混合至少一个计安全 finding | 15 | 15 |
| 风险与混合最终 block | 15 | 15 |

这是小型冻结回归集，不能外推生产误报率/漏报率。没有统计生产请求或安全事件的分母。

首次 47 条新增失败复现：32 failed、15 passed；修后通过。后续增加引用/代码/请求包裹、来源、all 策略和运行故障回归，目前新增规则文件 66 项、真实 HTTP 文件 2 项。

## 执行回执

目标环境：已有 docker-compose-security-engine:latest，image ID sha256:0838eba93ff4a52822438256db79e8d1da4783dee00f58945709aaf1d0409ea3，Python 3.11.15、pytest 9.1.1。仅启动临时容器，--network none、源码只读挂载、1 CPU、1536 MiB、临时 tmpfs；未操作生产容器。

- 目标 Python 3.11，138 项专项与相关回归：138 passed，1.37s。
- 真实 Uvicorn loopback HTTP：两种模式共 72 次请求；每种模式 5 组输入 + 4 组输出，各良性/风险/双向混合。鉴权开启、真实引擎路由和最终 action/策略身份/原始证据一致。输出本来不做用户意图注入扫描，因此没有用第 5 组输入注入样例伪造输出覆盖。
- compileall app：成功，字节码仅写入 tmpfs。
- 目标 Python 3.11 全模块：1764 passed、3 failed、1 skipped，64.02s。
- 三项失败均 tests/test_bench_scorers.py 的 numpy 缺失；在未改的 2.6.6 基线同镜像重跑该文件，得到相同 3 failed、6 passed，确认是已有环境缺依赖，不是本次规则回归。没有安装新依赖或将缺依赖改成跳过。
- 一项 skip 为本地 Qwen 8091 未运行；不计模型可靠性通过。
- 系统 Python 3.14.4 的对应 bench 文件补充检查：9 passed（39.47s），不能替代目标 3.11 结果。独立 HTTP wrapper 子进程启动/清理 smoke 成功。

可复用启动器：tests/run_quality_http_267.py。它启动真实认证 HTTP 后运行指定集成命令，把随机 token 和 loopback URL 仅通过子进程环境 JJDGUARD_TEST_ENGINE_URL / JJDGUARD_TEST_ENGINE_TOKEN 传递，不输出凭据。

## 真实控制面默认策略验收

主任务在独立 PostgreSQL 完成全部 194 项迁移，再通过真实 EnsurePlatformDefaults、ListCompilableRulesByTenant、rules.Compile 生成默认策略包（不是读取生产配置）。包包含 5 条 matcher、245 条 policies，SHA256：

4f2d4b68a84aedc6bbcb969a010d1cad01222302903aa86c9cbabc7d1e201d11

tests/run_rule_quality_pack_267.py 使用生产 _build_candidate / _apply_candidate 严格解析和应用全部规则、策略、例外与文件策略。目标 Python 3.11 的真实 Uvicorn + 内部 token 鉴权 HTTP 执行冻结 20 样本，两种模式共 40 次请求；详细逐请求回执见 default-policy-quality-267.json。

- 防护：5 良性全部 allow、0 个请求计安全 finding；15 风险/混合均有安全 finding，12 block、3 audit。
- 观察：5 良性全部 allow；15 风险/混合全部 audit、保留风险依据。
- 三条防护仍 audit 的请求为危化单独风险及其两种混合顺序：illegal_hazardous_chemical_instructions 没有匹配当前默认策略绑定，所以按既有约定只 audit，不暗中越过前台策略执行 block。不能将这三条宣称已阻止。
- 包是默认初始化策略，不是客户生产配置；上述结果与前面自建 block 压力组分列。HTTP startup 同步和语义模型均未参与。

## 未验证边界

- 已完成正式默认策略编译包的 HTTP 验收；仍不等于客户当前生产策略。危化默认未绑定，不满足前台启用该项阻断的条件。
- HTTP harness 使用 lifespan=off，避免后台启动同步；因此不是签名配置分发或全节点模式生效的验收。
- 语义明确跳过，不是 Tier1/Judge ready/completed、完成率或模型准确率证据。
- source-aware 的 tool_result 普通注入规则缺口保留现状并显式记录，交 B/C 入口工作流验证；不能把 tool_result 无 finding 解释为本轮规则通过。
- 规则属于有限语言上下文启发式；长文本间接引用、罕见否定、嵌套指令需更大冻结集与语义证据。不能凭这 20 条样本开启客户全局阻断。
- confidence_kind 已通过 API triage 返回；前台是否正确解释规则分数需总集成核验，本分支未改界面。

回滚：回退本分支提交即可，无数据库迁移、历史回填或生产数据恢复动作。
