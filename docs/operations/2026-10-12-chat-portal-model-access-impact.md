# 开发 VM 模型授权收口影响（只读）

采集时间（数据库）：`2026-10-12T15:06:33.813514+00:00`。VM：`<开发 VM 地址>`；基线：`051e3e80`。

以下数字是旧方案在该采集时点的历史快照，不能作为保守方案的当前上线影响结论。旧方案按空模型条目与残存审计推断“未配置”并开放存量部门；审查要求撤回这一不可靠推断。同步任务已提供当时默认开放的历史明确授权，但本轮最新 A5 指示仍采用保守迁移。现采用保守迁移：不改变任何存量部门的 model_access_mode 或 team_models；只有新建普通部门默认 all_active。上线前须基于最终代码重新只读采集影响，用户名映射仅在受控交付记录保存。本文件不记录真实账号名或内网地址。

未读取密码、Key 明文/密文/hash、token 或供应商凭据值；未修改开发 VM 数据。

| 脱敏账号代号 | 角色 | 有效用户 Key | 应用/Key 路径数 | 现可用模型数 | 收口后模型数 | 减少数 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| U-01 | tenant_admin | 2 | 3 | 18 | 18 | 0 |
| U-02 | auditor | 0 | 1 | 18 | 18 | 0 |
| U-03 | platform_admin | 0 | 0 | 0 | 0 | 0 |
| U-04 | auditor | 0 | 1 | 18 | 18 | 0 |
| U-05 | platform_admin | 0 | 1 | 18 | 0 | 18 |
| U-06 | developer | 1 | 2 | 1 | 1 | 0 |
| U-07 | tenant_admin | 3 | 4 | 18 | 1 | 17 |

存量部门默认开放变更：0；原计划涉及的两个业务部门均保留既有策略。

减少模型的账号：2。

## U-05（platform_admin）

配额模型模式：`soft`。

现可用：`claude-opus-5-5`、`claude-sonnet-5-5`、`deepseek-flash`、`deepseek-v4-flash`、`deepseek-v4-flash-vision-exp`、`deepseek-v4-pro`、`gpt-5.6-luna`、`gpt-5.6-sol`、`gpt-5.6-terra`、`gpt-6-astra`、`gpt-6-luna`、`gpt-6-sol`、`gpt-6.1-sol`、`gpt-image-2`、`gpt-image-2.5-flare`、`gpt-image-2.5-sunburst`、`qwen2.5-7b-instruct-local`、`qwen3.8-27b-fp8`。

收口后：无。

差异模型（减少）：`claude-opus-5-5`、`claude-sonnet-5-5`、`deepseek-flash`、`deepseek-v4-flash`、`deepseek-v4-flash-vision-exp`、`deepseek-v4-pro`、`gpt-5.6-luna`、`gpt-5.6-sol`、`gpt-5.6-terra`、`gpt-6-astra`、`gpt-6-luna`、`gpt-6-sol`、`gpt-6.1-sol`、`gpt-image-2`、`gpt-image-2.5-flare`、`gpt-image-2.5-sunburst`、`qwen2.5-7b-instruct-local`、`qwen3.8-27b-fp8`。

## U-07（tenant_admin）

配额模型模式：`soft`。

现可用：`claude-opus-5-5`、`claude-sonnet-5-5`、`deepseek-flash`、`deepseek-v4-flash`、`deepseek-v4-flash-vision-exp`、`deepseek-v4-pro`、`gpt-5.6-luna`、`gpt-5.6-sol`、`gpt-5.6-terra`、`gpt-6-astra`、`gpt-6-luna`、`gpt-6-sol`、`gpt-6.1-sol`、`gpt-image-2`、`gpt-image-2.5-flare`、`gpt-image-2.5-sunburst`、`qwen2.5-7b-instruct-local`、`qwen3.8-27b-fp8`。

收口后：`claude-opus-5-5`。

差异模型（减少）：`claude-sonnet-5-5`、`deepseek-flash`、`deepseek-v4-flash`、`deepseek-v4-flash-vision-exp`、`deepseek-v4-pro`、`gpt-5.6-luna`、`gpt-5.6-sol`、`gpt-5.6-terra`、`gpt-6-astra`、`gpt-6-luna`、`gpt-6-sol`、`gpt-6.1-sol`、`gpt-image-2`、`gpt-image-2.5-flare`、`gpt-image-2.5-sunburst`、`qwen2.5-7b-instruct-local`、`qwen3.8-27b-fp8`。
