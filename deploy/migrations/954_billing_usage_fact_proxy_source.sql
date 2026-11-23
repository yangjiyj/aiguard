-- 954: 正向代理按用量计费。
--
-- 1. usage_source 标记计费事实来自哪条链路：'gateway'（网关 API，历史行全部是它）或
--    'forward_proxy'（proxy-server 解密的大模型流量）。ADD COLUMN ... NOT NULL DEFAULT 常量
--    在 PostgreSQL 11+ 只改元数据、不重写表，也不会触发 append-only 触发器。
-- 2. status 新增 'usage_unknown'：请求成功但解析不出 token 用量（网页版 ChatGPT/Claude 等），
--    token 全 0、金额 0，进入「计费待处理」，不得静默丢弃，也不得被当成“已定价 0 元”。
--
-- 两个 CHECK 都用 NOT VALID 加：只约束新写入的行，不对历史行做全表校验扫描。
-- 历史行天然满足：status 原约束是新约束的子集，usage_source 全部取默认值 'gateway'。
-- 只新增、不改旧迁移；可在空库和现有库重复执行。
ALTER TABLE billing_usage_facts
    ADD COLUMN IF NOT EXISTS usage_source VARCHAR(32) NOT NULL DEFAULT 'gateway';

ALTER TABLE billing_usage_facts DROP CONSTRAINT IF EXISTS ck_billing_usage_fact_usage_source;
ALTER TABLE billing_usage_facts
    ADD CONSTRAINT ck_billing_usage_fact_usage_source
    CHECK (usage_source IN ('gateway', 'forward_proxy')) NOT VALID;

ALTER TABLE billing_usage_facts DROP CONSTRAINT IF EXISTS ck_billing_usage_fact_status;
ALTER TABLE billing_usage_facts
    ADD CONSTRAINT ck_billing_usage_fact_status
    CHECK (status IN ('settled', 'released', 'unpriced', 'failed', 'usage_unknown')) NOT VALID;

COMMENT ON COLUMN billing_usage_facts.usage_source IS 'gateway = 网关 API 计量；forward_proxy = 正向代理解密的大模型流量（结算后记账，最多超出一次请求的用量）';
