-- 112_tool_event_runtime_truth.sql
-- Add proof-oriented tool lifecycle facts without rewriting the existing audit table.
-- Historical rows remain NULL; read paths derive only conservative legacy categories.

ALTER TABLE tool_call_logs
  ADD COLUMN IF NOT EXISTS event_kind VARCHAR(32),
  ADD COLUMN IF NOT EXISTS execution_observed BOOLEAN,
  ADD COLUMN IF NOT EXISTS result_observed BOOLEAN,
  ADD COLUMN IF NOT EXISTS tool_call_id TEXT,
  ADD COLUMN IF NOT EXISTS asset_id VARCHAR(128),
  ADD COLUMN IF NOT EXISTS skill_invocation_id TEXT,
  ADD COLUMN IF NOT EXISTS mcp_server_id VARCHAR(128),
  ADD COLUMN IF NOT EXISTS mcp_tool_id VARCHAR(128),
  ADD COLUMN IF NOT EXISTS definition_hash VARCHAR(128),
  ADD COLUMN IF NOT EXISTS attribution_mode VARCHAR(16),
  ADD COLUMN IF NOT EXISTS attribution_confidence DOUBLE PRECISION;

-- 版本表原先只按 policy_id 外键关联，无法阻止 tenant_id 指向另一租户策略。
-- policies.id 已是全局主键，因此补 (tenant_id,id) 唯一约束不会改变既有唯一性；
-- 复合 FK 使用 NOT VALID 兼容历史数据，但从创建起即约束所有新写入。
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'agentguard_policies'::regclass
      AND conname = 'agentguard_policies_tenant_id_id_key'
  ) THEN
    ALTER TABLE agentguard_policies
      ADD CONSTRAINT agentguard_policies_tenant_id_id_key
      UNIQUE (tenant_id, id);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'agentguard_policy_versions'::regclass
      AND conname = 'agentguard_policy_versions_tenant_policy_fk'
  ) THEN
    ALTER TABLE agentguard_policy_versions
      ADD CONSTRAINT agentguard_policy_versions_tenant_policy_fk
      FOREIGN KEY (tenant_id, policy_id)
      REFERENCES agentguard_policies (tenant_id, id)
      ON DELETE CASCADE
      NOT VALID;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'tool_call_logs'::regclass
      AND conname = 'tool_call_logs_event_kind_check'
  ) THEN
    ALTER TABLE tool_call_logs
      ADD CONSTRAINT tool_call_logs_event_kind_check
      CHECK (event_kind IN (
        'legacy_unknown',
        'definition_exposed',
        'invocation_proposed',
        'execution_forwarded',
        'result_observed',
        'confirmation_replay'
      )) NOT VALID;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'tool_call_logs'::regclass
      AND conname = 'tool_call_logs_attribution_mode_check'
  ) THEN
    ALTER TABLE tool_call_logs
      ADD CONSTRAINT tool_call_logs_attribution_mode_check
      CHECK (attribution_mode IN ('explicit', 'linked', 'inferred', 'none')) NOT VALID;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'tool_call_logs'::regclass
      AND conname = 'tool_call_logs_attribution_confidence_check'
  ) THEN
    ALTER TABLE tool_call_logs
      ADD CONSTRAINT tool_call_logs_attribution_confidence_check
      CHECK (
        (attribution_mode IS NULL AND attribution_confidence IS NULL)
        OR (
          attribution_mode IS NOT NULL
          AND attribution_confidence IS NOT NULL
          AND attribution_confidence >= 0
          AND attribution_confidence <= 1
        )
      ) NOT VALID;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'tool_call_logs'::regclass
      AND conname = 'tool_call_logs_execution_fact_check'
  ) THEN
    ALTER TABLE tool_call_logs
      ADD CONSTRAINT tool_call_logs_execution_fact_check
      CHECK (
        (event_kind IS NULL AND execution_observed IS NULL AND result_observed IS NULL)
        OR (
          event_kind IS NOT NULL
          AND execution_observed IS NOT NULL
          AND result_observed IS NOT NULL
          AND (event_kind = 'execution_forwarded') = execution_observed
        )
      ) NOT VALID;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'tool_call_logs'::regclass
      AND conname = 'tool_call_logs_block_not_executed_check'
  ) THEN
    ALTER TABLE tool_call_logs
      ADD CONSTRAINT tool_call_logs_block_not_executed_check
      CHECK (
        COALESCE(effective_decision, '') NOT IN ('block', 'confirm')
        OR execution_observed IS NOT TRUE
      ) NOT VALID;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'tool_call_logs'::regclass
      AND conname = 'tool_call_logs_result_fact_check'
  ) THEN
    ALTER TABLE tool_call_logs
      ADD CONSTRAINT tool_call_logs_result_fact_check
      CHECK (
        (event_kind IS NULL AND result_observed IS NULL)
        OR (
          event_kind IS NOT NULL
          AND (result_observed IS NOT TRUE OR event_kind IN ('execution_forwarded', 'result_observed'))
          AND (event_kind <> 'result_observed' OR result_observed IS TRUE)
        )
      ) NOT VALID;
  END IF;
END $$;

DO $$
DECLARE
  invalid_index RECORD;
BEGIN
  FOR invalid_index IN
    SELECT n.nspname, index_rel.relname
    FROM pg_index i
    JOIN pg_class index_rel ON index_rel.oid = i.indexrelid
    JOIN pg_class table_rel ON table_rel.oid = i.indrelid
    JOIN pg_namespace n ON n.oid = table_rel.relnamespace
    WHERE table_rel.oid = 'tool_call_logs'::regclass
      AND index_rel.relnamespace = table_rel.relnamespace
      AND index_rel.relname IN (
        'idx_tool_call_logs_tenant_event_created',
        'idx_tool_call_logs_tenant_tool_call_id'
      )
      AND NOT i.indisvalid
  LOOP
    EXECUTE format('DROP INDEX %I.%I', invalid_index.nspname, invalid_index.relname);
  END LOOP;
END $$;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tool_call_logs_tenant_event_created
  ON tool_call_logs (tenant_id, event_kind, created_at DESC)
  WHERE event_kind IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tool_call_logs_tenant_tool_call_id
  ON tool_call_logs (tenant_id, tool_call_id)
  WHERE tool_call_id IS NOT NULL AND tool_call_id <> '';

DO $$
DECLARE
  valid_runtime_indexes INTEGER;
BEGIN
  SELECT count(*) INTO valid_runtime_indexes
  FROM pg_index i
  JOIN pg_class index_rel ON index_rel.oid = i.indexrelid
  JOIN pg_class table_rel ON table_rel.oid = i.indrelid
  WHERE table_rel.oid = 'tool_call_logs'::regclass
    AND index_rel.relnamespace = table_rel.relnamespace
    AND index_rel.relname IN (
      'idx_tool_call_logs_tenant_event_created',
      'idx_tool_call_logs_tenant_tool_call_id'
    )
    AND i.indisvalid;

  IF valid_runtime_indexes <> 2 THEN
    RAISE EXCEPTION 'runtime-truth indexes are missing or invalid: %/2 valid', valid_runtime_indexes;
  END IF;
END $$;

COMMENT ON COLUMN tool_call_logs.event_kind IS
  '可证明的工具生命周期事件；definition_exposed 仅表示网关观察到客户端提交工具定义，不证明定义已送达模型；NULL 表示迁移前未知，查询层保守派生且不得按 status 推断执行';
COMMENT ON COLUMN tool_call_logs.execution_observed IS
  '网关是否收到上游响应并据此证明请求已转发；连接或握手失败不得为 true';
COMMENT ON COLUMN tool_call_logs.result_observed IS
  '网关是否观察到工具结果；不能单独证明本地客户端已执行';
COMMENT ON COLUMN tool_call_logs.tool_call_id IS
  'OpenAI/Anthropic tool_call_id 或 MCP JSON-RPC id，用于关联拟调用与结果';
COMMENT ON COLUMN tool_call_logs.asset_id IS
  '网关可见工具或 Skill 资产标识';
COMMENT ON COLUMN tool_call_logs.skill_invocation_id IS
  'Skill 调用链标识；无端侧时可能为空';
COMMENT ON COLUMN tool_call_logs.mcp_server_id IS
  'MCP Server 资产标识';
COMMENT ON COLUMN tool_call_logs.mcp_tool_id IS
  'MCP Tool 资产标识';
COMMENT ON COLUMN tool_call_logs.definition_hash IS
  '工具名称、描述与输入 Schema 的规范化 SHA-256';
COMMENT ON COLUMN tool_call_logs.attribution_mode IS
  '归因方式：explicit/linked/inferred/none';
COMMENT ON COLUMN tool_call_logs.attribution_confidence IS
  '归因置信度，范围 0..1';
