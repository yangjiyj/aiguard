-- Agent destructive-operation policy and lifecycle evidence.
-- Legacy audit-only configuration is consumed once from system_settings.

CREATE OR REPLACE FUNCTION agent_destructive_json_string_array_valid(value_json jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
  item jsonb;
BEGIN
  IF value_json IS NULL OR jsonb_typeof(value_json) <> 'array' THEN
    RETURN FALSE;
  END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(value_json)
  LOOP
    IF jsonb_typeof(item) <> 'string' OR btrim(item #>> '{}') = '' THEN
      RETURN FALSE;
    END IF;
  END LOOP;
  RETURN TRUE;
END
$$;

CREATE OR REPLACE FUNCTION agent_destructive_paths_valid(paths_json jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
  item jsonb;
  path_value text;
BEGIN
  IF NOT agent_destructive_json_string_array_valid(paths_json) THEN
    RETURN FALSE;
  END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(paths_json)
  LOOP
    path_value := btrim(item #>> '{}');
    IF left(path_value, 1) IN ('/', chr(92))
       OR path_value ~ '^[A-Za-z]:'
       OR path_value LIKE '~%'
       OR path_value = '.'
       OR path_value LIKE './%'
       OR left(path_value, 2) = '.' || chr(92)
       OR path_value ~ '(^|[\\/])\.\.([\\/]|$)'
       OR path_value ~ '[*?]' THEN
      RETURN FALSE;
    END IF;
  END LOOP;
  RETURN TRUE;
END
$$;

CREATE OR REPLACE FUNCTION agent_destructive_project_legacy_mode(legacy_mode text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT CASE lower(btrim(legacy_mode))
    WHEN 'observe' THEN 'audit'
    ELSE lower(btrim(legacy_mode))
  END
$$;

CREATE OR REPLACE FUNCTION agent_destructive_legacy_audit_only(legacy_value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT CASE
    WHEN lower(btrim(legacy_value)) IN ('0', 'false', 'no', 'off') THEN false
    WHEN lower(btrim(legacy_value)) IN ('1', 'true', 'yes', 'on') THEN true
    ELSE true
  END
$$;

CREATE TABLE IF NOT EXISTS agent_destructive_policies (
  id varchar(64) PRIMARY KEY,
  tenant_id varchar(64) NOT NULL,
  scope_type varchar(16) NOT NULL,
  scope_ref varchar(128) NOT NULL DEFAULT '',
  mode varchar(16) NOT NULL,
  action varchar(16) NOT NULL,
	protocol varchar(16) NOT NULL DEFAULT '',
  discardable_paths_json jsonb NOT NULL DEFAULT
    '["dist","tmp","build",".cache","node_modules","test-output"]'::jsonb,
  notify_channel_ids_json jsonb NOT NULL DEFAULT '[]'::jsonb,
  version bigint NOT NULL DEFAULT 1,
  enabled boolean NOT NULL DEFAULT true,
  created_by varchar(128) NOT NULL DEFAULT 'system',
  updated_by varchar(128) NOT NULL DEFAULT 'system',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_destructive_policies_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  CONSTRAINT agent_destructive_policies_tenant_id_id_key
    UNIQUE (tenant_id, id),
  CONSTRAINT agent_destructive_policies_scope_check
    CHECK (
      (scope_type = 'tenant' AND scope_ref = '')
      OR (scope_type IN ('application', 'agent') AND btrim(scope_ref) <> '')
    ),
  CONSTRAINT agent_destructive_policies_mode_check
    CHECK (mode IN ('audit', 'light', 'strict')),
  CONSTRAINT agent_destructive_policies_action_check
    CHECK (action IN ('record', 'alert_allow', 'confirm', 'block')),
	CONSTRAINT agent_destructive_policies_protocol_check
	  CHECK (protocol IN ('', 'mcp')),
	CONSTRAINT agent_destructive_policies_confirm_capability_check
	  CHECK (
	    action <> 'confirm'
	    OR (scope_type IN ('application', 'agent') AND protocol = 'mcp')
	  ),
  CONSTRAINT agent_destructive_policies_paths_check
    CHECK (agent_destructive_paths_valid(discardable_paths_json)),
  CONSTRAINT agent_destructive_policies_notify_channels_check
    CHECK (agent_destructive_json_string_array_valid(notify_channel_ids_json)),
  CONSTRAINT agent_destructive_policies_version_check
    CHECK (version > 0)
);

CREATE TABLE IF NOT EXISTS agent_destructive_policy_audits (
	id varchar(64) PRIMARY KEY,
	tenant_id varchar(64) NOT NULL,
	actor_id varchar(128) NOT NULL,
	source varchar(32) NOT NULL,
	scope_type varchar(16) NOT NULL,
	scope_ref varchar(128) NOT NULL DEFAULT '',
	before_json jsonb NOT NULL,
	after_json jsonb NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT agent_destructive_policy_audits_tenant_fk
	  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_agent_destructive_policy_audits_tenant_created
	ON agent_destructive_policy_audits (tenant_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_destructive_policies_enabled_scope
  ON agent_destructive_policies (tenant_id, scope_type, scope_ref)
  WHERE enabled;

CREATE INDEX IF NOT EXISTS idx_agent_destructive_policies_tenant_updated
  ON agent_destructive_policies (tenant_id, updated_at DESC);

CREATE OR REPLACE FUNCTION initialize_agent_destructive_policies_from_legacy(
  legacy_security_audit_only boolean
)
RETURNS integer
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
DECLARE
  inserted_count integer;
BEGIN
  INSERT INTO agent_destructive_policies (
    id, tenant_id, scope_type, scope_ref, mode, action, created_by, updated_by
  )
  SELECT
    'adp_legacy_' || md5(t.id),
    t.id,
    'tenant',
    '',
    CASE WHEN legacy_security_audit_only THEN 'audit' ELSE 'strict' END,
    CASE WHEN legacy_security_audit_only THEN 'record' ELSE 'block' END,
    'legacy_setting',
    'legacy_setting'
  FROM tenants AS t
  WHERE NOT EXISTS (
    SELECT 1
    FROM agent_destructive_policies AS p
    WHERE p.tenant_id = t.id
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_count = ROW_COUNT;
  RETURN inserted_count;
END
$$;

DO $$
DECLARE
  initialization_complete boolean := false;
  legacy_audit_only boolean := true;
BEGIN
  SELECT lower(btrim(value)) IN ('1', 'true', 'yes', 'on')
    INTO initialization_complete
  FROM system_settings
  WHERE key = 'agent_destructive_legacy_policy_initialized_v1';

  IF NOT COALESCE(initialization_complete, false) THEN
    SELECT agent_destructive_legacy_audit_only((
      SELECT value FROM system_settings
      WHERE key = 'security_audit_only'
    ))
    INTO legacy_audit_only;

    PERFORM initialize_agent_destructive_policies_from_legacy(
      COALESCE(legacy_audit_only, true)
    );

    INSERT INTO system_settings(key, value, updated_at)
    VALUES ('agent_destructive_legacy_policy_initialized_v1', 'true', now())
    ON CONFLICT (key) DO UPDATE
    SET value = 'true',
        updated_at = EXCLUDED.updated_at;
  END IF;
END
$$;

ALTER TABLE tool_call_logs
  ADD COLUMN IF NOT EXISTS operation_id varchar(128),
  ADD COLUMN IF NOT EXISTS event_type varchar(48),
  ADD COLUMN IF NOT EXISTS risk_category varchar(64),
  ADD COLUMN IF NOT EXISTS risk_subcategory varchar(64),
  ADD COLUMN IF NOT EXISTS reason_summary text,
	ADD COLUMN IF NOT EXISTS public_event_id varchar(64),
  ADD COLUMN IF NOT EXISTS target_summary text,
  ADD COLUMN IF NOT EXISTS mode_default_action varchar(16),
  ADD COLUMN IF NOT EXISTS custom_action varchar(16),
  ADD COLUMN IF NOT EXISTS final_action varchar(16),
  ADD COLUMN IF NOT EXISTS notification_required boolean,
  ADD COLUMN IF NOT EXISTS notification_status varchar(16),
  ADD COLUMN IF NOT EXISTS discardable_path_matched boolean,
  ADD COLUMN IF NOT EXISTS discardable_path_reason text,
  ADD COLUMN IF NOT EXISTS execution_forwarded boolean,
  ADD COLUMN IF NOT EXISTS application_id varchar(128),
  ADD COLUMN IF NOT EXISTS agent_type varchar(128),
  ADD COLUMN IF NOT EXISTS model varchar(256),
  ADD COLUMN IF NOT EXISTS protocol varchar(32);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'tool_call_logs'::regclass
      AND conname = 'tool_call_logs_destructive_event_type_check'
  ) THEN
    ALTER TABLE tool_call_logs
      ADD CONSTRAINT tool_call_logs_destructive_event_type_check
      CHECK (
        event_type IS NULL
        OR event_type IN (
          'tool_destructive_intent',
          'tool_attempt_blocked',
          'tool_execution_risk'
        )
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'tool_call_logs'::regclass
      AND conname = 'tool_call_logs_destructive_operation_tuple_check'
  ) THEN
    ALTER TABLE tool_call_logs
      ADD CONSTRAINT tool_call_logs_destructive_operation_tuple_check
      CHECK (
        (operation_id IS NULL AND event_type IS NULL)
        OR (
          operation_id IS NOT NULL
          AND btrim(operation_id) <> ''
          AND event_type IS NOT NULL
        )
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'tool_call_logs'::regclass
      AND conname = 'tool_call_logs_destructive_action_check'
  ) THEN
    ALTER TABLE tool_call_logs
      ADD CONSTRAINT tool_call_logs_destructive_action_check
      CHECK (
        (mode_default_action IS NULL OR mode_default_action IN ('record', 'alert_allow', 'confirm', 'block'))
        AND (custom_action IS NULL OR custom_action IN ('record', 'alert_allow', 'confirm', 'block'))
        AND (final_action IS NULL OR final_action IN ('record', 'alert_allow', 'confirm', 'block'))
      ) NOT VALID;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'tool_call_logs'::regclass
      AND conname = 'tool_call_logs_destructive_notification_status_check'
  ) THEN
    ALTER TABLE tool_call_logs
      ADD CONSTRAINT tool_call_logs_destructive_notification_status_check
      CHECK (
        notification_status IS NULL
        OR notification_status IN ('pending', 'sent', 'failed', 'dead', 'skipped')
      ) NOT VALID;
  END IF;
END
$$;

DO $$
DECLARE
  invalid_index record;
BEGIN
  FOR invalid_index IN
    SELECT n.nspname, index_rel.relname
    FROM pg_index i
    JOIN pg_class index_rel ON index_rel.oid = i.indexrelid
    JOIN pg_class table_rel ON table_rel.oid = i.indrelid
    JOIN pg_namespace n ON n.oid = table_rel.relnamespace
    WHERE table_rel.oid = 'tool_call_logs'::regclass
      AND index_rel.relnamespace = table_rel.relnamespace
      AND index_rel.relname IN ('uq_tool_call_logs_destructive_operation_event', 'uq_tool_call_logs_destructive_public_event')
      AND NOT i.indisvalid
  LOOP
    EXECUTE format('DROP INDEX %I.%I', invalid_index.nspname, invalid_index.relname);
  END LOOP;
END
$$;

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS
  uq_tool_call_logs_destructive_operation_event
  ON tool_call_logs (tenant_id, operation_id, event_type)
  WHERE operation_id IS NOT NULL
    AND pg_catalog.btrim(operation_id::text) OPERATOR(pg_catalog.<>) ''::text;

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS
  uq_tool_call_logs_destructive_public_event
  ON tool_call_logs (tenant_id, public_event_id)
  WHERE public_event_id IS NOT NULL
    AND pg_catalog.btrim(public_event_id::text) OPERATOR(pg_catalog.<>) ''::text;

DO $$
DECLARE
  index_oid oid;
  relation_kind "char";
  index_table oid;
  index_unique boolean;
  index_predicate text;
  normalized_predicate text;
  index_valid boolean;
  index_ready boolean;
  index_live boolean;
  key_count integer;
  attribute_count integer;
  first_key text;
  second_key text;
  third_key text;
  non_catalog_function_count integer;
  non_catalog_operator_count integer;
BEGIN
  SELECT c.oid, c.relkind
    INTO index_oid, relation_kind
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = current_schema()
    AND c.relname = 'uq_tool_call_logs_destructive_operation_event';

  IF index_oid IS NULL THEN
    RAISE EXCEPTION 'incompatible definition for index uq_tool_call_logs_destructive_operation_event: relation is missing';
  ELSIF relation_kind NOT IN ('i', 'I') THEN
    RAISE EXCEPTION 'incompatible definition for index uq_tool_call_logs_destructive_operation_event: relation is not an index';
  ELSE
    SELECT i.indrelid,
           i.indisunique,
           pg_get_expr(i.indpred, i.indrelid),
           i.indnkeyatts,
           i.indnatts,
           pg_get_indexdef(i.indexrelid, 1, true),
           pg_get_indexdef(i.indexrelid, 2, true),
           pg_get_indexdef(i.indexrelid, 3, true),
           i.indisvalid,
           i.indisready,
           i.indislive
      INTO index_table,
           index_unique,
           index_predicate,
           key_count,
           attribute_count,
           first_key,
           second_key,
           third_key,
           index_valid,
           index_ready,
           index_live
    FROM pg_index i
    WHERE i.indexrelid = index_oid;

    SELECT count(*)
      INTO non_catalog_function_count
    FROM pg_depend d
    JOIN pg_proc p
      ON d.refclassid = 'pg_proc'::regclass
     AND p.oid = d.refobjid
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE d.classid = 'pg_class'::regclass
      AND d.objid = index_oid
      AND n.nspname <> 'pg_catalog';
    normalized_predicate := lower(index_predicate);

    SELECT count(*)
      INTO non_catalog_operator_count
    FROM pg_depend d
    JOIN pg_operator o
      ON d.refclassid = 'pg_operator'::regclass
     AND o.oid = d.refobjid
    JOIN pg_namespace n ON n.oid = o.oprnamespace
    WHERE d.classid = 'pg_class'::regclass
      AND d.objid = index_oid
      AND n.nspname <> 'pg_catalog';

    normalized_predicate := regexp_replace(
      normalized_predicate,
      '::(text|character varying)',
      '',
      'g'
    );
    normalized_predicate := regexp_replace(
      normalized_predicate,
      '[[:space:]()]',
      '',
      'g'
    );

    IF index_table IS DISTINCT FROM 'tool_call_logs'::regclass
       OR index_unique IS DISTINCT FROM true
       OR index_valid IS DISTINCT FROM true
       OR index_ready IS DISTINCT FROM true
       OR index_live IS DISTINCT FROM true
       OR key_count IS DISTINCT FROM 3
       OR attribute_count IS DISTINCT FROM 3
       OR lower(btrim(first_key)) IS DISTINCT FROM 'tenant_id'
       OR lower(btrim(second_key)) IS DISTINCT FROM 'operation_id'
       OR lower(btrim(third_key)) IS DISTINCT FROM 'event_type'
       OR non_catalog_function_count IS DISTINCT FROM 0
       OR non_catalog_operator_count IS DISTINCT FROM 0
       OR normalized_predicate IS DISTINCT FROM
          'operation_idisnotnullandbtrimoperation_id<>''''' THEN
      RAISE EXCEPTION 'incompatible definition for index uq_tool_call_logs_destructive_operation_event: %',
        pg_get_indexdef(index_oid);
    END IF;
  END IF;
END
$$;

DO $$
DECLARE
  index_oid oid;
  relation_kind "char";
  index_table oid;
  index_unique boolean;
  index_valid boolean;
  index_ready boolean;
  index_live boolean;
  key_count integer;
  attribute_count integer;
  first_key text;
  second_key text;
  normalized_predicate text;
  non_catalog_function_count integer;
  non_catalog_operator_count integer;
BEGIN
  SELECT c.oid, c.relkind, i.indrelid, i.indisunique, i.indisvalid,
         i.indisready, i.indislive, i.indnkeyatts, i.indnatts,
         pg_get_indexdef(c.oid, 1, true), pg_get_indexdef(c.oid, 2, true),
         pg_get_expr(i.indpred, i.indrelid)
    INTO index_oid, relation_kind, index_table, index_unique, index_valid,
         index_ready, index_live, key_count, attribute_count, first_key,
         second_key, normalized_predicate
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  LEFT JOIN pg_index i ON i.indexrelid = c.oid
  WHERE n.nspname = current_schema()
    AND c.relname = 'uq_tool_call_logs_destructive_public_event';

  SELECT count(*) INTO non_catalog_function_count
  FROM pg_depend d
  JOIN pg_proc p ON d.refclassid = 'pg_proc'::regclass AND p.oid = d.refobjid
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE d.classid = 'pg_class'::regclass AND d.objid = index_oid
    AND n.nspname <> 'pg_catalog';

  SELECT count(*) INTO non_catalog_operator_count
  FROM pg_depend d
  JOIN pg_operator o ON d.refclassid = 'pg_operator'::regclass AND o.oid = d.refobjid
  JOIN pg_namespace n ON n.oid = o.oprnamespace
  WHERE d.classid = 'pg_class'::regclass AND d.objid = index_oid
    AND n.nspname <> 'pg_catalog';

  normalized_predicate := lower(normalized_predicate);
  normalized_predicate := regexp_replace(normalized_predicate,
    '::(text|character varying)', '', 'g');
  normalized_predicate := regexp_replace(normalized_predicate,
    '[[:space:]()]', '', 'g');

  IF index_oid IS NULL
     OR relation_kind NOT IN ('i', 'I')
     OR index_table IS DISTINCT FROM 'tool_call_logs'::regclass
     OR index_unique IS DISTINCT FROM true
     OR index_valid IS DISTINCT FROM true
     OR index_ready IS DISTINCT FROM true
     OR index_live IS DISTINCT FROM true
     OR key_count IS DISTINCT FROM 2
     OR attribute_count IS DISTINCT FROM 2
     OR lower(btrim(first_key)) IS DISTINCT FROM 'tenant_id'
     OR lower(btrim(second_key)) IS DISTINCT FROM 'public_event_id'
     OR non_catalog_function_count IS DISTINCT FROM 0
     OR non_catalog_operator_count IS DISTINCT FROM 0
     OR normalized_predicate IS DISTINCT FROM
        'public_event_idisnotnullandbtrimpublic_event_id<>''''' THEN
    RAISE EXCEPTION 'incompatible definition for index uq_tool_call_logs_destructive_public_event: %',
      coalesce(pg_get_indexdef(index_oid), '<missing>');
  END IF;
END
$$;

COMMENT ON TABLE agent_destructive_policies IS
  'Tenant-isolated destructive-operation policies; legacy audit-only is initialization-only';
COMMENT ON COLUMN tool_call_logs.operation_id IS
  'Stable identifier shared by intent, blocked, and execution-risk events';
COMMENT ON COLUMN tool_call_logs.event_type IS
  'Destructive-operation lifecycle event; NULL means unknown legacy evidence';
COMMENT ON COLUMN tool_call_logs.execution_forwarded IS
  'Whether the gateway forwarded the operation; NULL means unknown legacy evidence';
