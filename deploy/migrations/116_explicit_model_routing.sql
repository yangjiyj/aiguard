-- v3 policies are explicit per-model provider routes. Existing v1/v2 rows are
-- intentionally left unchanged; invalid pre-existing v3 rows fail safely.
-- These non-concurrent indexes run under the transactional migration runner;
-- apply this migration during a maintenance window on large installations.
DO $$
DECLARE
  index_oid oid;
  relation_kind "char";
  index_table oid;
  index_unique boolean;
  index_predicate text;
  index_valid boolean;
  index_ready boolean;
  index_live boolean;
  key_count integer;
  attribute_count integer;
  first_key text;
  second_key text;
BEGIN
  SELECT c.oid, c.relkind
    INTO index_oid, relation_kind
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = current_schema()
    AND c.relname = 'uq_providers_tenant_provider';

  IF index_oid IS NULL THEN
    CREATE UNIQUE INDEX uq_providers_tenant_provider
      ON providers (tenant_id, id);
  ELSIF relation_kind NOT IN ('i', 'I') THEN
    RAISE EXCEPTION 'incompatible definition for index uq_providers_tenant_provider: relation is not an index';
  ELSE
    SELECT i.indrelid,
           i.indisunique,
           pg_get_expr(i.indpred, i.indrelid),
           i.indnkeyatts,
           i.indnatts,
           pg_get_indexdef(i.indexrelid, 1, true),
           pg_get_indexdef(i.indexrelid, 2, true),
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
           index_valid,
           index_ready,
           index_live
    FROM pg_index i
    WHERE i.indexrelid = index_oid;

    IF index_table IS DISTINCT FROM 'providers'::regclass
       OR index_unique IS DISTINCT FROM true
       OR index_valid IS DISTINCT FROM true
       OR index_ready IS DISTINCT FROM true
       OR index_live IS DISTINCT FROM true
       OR key_count IS DISTINCT FROM 2
       OR attribute_count IS DISTINCT FROM 2
       OR lower(btrim(first_key)) IS DISTINCT FROM 'tenant_id'
       OR lower(btrim(second_key)) IS DISTINCT FROM 'id'
       OR index_predicate IS NOT NULL THEN
      RAISE EXCEPTION 'incompatible definition for index uq_providers_tenant_provider: %',
        pg_get_indexdef(index_oid);
    END IF;
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS model_route_baselines (
  tenant_id varchar(64) NOT NULL REFERENCES tenants(id),
  model_name varchar(255) NOT NULL,
  provider_id varchar(64) NOT NULL,
  captured_from varchar(32) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, model_name),
  CONSTRAINT fk_model_route_baseline_provider
    FOREIGN KEY (tenant_id, provider_id)
    REFERENCES providers(tenant_id, id)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_routing_v3_explicit_model'
      AND conrelid = 'routing_policies'::regclass
  ) THEN
    ALTER TABLE routing_policies
      ADD CONSTRAINT chk_routing_v3_explicit_model
      CHECK (
        schema_version <> 3
        OR (
          scope_type = 'model'
          AND scope_ref IS NOT NULL
          AND btrim(scope_ref) <> ''
          AND layer = 'provider'
        )
      );
  END IF;
END
$$;

DO $$
DECLARE
  index_oid oid;
  relation_kind "char";
  index_table oid;
  index_unique boolean;
  index_predicate text;
  index_valid boolean;
  index_ready boolean;
  index_live boolean;
  normalized_predicate text;
  predicate_remainder text;
  key_count integer;
  attribute_count integer;
  first_key text;
  second_key text;
BEGIN
  SELECT c.oid, c.relkind
    INTO index_oid, relation_kind
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = current_schema()
    AND c.relname = 'uq_routing_v3_model';

  IF index_oid IS NULL THEN
    CREATE UNIQUE INDEX uq_routing_v3_model
      ON routing_policies (tenant_id, scope_ref)
      WHERE schema_version = 3 AND scope_type = 'model' AND layer = 'provider';
  ELSIF relation_kind NOT IN ('i', 'I') THEN
    RAISE EXCEPTION 'incompatible definition for index uq_routing_v3_model: relation is not an index';
  ELSE
    SELECT i.indrelid,
           i.indisunique,
           pg_get_expr(i.indpred, i.indrelid),
           i.indnkeyatts,
           i.indnatts,
           pg_get_indexdef(i.indexrelid, 1, true),
           pg_get_indexdef(i.indexrelid, 2, true),
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
           index_valid,
           index_ready,
           index_live
    FROM pg_index i
    WHERE i.indexrelid = index_oid;

    normalized_predicate := lower(index_predicate);
    normalized_predicate := regexp_replace(
      normalized_predicate,
      '::(text|smallint|integer|character varying)',
      '',
      'g'
    );
    normalized_predicate := regexp_replace(normalized_predicate, '[[:space:]()]', '', 'g');
    predicate_remainder := replace(normalized_predicate, 'schema_version=3', '');
    predicate_remainder := replace(predicate_remainder, 'scope_type=''model''', '');
    predicate_remainder := replace(predicate_remainder, 'layer=''provider''', '');
    predicate_remainder := replace(predicate_remainder, 'and', '');

    IF index_table IS DISTINCT FROM 'routing_policies'::regclass
       OR index_unique IS DISTINCT FROM true
       OR index_valid IS DISTINCT FROM true
       OR index_ready IS DISTINCT FROM true
       OR index_live IS DISTINCT FROM true
       OR key_count IS DISTINCT FROM 2
       OR attribute_count IS DISTINCT FROM 2
       OR lower(btrim(first_key)) IS DISTINCT FROM 'tenant_id'
       OR lower(btrim(second_key)) IS DISTINCT FROM 'scope_ref'
       OR index_predicate IS NULL
       OR position('schema_version=3' IN normalized_predicate) = 0
       OR position('scope_type=''model''' IN normalized_predicate) = 0
       OR position('layer=''provider''' IN normalized_predicate) = 0
       OR (length(normalized_predicate) - length(replace(normalized_predicate, 'and', ''))) / 3 <> 2
       OR predicate_remainder <> '' THEN
      RAISE EXCEPTION 'incompatible definition for index uq_routing_v3_model: %',
        pg_get_indexdef(index_oid);
    END IF;
  END IF;
END
$$;
