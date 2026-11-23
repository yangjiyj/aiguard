BEGIN;

-- T07/T08: server-side approval basis catalog for model destinations.
--
-- aiprobe declares approval_status/approval_basis/approval_rule_id per
-- destination (contracts/model-destination-approval.v1.schema.json), but the
-- control plane previously had no catalog of its own and could not recheck
-- the client's claim. This table is that catalog: tenant-scoped destination
-- entries an admin approves, matched by exact host or by an exact base_url
-- prefix. It applies identically to official and self-hosted relay
-- endpoints — classification never grants or denies approval by itself.
--
-- rule_id follows the same pattern the probe contract enforces on
-- approval_rule_id (^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$) so a server-issued rule
-- id and a client-declared rule id are always comparable byte for byte.
CREATE TABLE IF NOT EXISTS agent_destination_approval_rules (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    rule_id text NOT NULL
        CHECK (rule_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    match_type text NOT NULL CHECK (match_type IN ('host', 'base_url_prefix')),
    match_value text NOT NULL CHECK (length(btrim(match_value)) BETWEEN 1 AND 512),
    category text NOT NULL CHECK (category IN ('official', 'relay')),
    enabled boolean NOT NULL DEFAULT true,
    description text NOT NULL DEFAULT '',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    disabled_by text NOT NULL DEFAULT '',
    UNIQUE (tenant_id, rule_id),
    -- Enables the composite FK below (tenant_id, server_matched_rule_row_id)
    -- from agent_destination_approval_observations: id alone is already
    -- globally unique via the primary key, so (tenant_id, id) is trivially
    -- unique too — this only gives Postgres a named unique constraint on
    -- that pair to reference.
    UNIQUE (tenant_id, id)
);

-- One tenant cannot have two enabled rules for the identical match. A
-- disabled rule's match value can be reused by a fresh enabled rule, so the
-- uniqueness only applies while enabled=true (a partial unique index).
CREATE UNIQUE INDEX IF NOT EXISTS ux_agent_destination_approval_rules_enabled_match
    ON agent_destination_approval_rules (tenant_id, match_type, match_value)
    WHERE enabled;

CREATE INDEX IF NOT EXISTS idx_agent_destination_approval_rules_tenant
    ON agent_destination_approval_rules (tenant_id, enabled, updated_at DESC);

-- T07: per-destination server verification outcome for every probe report
-- accepted. The client's declared approval_status/approval_basis/
-- approval_rule_id are stored verbatim as client_claimed_*, and the server's
-- own recheck against agent_destination_approval_rules is stored separately
-- as server_verified_*. A forged or disabled rule_id, or one that simply does
-- not match this tenant's catalog, must never be promoted to server_verified
-- approved — that is the whole point of keeping the two columns apart.
CREATE TABLE IF NOT EXISTS agent_destination_approval_observations (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    endpoint_id text NOT NULL,
    report_id text NOT NULL,
    asset_source_id text NOT NULL,
    -- -1 is a reserved sentinel for the asset's singular Evidence.Endpoint
    -- (which has no natural array index); Evidence.Destinations[] entries use
    -- their real index (>=0), so the two families can never collide under
    -- the UNIQUE(tenant_id,report_id,asset_source_id,destination_index) key
    -- below.
    destination_index integer NOT NULL CHECK (destination_index >= -1),
    origin text NOT NULL,
    classification text NOT NULL,
    client_claimed_status text NOT NULL DEFAULT '',
    client_claimed_basis text NOT NULL DEFAULT '',
    client_claimed_rule_id text NOT NULL DEFAULT '',
    server_verified_status text NOT NULL
        CHECK (server_verified_status IN ('approved', 'not_listed', 'unreviewed', 'invalid_claim')),
    server_verified_rule_id text NOT NULL DEFAULT '',
    server_matched_rule_row_id text,
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, report_id, asset_source_id, destination_index),
    FOREIGN KEY (tenant_id, server_matched_rule_row_id)
        REFERENCES agent_destination_approval_rules (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_agent_destination_approval_observations_tenant_endpoint
    ON agent_destination_approval_observations (tenant_id, endpoint_id, received_at DESC);

COMMIT;
