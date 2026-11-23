BEGIN;

-- Native T02 observations remain separate from legacy events.v1.
-- Endpoint identity is authenticated transport provenance, not payload identity.
CREATE TABLE agent_native_events (
    sequence_id bigserial PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    endpoint_id text NOT NULL,
    event_id uuid NOT NULL,
    source_id char(64) NOT NULL,
    schema_version text NOT NULL CHECK (schema_version = '1.0'),
    producer jsonb NOT NULL CHECK (jsonb_typeof(producer) = 'object'),
    event_type text NOT NULL,
    source_occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    payload_hash char(64) NOT NULL,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    UNIQUE (tenant_id, endpoint_id, event_id),
    UNIQUE (tenant_id, endpoint_id, event_id, source_id)
);
CREATE INDEX idx_agent_native_events_timeline
    ON agent_native_events (tenant_id, sequence_id DESC);
CREATE INDEX idx_agent_native_events_source
    ON agent_native_events (tenant_id, source_id, sequence_id DESC);
CREATE INDEX idx_agent_native_events_endpoint
    ON agent_native_events (tenant_id, endpoint_id, sequence_id DESC);

CREATE TABLE agent_native_event_refs (
    tenant_id varchar(64) NOT NULL,
    endpoint_id text NOT NULL,
    event_id uuid NOT NULL,
    source_id char(64) NOT NULL,
    role text NOT NULL,
    ref_hash char(64) NOT NULL,
    native_ref jsonb NOT NULL CHECK (jsonb_typeof(native_ref) = 'object'),
    PRIMARY KEY (tenant_id, endpoint_id, event_id, role),
    FOREIGN KEY (tenant_id, endpoint_id, event_id, source_id)
        REFERENCES agent_native_events (tenant_id, endpoint_id, event_id, source_id)
        ON DELETE CASCADE
);
CREATE INDEX idx_agent_native_event_refs_lookup
    ON agent_native_event_refs (tenant_id, source_id, ref_hash, event_id);

-- There is deliberately no FK to mutable endpoint inventory: audit evidence
-- remains attributable after an endpoint registration is removed.
COMMENT ON TABLE agent_native_events IS
    'Append-only via application API; source times and native claims are untrusted. Sequence order is presentation order, not causal or commit order.';
COMMIT;
