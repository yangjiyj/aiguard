-- +goose Up
-- +goose StatementBegin
-- W7 7.5: reconciliation can only recover prompt/output totals from
-- request_logs, so a recovered charge whose price snapshot has a distinct
-- cache rate may be mis-billed. Operators confirm the true cache breakdown and
-- the difference is booked as a ledger refund/adjustment. This append-only
-- table records that an exception was handled so it leaves the queue.
CREATE TABLE IF NOT EXISTS billing_exception_resolutions (
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    request_id VARCHAR(128) NOT NULL,
    kind VARCHAR(48) NOT NULL,
    resolution VARCHAR(48) NOT NULL,
    delta_micros BIGINT NOT NULL DEFAULT 0,
    detail_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    actor_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT pk_billing_exception_resolutions PRIMARY KEY (tenant_id, request_id, kind),
    CONSTRAINT ck_billing_exception_resolution_kind CHECK (kind IN ('recovered_without_cache')),
    CONSTRAINT ck_billing_exception_resolution_value CHECK (resolution IN ('cache_true_up')),
    CONSTRAINT ck_billing_exception_resolution_detail CHECK (jsonb_typeof(detail_json) = 'object')
);

DROP TRIGGER IF EXISTS trg_billing_exception_resolutions_append_only ON billing_exception_resolutions;
CREATE TRIGGER trg_billing_exception_resolutions_append_only
    BEFORE UPDATE OR DELETE ON billing_exception_resolutions
    FOR EACH ROW EXECUTE FUNCTION reject_billing_audit_mutation();

COMMENT ON TABLE billing_exception_resolutions IS 'Append-only operator resolutions for billing exceptions (e.g. cache breakdown true-up)';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trg_billing_exception_resolutions_append_only ON billing_exception_resolutions;
DROP TABLE IF EXISTS billing_exception_resolutions;
-- +goose StatementEnd
