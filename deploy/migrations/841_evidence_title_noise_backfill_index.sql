-- +goose NO TRANSACTION
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_evidence_title_noise_backfill
    ON evidence_run_request_index (created_at, request_log_id)
    WHERE evidence_run_source IN (
        'responses_prompt_cache_key',
        'responses_prompt_cache_key_candidate'
    );
