BEGIN;

-- 训练语料扫描任务（规格第 5.4 节）。全部为新表，不改动业务表。
-- 原始语料、报告、脱敏副本存放在控制面留存卷（retentionstore 本地后端），这里只存元数据和存储 key。
-- 原始语料按上传分片各存一个对象（source_keys），upload_hash_state 是逐片累计的 SHA-256 中间状态，
-- 开始扫描时用 upload_sha256 与声明的 sha256 比对，不必重读整份文件。
CREATE TABLE IF NOT EXISTS corpus_scan_jobs (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    created_by         TEXT NOT NULL,
    file_name          TEXT NOT NULL,
    format             TEXT NOT NULL CHECK (format IN ('jsonl','csv','txt','docx','pdf','xlsx')),
    size_bytes         BIGINT NOT NULL CHECK (size_bytes > 0),
    sha256             TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('uploading','queued','running','succeeded','failed','canceled','interrupted')),
    error_code         TEXT NOT NULL DEFAULT '',
    cancel_requested   BOOLEAN NOT NULL DEFAULT FALSE,
    owner_token        TEXT NOT NULL DEFAULT '',
    lease_until        TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
    uploaded_bytes     BIGINT NOT NULL DEFAULT 0,
    next_chunk         INTEGER NOT NULL DEFAULT 0,
    processed_bytes    BIGINT NOT NULL DEFAULT 0,
    total_records      BIGINT NOT NULL DEFAULT 0,
    scanned_records    BIGINT NOT NULL DEFAULT 0,
    hit_records        BIGINT NOT NULL DEFAULT 0,
    unscanned_records  BIGINT NOT NULL DEFAULT 0,
    incomplete_records BIGINT NOT NULL DEFAULT 0,
    stats_json         JSONB NOT NULL DEFAULT '{}'::JSONB,
    samples_json       JSONB NOT NULL DEFAULT '[]'::JSONB,
    unscanned_json     JSONB NOT NULL DEFAULT '[]'::JSONB,
    notes_json         JSONB NOT NULL DEFAULT '[]'::JSONB,
    source_keys        JSONB NOT NULL DEFAULT '[]'::JSONB,
    upload_hash_state  BYTEA,
    upload_sha256      TEXT NOT NULL DEFAULT '',
    report_key         TEXT NOT NULL DEFAULT '',
    masked_key         TEXT NOT NULL DEFAULT '',
    masked_format      TEXT NOT NULL DEFAULT '',
    rule_pack_version  TEXT NOT NULL DEFAULT '',
    expires_at         TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at         TIMESTAMPTZ,
    completed_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_corpus_scan_jobs_tenant_created ON corpus_scan_jobs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_corpus_scan_jobs_expires ON corpus_scan_jobs (expires_at);
-- 全局同时只跑 1 个任务：运行中的任务最多一条（所有租户共用引擎线程池）；其余任务在 queued 里排队。
CREATE UNIQUE INDEX IF NOT EXISTS idx_corpus_scan_jobs_single_active ON corpus_scan_jobs ((TRUE)) WHERE status = 'running';

COMMIT;
