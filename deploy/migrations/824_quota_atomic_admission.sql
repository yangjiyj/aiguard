BEGIN;

ALTER TABLE quota_policies
    ADD COLUMN IF NOT EXISTS tpm_limit BIGINT,
    ADD COLUMN IF NOT EXISTS tpm_blocked BOOLEAN NOT NULL DEFAULT FALSE;

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'quota_policies_tpm_limit_nonnegative_check'
          AND conrelid = 'quota_policies'::regclass
    ) THEN
        ALTER TABLE quota_policies
            ADD CONSTRAINT quota_policies_tpm_limit_nonnegative_check
            CHECK (tpm_limit IS NULL OR tpm_limit >= 0) NOT VALID;
    END IF;
END
$migration$;

ALTER TABLE quota_policies
    VALIDATE CONSTRAINT quota_policies_tpm_limit_nonnegative_check;

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'quota_policies_tpm_block_exclusive_check'
          AND conrelid = 'quota_policies'::regclass
    ) THEN
        ALTER TABLE quota_policies
            ADD CONSTRAINT quota_policies_tpm_block_exclusive_check
            CHECK (NOT tpm_blocked OR tpm_limit IS NULL) NOT VALID;
    END IF;
END
$migration$;

ALTER TABLE quota_policies
    VALIDATE CONSTRAINT quota_policies_tpm_block_exclusive_check;

COMMENT ON COLUMN quota_policies.tpm_limit IS
    '每分钟 Token 上限；NULL=未设置/继承，0=显式不限，正数=限额';
COMMENT ON COLUMN quota_policies.tpm_blocked IS
    '显式禁止 Token 请求；与 tpm_limit 分离以保持历史 0=不限语义';

COMMIT;
