-- 810: anchor request content logs to the original chat message array index.
BEGIN;

ALTER TABLE content_logs
    ADD COLUMN IF NOT EXISTS message_index INTEGER;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'content_logs_message_index_nonnegative_check'
          AND conrelid = to_regclass('public.content_logs')
    ) THEN
        ALTER TABLE content_logs
            ADD CONSTRAINT content_logs_message_index_nonnegative_check
            CHECK (message_index IS NULL OR message_index >= 0);
    END IF;
END $$;

COMMIT;
