-- Keep database-generated tool-call evidence IDs aligned with the application.
-- This changes only the default expression; existing rows are not rewritten.
ALTER TABLE IF EXISTS tool_call_logs
    ALTER COLUMN id SET DEFAULT
        'tc_' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 24);
