BEGIN;

DO $migration$
DECLARE
    daily_budget_micros_existed BOOLEAN;
    monthly_budget_micros_existed BOOLEAN;
    daily_token_canonical_existed BOOLEAN;
    monthly_token_canonical_existed BOOLEAN;
    rpm_canonical_existed BOOLEAN;
    concurrency_canonical_existed BOOLEAN;
BEGIN
    SELECT
        COUNT(*) FILTER (WHERE column_name = 'daily_budget_micros') > 0,
        COUNT(*) FILTER (WHERE column_name = 'monthly_budget_micros') > 0,
        COUNT(*) FILTER (WHERE column_name = 'daily_token_limit_canonical') > 0,
        COUNT(*) FILTER (WHERE column_name = 'monthly_token_limit_canonical') > 0,
        COUNT(*) FILTER (WHERE column_name = 'rpm_limit_canonical') > 0,
        COUNT(*) FILTER (WHERE column_name = 'concurrency_limit_canonical') > 0
    INTO
        daily_budget_micros_existed,
        monthly_budget_micros_existed,
        daily_token_canonical_existed,
        monthly_token_canonical_existed,
        rpm_canonical_existed,
        concurrency_canonical_existed
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'quota_policies';

    ALTER TABLE quota_policies
        ADD COLUMN IF NOT EXISTS daily_budget_micros BIGINT,
        ADD COLUMN IF NOT EXISTS monthly_budget_micros BIGINT,
        ADD COLUMN IF NOT EXISTS daily_budget_blocked BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS monthly_budget_blocked BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS daily_token_limit_canonical BIGINT,
        ADD COLUMN IF NOT EXISTS monthly_token_limit_canonical BIGINT,
        ADD COLUMN IF NOT EXISTS daily_token_blocked BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS monthly_token_blocked BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS rpm_limit_canonical INTEGER,
        ADD COLUMN IF NOT EXISTS rpm_blocked BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS concurrency_limit_canonical INTEGER,
        ADD COLUMN IF NOT EXISTS concurrency_blocked BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS quota_timezone VARCHAR(64) NOT NULL DEFAULT 'Asia/Shanghai';

    IF NOT daily_budget_micros_existed THEN
        IF EXISTS (
            SELECT 1
            FROM quota_policies
            WHERE NOT daily_budget_blocked
              AND CASE
                    WHEN daily_budget_limit::text = 'Infinity' THEN TRUE
                    WHEN daily_budget_limit::text IN ('NaN', '-Infinity') THEN FALSE
                    WHEN daily_budget_limit > 0
                    THEN ROUND(daily_budget_limit * 1000000) > 9007199254740991::numeric
                    ELSE FALSE
                  END
        ) THEN
            RAISE EXCEPTION
                'migration 827: daily_budget_limit contains a positive value above 9007199254740991 micros'
                USING ERRCODE = '22003';
        END IF;

        UPDATE quota_policies
        SET daily_budget_micros = CASE
                WHEN daily_budget_blocked THEN NULL
                WHEN daily_budget_limit IS NULL THEN NULL
                WHEN daily_budget_limit::text IN ('NaN', '-Infinity') THEN 0
                WHEN daily_budget_limit <= 0 THEN 0
                ELSE ROUND(daily_budget_limit * 1000000)::BIGINT
            END;
    END IF;

    IF NOT monthly_budget_micros_existed THEN
        IF EXISTS (
            SELECT 1
            FROM quota_policies
            WHERE NOT monthly_budget_blocked
              AND CASE
                    WHEN monthly_budget_limit::text = 'Infinity' THEN TRUE
                    WHEN monthly_budget_limit::text IN ('NaN', '-Infinity') THEN FALSE
                    WHEN monthly_budget_limit > 0
                    THEN ROUND(monthly_budget_limit * 1000000) > 9007199254740991::numeric
                    ELSE FALSE
                  END
        ) THEN
            RAISE EXCEPTION
                'migration 827: monthly_budget_limit contains a positive value above 9007199254740991 micros'
                USING ERRCODE = '22003';
        END IF;

        UPDATE quota_policies
        SET monthly_budget_micros = CASE
                WHEN monthly_budget_blocked THEN NULL
                WHEN monthly_budget_limit IS NULL THEN NULL
                WHEN monthly_budget_limit::text IN ('NaN', '-Infinity') THEN 0
                WHEN monthly_budget_limit <= 0 THEN 0
                ELSE ROUND(monthly_budget_limit * 1000000)::BIGINT
            END;
    END IF;

    IF NOT daily_token_canonical_existed THEN
        IF EXISTS (
            SELECT 1
            FROM quota_policies
            WHERE NOT daily_token_blocked
              AND daily_token_limit > 9007199254740991
        ) THEN
            RAISE EXCEPTION
                'migration 827: daily_token_limit contains a value above 9007199254740991'
                USING ERRCODE = '22003';
        END IF;

        UPDATE quota_policies
        SET daily_token_limit_canonical = CASE
                WHEN daily_token_blocked THEN NULL
                WHEN daily_token_limit IS NULL THEN NULL
                WHEN daily_token_limit <= 0 THEN 0
                ELSE daily_token_limit
            END;
    END IF;

    IF NOT monthly_token_canonical_existed THEN
        IF EXISTS (
            SELECT 1
            FROM quota_policies
            WHERE NOT monthly_token_blocked
              AND monthly_token_limit > 9007199254740991
        ) THEN
            RAISE EXCEPTION
                'migration 827: monthly_token_limit contains a value above 9007199254740991'
                USING ERRCODE = '22003';
        END IF;

        UPDATE quota_policies
        SET monthly_token_limit_canonical = CASE
                WHEN monthly_token_blocked THEN NULL
                WHEN monthly_token_limit IS NULL THEN NULL
                WHEN monthly_token_limit <= 0 THEN 0
                ELSE monthly_token_limit
            END;
    END IF;

    IF NOT rpm_canonical_existed THEN
        UPDATE quota_policies
        SET rpm_limit_canonical = CASE
                WHEN rpm_blocked THEN NULL
                WHEN rpm_limit IS NULL THEN NULL
                WHEN rpm_limit <= 0 THEN 0
                ELSE rpm_limit
            END;
    END IF;

    IF NOT concurrency_canonical_existed THEN
        UPDATE quota_policies
        SET concurrency_limit_canonical = CASE
                WHEN concurrency_blocked THEN NULL
                WHEN concurrency_limit IS NULL THEN NULL
                WHEN concurrency_limit <= 0 THEN 0
                ELSE concurrency_limit
            END;
    END IF;
END
$migration$;

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_quota_daily_budget_micros'
          AND conrelid = 'quota_policies'::regclass
    ) THEN
        ALTER TABLE quota_policies
            ADD CONSTRAINT chk_quota_daily_budget_micros
            CHECK (
                daily_budget_blocked IS NOT NULL
                AND (daily_budget_micros IS NULL OR daily_budget_micros BETWEEN 0 AND 9007199254740991)
                AND NOT (daily_budget_blocked AND daily_budget_micros IS NOT NULL)
            ) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_quota_monthly_budget_micros'
          AND conrelid = 'quota_policies'::regclass
    ) THEN
        ALTER TABLE quota_policies
            ADD CONSTRAINT chk_quota_monthly_budget_micros
            CHECK (
                monthly_budget_blocked IS NOT NULL
                AND (monthly_budget_micros IS NULL OR monthly_budget_micros BETWEEN 0 AND 9007199254740991)
                AND NOT (monthly_budget_blocked AND monthly_budget_micros IS NOT NULL)
            ) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_quota_daily_token_canonical'
          AND conrelid = 'quota_policies'::regclass
    ) THEN
        ALTER TABLE quota_policies
            ADD CONSTRAINT chk_quota_daily_token_canonical
            CHECK (
                daily_token_blocked IS NOT NULL
                AND (daily_token_limit_canonical IS NULL OR daily_token_limit_canonical BETWEEN 0 AND 9007199254740991)
                AND NOT (daily_token_blocked AND daily_token_limit_canonical IS NOT NULL)
            ) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_quota_monthly_token_canonical'
          AND conrelid = 'quota_policies'::regclass
    ) THEN
        ALTER TABLE quota_policies
            ADD CONSTRAINT chk_quota_monthly_token_canonical
            CHECK (
                monthly_token_blocked IS NOT NULL
                AND (monthly_token_limit_canonical IS NULL OR monthly_token_limit_canonical BETWEEN 0 AND 9007199254740991)
                AND NOT (monthly_token_blocked AND monthly_token_limit_canonical IS NOT NULL)
            ) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_quota_rpm_canonical'
          AND conrelid = 'quota_policies'::regclass
    ) THEN
        ALTER TABLE quota_policies
            ADD CONSTRAINT chk_quota_rpm_canonical
            CHECK (
                rpm_blocked IS NOT NULL
                AND (rpm_limit_canonical IS NULL OR rpm_limit_canonical >= 0)
                AND NOT (rpm_blocked AND rpm_limit_canonical IS NOT NULL)
            ) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_quota_concurrency_canonical'
          AND conrelid = 'quota_policies'::regclass
    ) THEN
        ALTER TABLE quota_policies
            ADD CONSTRAINT chk_quota_concurrency_canonical
            CHECK (
                concurrency_blocked IS NOT NULL
                AND (concurrency_limit_canonical IS NULL OR concurrency_limit_canonical >= 0)
                AND NOT (concurrency_blocked AND concurrency_limit_canonical IS NOT NULL)
            ) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_quota_timezone_nonempty'
          AND conrelid = 'quota_policies'::regclass
    ) THEN
        ALTER TABLE quota_policies
            ADD CONSTRAINT chk_quota_timezone_nonempty
            CHECK (quota_timezone IS NOT NULL AND BTRIM(quota_timezone) <> '') NOT VALID;
    END IF;
END
$migration$;

ALTER TABLE quota_policies VALIDATE CONSTRAINT chk_quota_daily_budget_micros;
ALTER TABLE quota_policies VALIDATE CONSTRAINT chk_quota_monthly_budget_micros;
ALTER TABLE quota_policies VALIDATE CONSTRAINT chk_quota_daily_token_canonical;
ALTER TABLE quota_policies VALIDATE CONSTRAINT chk_quota_monthly_token_canonical;
ALTER TABLE quota_policies VALIDATE CONSTRAINT chk_quota_rpm_canonical;
ALTER TABLE quota_policies VALIDATE CONSTRAINT chk_quota_concurrency_canonical;
ALTER TABLE quota_policies VALIDATE CONSTRAINT chk_quota_timezone_nonempty;

COMMENT ON COLUMN quota_policies.daily_budget_micros IS
    '每日客户应扣 billable_amount，整数微元；NULL=未设置/继承，0=本级不限，正数=上限';
COMMENT ON COLUMN quota_policies.monthly_budget_micros IS
    '每月客户应扣 billable_amount，整数微元；NULL=未设置/继承，0=本级不限，正数=上限';
COMMENT ON COLUMN quota_policies.daily_budget_blocked IS
    '每日金额配额显式禁止；true 时 daily_budget_micros 必须为 NULL';
COMMENT ON COLUMN quota_policies.monthly_budget_blocked IS
    '每月金额配额显式禁止；true 时 monthly_budget_micros 必须为 NULL';
COMMENT ON COLUMN quota_policies.daily_budget_limit IS
    '兼容旧 CNY API 和运行时字段；canonical 配置见 daily_budget_micros/daily_budget_blocked';
COMMENT ON COLUMN quota_policies.monthly_budget_limit IS
    '兼容旧 CNY API 和运行时字段；canonical 配置见 monthly_budget_micros/monthly_budget_blocked';
COMMENT ON COLUMN quota_policies.daily_token_limit_canonical IS
    '每日 Token canonical 配额；NULL=未设置/继承，0=本级不限，正数=上限';
COMMENT ON COLUMN quota_policies.monthly_token_limit_canonical IS
    '每月 Token canonical 配额；NULL=未设置/继承，0=本级不限，正数=上限';
COMMENT ON COLUMN quota_policies.daily_token_blocked IS
    '每日 Token 配额显式禁止；true 时 daily_token_limit_canonical 必须为 NULL';
COMMENT ON COLUMN quota_policies.monthly_token_blocked IS
    '每月 Token 配额显式禁止；true 时 monthly_token_limit_canonical 必须为 NULL';
COMMENT ON COLUMN quota_policies.rpm_limit_canonical IS
    'RPM canonical 配额；NULL=未设置/继承，0=本级不限，正数=上限';
COMMENT ON COLUMN quota_policies.rpm_blocked IS
    'RPM 配额显式禁止；true 时 rpm_limit_canonical 必须为 NULL';
COMMENT ON COLUMN quota_policies.concurrency_limit_canonical IS
    '并发 canonical 配额；NULL=未设置/继承，0=本级不限，正数=上限';
COMMENT ON COLUMN quota_policies.concurrency_blocked IS
    '并发配额显式禁止；true 时 concurrency_limit_canonical 必须为 NULL';
COMMENT ON COLUMN quota_policies.quota_timezone IS
    '配额周期时区；旧数据和空输入兼容为 Asia/Shanghai';

COMMIT;
