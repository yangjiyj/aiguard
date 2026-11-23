BEGIN;

ALTER TABLE content_audit_exceptions
    ADD COLUMN IF NOT EXISTS include_children BOOLEAN NOT NULL DEFAULT FALSE;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_content_audit_exception_scope_v1'
          AND conrelid = 'content_audit_exceptions'::regclass
    ) THEN
        ALTER TABLE content_audit_exceptions
            ADD CONSTRAINT chk_content_audit_exception_scope_v1
            CHECK (
                scope_type IN (
                    'tenant',
                    'project',
                    'user',
                    'rule',
                    'key_v1',
                    'actor_department_v1'
                )
                AND (
                    scope_type NOT IN (
                        'project',
                        'user',
                        'key_v1',
                        'actor_department_v1'
                    )
                    OR btrim(scope_ref) <> ''
                )
                AND (
                    scope_type <> 'rule'
                    OR rule_id IS NOT NULL
                    OR NULLIF(btrim(rule_ref), '') IS NOT NULL
                )
                AND (
                    include_children = FALSE
                    OR scope_type = 'actor_department_v1'
                )
            ) NOT VALID;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_content_audit_exceptions_scope_ref
    ON content_audit_exceptions(tenant_id, scope_type, scope_ref)
    WHERE enabled = TRUE;

COMMENT ON COLUMN content_audit_exceptions.include_children IS
    '仅 actor_department_v1 可用；false=直属部门精确匹配，true=含子部门';

COMMIT;
