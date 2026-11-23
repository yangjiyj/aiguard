BEGIN;

-- Migration 820 is already deployed. Keep its ledger checksum intact and replace
-- only its refresh function; existing triggers pick up this serialized version.
CREATE OR REPLACE FUNCTION jjdguard_refresh_request_customer_content_projection(
    p_tenant_id varchar,
    p_request_id varchar
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
AS $$
BEGIN
    -- Serialize sibling evidence writes before acquiring the snapshot used by
    -- the UPDATE below. One UPDATE alone can wait on the row and still evaluate
    -- its child-table EXISTS clauses against its pre-wait READ COMMITTED snapshot.
    -- NO KEY UPDATE remains compatible with the KEY SHARE locks taken by child
    -- foreign keys; FOR UPDATE here can deadlock two concurrent child inserts.
    PERFORM 1
    FROM request_logs rl
    WHERE rl.tenant_id = p_tenant_id
      AND rl.request_id = p_request_id
    FOR NO KEY UPDATE;

    UPDATE request_logs rl
    SET has_customer_content = (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND (
                      jjdguard_customer_content_text(acl.request_content_redacted)
                      OR jjdguard_customer_content_text(acl.response_content_redacted)
                      OR COALESCE(acl.file_metadata_json, '[]'::jsonb) <> '[]'::jsonb
                  )
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND EXISTS (
                    SELECT 1
                    FROM content_logs cl
                    WHERE cl.tenant_id = rl.tenant_id
                      AND cl.request_id = rl.id
                      AND cl.role IN ('user', 'assistant')
                      AND jjdguard_customer_content_text(cl.content)
                )
            )
        ),
        has_customer_request_body = (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND jjdguard_customer_content_text(acl.request_content_redacted)
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND EXISTS (
                    SELECT 1
                    FROM content_logs cl
                    WHERE cl.tenant_id = rl.tenant_id
                      AND cl.request_id = rl.id
                      AND cl.role = 'user'
                      AND jjdguard_customer_content_text(cl.content)
                )
            )
        ),
        has_customer_response_body = (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND jjdguard_customer_content_text(acl.response_content_redacted)
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND EXISTS (
                    SELECT 1
                    FROM content_logs cl
                    WHERE cl.tenant_id = rl.tenant_id
                      AND cl.request_id = rl.id
                      AND cl.role = 'assistant'
                      AND jjdguard_customer_content_text(cl.content)
                )
            )
        ),
        customer_content_rule_version = 1
    WHERE rl.tenant_id = p_tenant_id
      AND rl.request_id = p_request_id;
END;
$$;

-- Do not repair history in this synchronous migration. Migration 834 registers
-- a resumable, keyset-paginated background task. Existing triggers immediately
-- use this serialized function for new writes.

COMMIT;
