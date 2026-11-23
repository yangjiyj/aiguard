-- Correct the frozen built-in catalog entry without changing migration 125 or
-- claiming mask capability for a detector that only supports audit/block.
UPDATE rules
SET action = 'block',
    description = '检测代码中的硬编码凭据示例，阻断请求'
WHERE policy_code = 'builtin.code_security.9640acf0d1083905'
  AND (
    action = 'mask'
    OR description = '检测代码中的硬编码凭据示例，脱敏处理'
  );
