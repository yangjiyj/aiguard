-- Repair only the legacy near-all-audit profile found by the full policy
-- evaluation. Customer-customized rule sets are intentionally left untouched.
BEGIN;

CREATE TEMP TABLE migration_848_legacy_rule_sets ON COMMIT DROP AS
SELECT r.rule_set_id
FROM rules r
WHERE r.policy_code LIKE 'builtin.%'
GROUP BY r.rule_set_id
HAVING COUNT(*) >= 230
   AND COUNT(*) FILTER (WHERE r.action = 'mask') = 0
   AND COUNT(*) FILTER (WHERE r.action = 'block') <= 1
   AND COUNT(*) FILTER (WHERE r.action NOT IN ('audit','mask','block')) = 0;

UPDATE rules r
SET action = 'mask'
FROM migration_848_legacy_rule_sets legacy
WHERE r.rule_set_id = legacy.rule_set_id
  AND r.policy_code = ANY(ARRAY[
    'builtin.data_leak.e5821efde7585cbb',
    'builtin.data_leak.ee20059e4c9fbf2f',
    'builtin.data_leak.2348426d637af519',
    'builtin.data_leak.63ae19f7cd1834bf',
    'builtin.data_leak.9a6811b786b7618f',
    'builtin.data_leak.86c5bbeff12d7c44',
    'builtin.data_leak.e18afae0f9594164',
    'builtin.data_leak.a3048f2177b99395',
    'builtin.data_leak.d85734a727cce7b8',
    'builtin.data_leak.aa6a72765f3d1d2b',
    'builtin.data_leak.3512cd70e182c979',
    'builtin.data_leak.cd7cd3f962c8a7c1',
    'builtin.data_leak.65f151cdf48b5404',
    'builtin.data_leak.85d7d239c670bab5',
    'builtin.data_leak.1a873ce1a4f5e91e',
    'builtin.data_leak.7399a414eb30dbb9'
  ]::text[]);

UPDATE rules r
SET action = 'block',
    description = '检测代码中的硬编码凭据示例，阻断请求'
FROM migration_848_legacy_rule_sets legacy
WHERE r.rule_set_id = legacy.rule_set_id
  AND r.policy_code = 'builtin.code_security.9640acf0d1083905';

COMMIT;
