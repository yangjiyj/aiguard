-- W9 9.3：控制台 CAS / 企业微信登录的账号绑定。
--
-- CAS 与企业微信没有 OIDC 那样的 iss+sub，主体分别是 CAS 服务前缀下的 user、
-- 企业（corpid）内的 userid。它们以独立的 source_type 记在 user_identity_links，
-- 与 OIDC 绑定互不混用：
--   * cas   : issuer = CAS 服务前缀（如 https://cas.example.gov.cn/cas），external_subject = CAS user
--   * wecom : issuer = 'wecom:<corpid>'，external_subject = 企业微信 userid
-- 绑定只能由管理员显式建立，登录时不按手机号/邮箱/用户名自动匹配或建号。
BEGIN;

ALTER TABLE user_identity_links
  DROP CONSTRAINT IF EXISTS user_identity_links_source_type_check;

ALTER TABLE user_identity_links
  ADD CONSTRAINT user_identity_links_source_type_check
  CHECK (source_type IN ('local', 'oidc', 'ldap', 'ad', 'cas', 'wecom'));

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_user_identity_links_wecom_issuer'
  ) THEN
    ALTER TABLE user_identity_links
      ADD CONSTRAINT chk_user_identity_links_wecom_issuer
      CHECK (source_type <> 'wecom' OR issuer ~ '^wecom:[A-Za-z0-9]{6,64}$');
  END IF;
END
$$;

COMMIT;
