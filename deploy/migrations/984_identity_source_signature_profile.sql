-- 984: 身份源「id_token 验签方式」与「首次登录不弹资料页」两个选项。
--
-- signature_mode：jwks（默认，按 IdP 公钥验签，行为与旧版本完全一致）/ none（不校验 id_token 签名，
--   仅当 token 由服务端经 HTTPS 直连 token 端点换取时可用，由应用层校验 https）。
-- skip_profile_review：首次登录不弹资料页，默认 false。
-- 两列均 NOT NULL 且带默认值：存量行自动取默认值，期望配置摘要对默认值保持不变，已发布身份源升级后不会漂移。
-- 回退：旧版本不读取这两列，保留列无害；确需删除见 +goose Down 与 rollback/984。
ALTER TABLE identity_sources
  ADD COLUMN IF NOT EXISTS signature_mode text NOT NULL DEFAULT 'jwks',
  ADD COLUMN IF NOT EXISTS skip_profile_review boolean NOT NULL DEFAULT false;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'identity_sources_signature_mode_check') THEN
    ALTER TABLE identity_sources
      ADD CONSTRAINT identity_sources_signature_mode_check CHECK (signature_mode IN ('jwks', 'none'));
  END IF;
END $$;

-- +goose Down
ALTER TABLE identity_sources DROP CONSTRAINT IF EXISTS identity_sources_signature_mode_check;
ALTER TABLE identity_sources DROP COLUMN IF EXISTS skip_profile_review;
ALTER TABLE identity_sources DROP COLUMN IF EXISTS signature_mode;
