-- 106_internal_keys_ciphertext.sql
-- key-reveal（后台复制完整密钥）：internal_keys 补 key_ciphertext 列。
-- 背景：完整密钥此前只存 sha256(key_hash)+key_prefix（不可逆），后台"复制密钥"实为复制 8 位前缀，误导管理员。
-- 方案：新建 key 时把完整明文经 AES-GCM 加密（enc:v1: 前缀，与 MCP/provider 凭据同一套 secrets.EncryptProviderSecret）
--       落入本列；后台按需解密复制，绝不改动 key_hash 鉴权链路，也不在 List/Create 常规响应回传本列。
-- 影响面：仅加列 TEXT NULLABLE。gateway-core 鉴权 SELECT 为显式列清单，零影响。
--         存量老 key 本列为 NULL（完整值已丢），reveal 端点返 {full_key:null,reason:created_before_encryption} 提示重置。
-- 幂等，可安全重跑。

ALTER TABLE internal_keys
  ADD COLUMN IF NOT EXISTS key_ciphertext TEXT;

COMMENT ON COLUMN internal_keys.key_ciphertext IS '完整密钥 AES-GCM 密文（enc:v1: 前缀，JJD_PROVIDER_SECRET_KEY 派生）；仅后台受保护 reveal 端点按需解密，NULL=改造前老 key 不可复原';
