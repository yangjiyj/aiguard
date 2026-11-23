-- 983: 本地身份（Keycloak）孤儿用户清理的持久化重试队列。
--
-- 背景：删除用户的顺序是 解析 subject -> 在 Keycloak 禁用 -> 删 users 行 -> 吊销会话 -> 删除 Keycloak 用户。
-- 最后一步失败时账号已禁用、无法登录，但 Keycloak 里仍留着孤儿用户（占着用户名，且是潜在的越权入口），
-- 必须有人持续重试直到删掉。users 行此时已经不存在，所以不能再靠 users.status=reconciliation_required 来记账，
-- 需要一张独立的、不依赖 users 行的队列。
--
-- 设计约束：
--   1) subject 加密存储（secrets 包，与 provider 密钥同一套密钥和算法），表里没有 Keycloak subject 明文；
--      subject_fingerprint 是 sha256(tenant_id|subject) 的十六进制，用于审计与对账关联，不可反推出 subject。
--   2) user_id 不加外键：users 行已被删除，审计和排查需要保留原值。
--   3) 到期调度靠 next_attempt_at + attempts：指数退避与最大次数由 worker 控制，超过上限置 status='exhausted'
--      并告警，不再自动重试，等待人工处置（避免无限重试打爆 Keycloak）。
--   4) (tenant_id, subject_fingerprint) 唯一：同一个 subject 重复入队只更新，不产生多条。
CREATE TABLE IF NOT EXISTS local_identity_cleanup_queue (
  id                  varchar(64)  PRIMARY KEY,
  tenant_id           varchar(64)  NOT NULL,
  user_id             varchar(64)  NOT NULL,
  subject_ciphertext  text         NOT NULL,
  subject_fingerprint varchar(64)  NOT NULL CHECK (subject_fingerprint ~ '^[0-9a-f]{64}$'),
  operation           varchar(32)  NOT NULL DEFAULT 'delete_user' CHECK (operation IN ('delete_user')),
  status              varchar(16)  NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','done','exhausted')),
  attempts            integer      NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts        integer      NOT NULL DEFAULT 12 CHECK (max_attempts > 0),
  next_attempt_at     timestamptz  NOT NULL DEFAULT now(),
  last_error_code     varchar(64)  NOT NULL DEFAULT '',
  actor_id            varchar(64)  NOT NULL DEFAULT '',
  created_at          timestamptz  NOT NULL DEFAULT now(),
  updated_at          timestamptz  NOT NULL DEFAULT now(),
  completed_at        timestamptz,
  UNIQUE (tenant_id, subject_fingerprint)
);

-- worker 只扫待处理且到期的行；已完成的行很快被清理，所以用部分索引。
CREATE INDEX IF NOT EXISTS idx_local_identity_cleanup_due
  ON local_identity_cleanup_queue (next_attempt_at)
  WHERE status = 'pending';
