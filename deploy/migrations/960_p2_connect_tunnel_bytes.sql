-- 960 (P2): 正向代理不解密 CONNECT 隧道补持续时长。
-- 上/下行字节复用 060 已有的 proxy_request_bytes / proxy_response_bytes，隧道结束时回写建隧道时那一行。
-- 只新增可空列（无默认值重写），可在空库和现有库重复执行；不改已有迁移。
ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS proxy_tunnel_duration_ms BIGINT;
