-- 095_request_logs_source_ip.sql
-- 为主链 chat 流量补充客户端源 IP 列（只读增强，供 lse 评测按源 IP 过滤/回显）。
-- nullable、无默认，metadata-only：在大表上仅改目录、不重写行。
-- 现存代理流量的源 IP 在 request_logs.proxy_source_ip；该列由后续 P2 写入路径填充。

ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS source_ip VARCHAR(64);
