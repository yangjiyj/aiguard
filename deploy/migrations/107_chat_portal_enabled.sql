-- 107_chat_portal_enabled.sql
-- Chat/SSO 门户暴露开关：系统设置新增 chat_portal_enabled（默认 false=不对外暴露）。
-- 由 web-console「系统设置」页 Switch 控制；portal-proxy 拉此值做 chat-edge 整站门控 + 数据面兜底。
-- 影响面：仅 system_settings 加一行，缺省 false 时行为与现状完全一致。幂等，可安全重跑。
INSERT INTO system_settings (key, value)
VALUES ('chat_portal_enabled', 'false')
ON CONFLICT (key) DO NOTHING;
