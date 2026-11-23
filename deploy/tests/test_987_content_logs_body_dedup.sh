#!/bin/bash
# 987 读方等价性测试：同一份数据（长对话、重复正文、跨租户、带历史表行）分别写入「原单表」与「987 视图」两个库，
# 然后对 content_logs 执行代表性读法（按请求列表、首条 user、计数、关键词、会话聚合、客户内容投影、证据索引），
# 两边结果逐字节比较。再验证回滚后数据与原单表一致。
set -euo pipefail
WT=/home/dev/jjdguard-src/.worktrees/hotfix-acme-maxtokens-20261022
PW=$(docker inspect jg-alert-pg --format "{{range .Config.Env}}{{println .}}{{end}}" | sed -n "s/^POSTGRES_PASSWORD=//p")
P(){ local db=$1; shift; docker exec -i -e PGPASSWORD="$PW" jg-alert-pg psql -U newapi -d "$db" -v ON_ERROR_STOP=1 -Atq "$@"; }
# 只读查询不能让 docker exec -i 读走循环的标准输入
Q(){ local db=$1; shift; docker exec -e PGPASSWORD="$PW" jg-alert-pg psql -U newapi -d "$db" -v ON_ERROR_STOP=1 -Atq "$@" </dev/null; }
for db in eq_base eq_987; do
  P postgres -c "DROP DATABASE IF EXISTS $db" 2>/dev/null; P postgres -c "CREATE DATABASE $db TEMPLATE jjdguard"
  P $db < $WT/deploy/migrations/986_content_projection_write_amplification.sql
done
# 两边各放一条「迁移前的历史行」：base 直接在表里；987 在 legacy 表里（模拟升级前已有数据）
for db in eq_base eq_987; do P $db -c "INSERT INTO tenants (id,name,is_test) VALUES ('eq_t1','eq1',true),('eq_t2','eq2',true) ON CONFLICT DO NOTHING"; done
P eq_base -c "INSERT INTO request_logs (id,request_id,tenant_id,session_id,created_at,proxy_mode) VALUES ('eq_old','eq_old_r','eq_t1','sess_old', timestamp '2026-10-21 09:00','chat_completion')"
P eq_base -c "INSERT INTO content_logs (id,request_id,tenant_id,session_id,role,content,created_at,message_index,environment_scope) VALUES ('cl_old1','eq_old','eq_t1','sess_old','user','升级前的历史提问 OpenAI Codex', timestamp '2026-10-21 09:00',0,'customer')"
P eq_987 -c "INSERT INTO request_logs (id,request_id,tenant_id,session_id,created_at,proxy_mode) VALUES ('eq_old','eq_old_r','eq_t1','sess_old', timestamp '2026-10-21 09:00','chat_completion')"
P eq_987 -c "INSERT INTO content_logs (id,request_id,tenant_id,session_id,role,content,created_at,message_index,environment_scope) VALUES ('cl_old1','eq_old','eq_t1','sess_old','user','升级前的历史提问 OpenAI Codex', timestamp '2026-10-21 09:00',0,'customer')"
# 升级：历史行已在原表里，再应用 987（原表改名为 content_logs_legacy）
P eq_987 < $WT/deploy/migrations/987_content_logs_body_dedup.sql
# 新数据：2 租户 × 2 会话 × 12 轮，每轮带完整历史 + 同一系统提示词（两租户相同正文，验证租户隔离去重）
GEN="INSERT INTO request_logs (id,request_id,tenant_id,session_id,agent_type,created_at,proxy_mode)
 SELECT 'eq_'||t||'_'||s||'_'||r, 'eq_r_'||t||'_'||s||'_'||r, 'eq_t'||t, 'sess_'||t||'_'||s, CASE WHEN s=2 THEN 'vscode' ELSE 'claude-code' END,
        timestamp '2026-10-22 10:00' + ((t*100+s*20+r) * interval '1 minute'), 'chat_completion'
 FROM generate_series(1,2) t, generate_series(1,2) s, generate_series(1,12) r;
DO \$d\$ DECLARE t int; s int; r int; k int; BEGIN
 FOR t IN 1..2 LOOP FOR s IN 1..2 LOOP FOR r IN 1..12 LOOP
   INSERT INTO content_logs (id,request_id,tenant_id,session_id,role,content,tokens,created_at,message_index,environment_scope)
   VALUES ('eq_c_'||t||'_'||s||'_'||r||'_0','eq_'||t||'_'||s||'_'||r,'eq_t'||t,'sess_'||t||'_'||s,'system',
           CASE WHEN s=2 THEN 'You are OpenAI Codex. 系统提示' ELSE 'You are Claude Code. 系统提示' END, 0,
           timestamp '2026-10-22 10:00' + ((t*100+s*20+r) * interval '1 minute') + interval '1 ms', 0, 'customer');
   FOR k IN 1..r LOOP
     INSERT INTO content_logs (id,request_id,tenant_id,session_id,role,content,tokens,created_at,message_index,environment_scope)
     VALUES ('eq_c_'||t||'_'||s||'_'||r||'_'||(2*k-1),'eq_'||t||'_'||s||'_'||r,'eq_t'||t,'sess_'||t||'_'||s,'user',
             '会话'||s||'第'||k||'问 关键词'||(k%3), k,
             timestamp '2026-10-22 10:00' + ((t*100+s*20+r) * interval '1 minute') + ((2*k) * interval '1 ms'), 2*k-1, 'customer');
     INSERT INTO content_logs (id,request_id,tenant_id,session_id,role,content,tokens,created_at,message_index,environment_scope)
     VALUES ('eq_c_'||t||'_'||s||'_'||r||'_'||(2*k),'eq_'||t||'_'||s||'_'||r,'eq_t'||t,'sess_'||t||'_'||s,'assistant',
             '会话'||s||'第'||k||'答', k,
             timestamp '2026-10-22 10:00' + ((t*100+s*20+r) * interval '1 minute') + ((2*k+1) * interval '1 ms'), 2*k, 'customer');
   END LOOP;
 END LOOP; END LOOP; END LOOP; END \$d\$;"
for db in eq_base eq_987; do P $db -c "$GEN"; done
# 代表性读法（来自盘点的 50 个读方的各类：A 按请求全量、B 首条/末条、C 聚合计数、D 关键词）
read -r -d '' QUERIES <<'SQL' || true
A1|SELECT cl.id, cl.role, cl.content, cl.tokens, cl.message_index, cl.session_id, cl.environment_scope FROM content_logs cl JOIN request_logs rl ON rl.id=cl.request_id WHERE rl.tenant_id='eq_t1' AND rl.request_id='eq_r_1_1_12' ORDER BY cl.message_index NULLS LAST, cl.created_at, cl.id
A2|SELECT cl.id, cl.role, cl.content FROM content_logs cl WHERE cl.tenant_id='eq_t2' AND cl.session_id='sess_2_2' ORDER BY cl.created_at, cl.id
B1|SELECT rl.request_id, (SELECT cl.content FROM content_logs cl WHERE cl.tenant_id=rl.tenant_id AND cl.request_id=rl.id AND cl.role='user' AND jjdguard_customer_content_text(cl.content) ORDER BY cl.created_at ASC, cl.id ASC LIMIT 1) FROM request_logs rl WHERE rl.tenant_id IN ('eq_t1','eq_t2') ORDER BY 1
B2|SELECT rl.request_id, (SELECT cl.content FROM content_logs cl WHERE cl.request_id=rl.id AND cl.role='assistant' ORDER BY cl.created_at DESC, cl.id DESC LIMIT 1) FROM request_logs rl WHERE rl.tenant_id='eq_t1' ORDER BY 1
C1|SELECT tenant_id, session_id, role, count(*), sum(tokens), min(created_at), max(created_at) FROM content_logs WHERE tenant_id LIKE 'eq_t%' GROUP BY 1,2,3 ORDER BY 1,2,3
C2|SELECT rl.request_id, (SELECT count(*) FROM content_logs cl WHERE cl.request_id=rl.id) FROM request_logs rl WHERE rl.tenant_id LIKE 'eq_t%' ORDER BY 1
D1|SELECT cl.id, cl.request_id FROM content_logs cl WHERE cl.tenant_id='eq_t1' AND cl.role IN ('user','assistant') AND cl.content ILIKE '%关键词2%' ORDER BY cl.created_at DESC, cl.id
D2|SELECT count(*) FROM content_logs cl WHERE cl.tenant_id='eq_t1' AND (cl.content ILIKE '%OpenAI Codex%' OR cl.content ILIKE '%Codex Desktop%')
P1|SELECT request_id, has_customer_content, has_customer_request_body, has_customer_response_body, customer_content_rule_version FROM request_logs WHERE tenant_id LIKE 'eq_t%' ORDER BY 1
P2|SELECT request_id, effective_agent_type, effective_agent_runtime, effective_detection_source, effective_detection_confidence, session_id, title_hash, transcript_signature, chain_dirty FROM evidence_run_request_index WHERE tenant_id LIKE 'eq_t%' ORDER BY 1
SQL
fail=0
while IFS='|' read -r name sql; do
  [ -z "$name" ] && continue
  a=$(Q eq_base -c "$sql" | sha256sum | cut -c1-16); b=$(Q eq_987 -c "$sql" | sha256sum | cut -c1-16)
  n=$(Q eq_base -c "$sql" | wc -l)
  if [ "$a" = "$b" ]; then echo "[ok] $name 一致（$n 行）"; else echo "[FAIL] $name 不一致"; fail=1; diff <(Q eq_base -c "$sql") <(Q eq_987 -c "$sql") | head -6; fi
done <<< "$QUERIES"
echo "--- 存储 ---"
echo "base: $(P eq_base -c "select count(*) from content_logs where tenant_id like 'eq_t%'") 行"
echo "987 : $(P eq_987 -c "select count(*) from content_log_entries where tenant_id like 'eq_t%'") 行，正文 $(P eq_987 -c "select count(*) from content_log_bodies where tenant_id like 'eq_t%'") 份"
echo "--- 保留期清理：删 1 天前的数据并回收孤立正文 ---"
P eq_987 -c "DELETE FROM content_logs_legacy WHERE id='cl_old1'"
P eq_987 -c "DELETE FROM content_log_entries WHERE request_id='eq_1_1_1'"
before=$(P eq_987 -c "select count(*) from content_log_bodies"); pruned=$(P eq_987 -c "select prune_content_log_bodies(5000)"); after=$(P eq_987 -c "select count(*) from content_log_bodies")
echo "正文 $before → $after（回收 $pruned 份），视图仍可读：$(P eq_987 -c "select count(*) from content_logs where tenant_id='eq_t1'") 行"
echo "--- 回滚 987 ---"
P eq_987 < $WT/deploy/migrations/rollback/987_content_logs_body_dedup.sql
echo "回滚后 relkind=$(P eq_987 -c "select relkind from pg_class where relname='content_logs'")  行数=$(P eq_987 -c "select count(*) from content_logs where tenant_id like 'eq_t%'")"
P eq_987 -c "select tgname from pg_trigger where tgrelid='content_logs'::regclass and not tgisinternal order by 1" | tr '\n' ' '; echo
for db in eq_base eq_987; do P postgres -c "DROP DATABASE IF EXISTS $db" 2>/dev/null; done
exit $fail
