#!/bin/bash
# 在隔离测试库上回放：同一批长对话写入，分别用原函数和 986 函数，比较派生结果是否完全一致、写入次数差多少
set -euo pipefail
WT=${WT:-$(cd "$(dirname "$0")/../.." && pwd)}
W=${W:-$(mktemp -d)}
PW=$(docker inspect jg-alert-pg --format "{{range .Config.Env}}{{println .}}{{end}}" | sed -n "s/^POSTGRES_PASSWORD=//p")
P(){ docker exec -i -e PGPASSWORD="$PW" jg-alert-pg psql -U newapi -d jjdguard -v ON_ERROR_STOP=1 -Atq "$@"; }
run(){ # $1=标签 $2=函数定义文件
  local S=replay_$1
  P <<SQL
DROP SCHEMA IF EXISTS $S CASCADE; CREATE SCHEMA $S;
SET search_path=$S,public;
CREATE TABLE $S.request_logs (LIKE public.request_logs INCLUDING DEFAULTS);
ALTER TABLE $S.request_logs ADD PRIMARY KEY (id);
CREATE UNIQUE INDEX ON $S.request_logs(request_id);
CREATE TABLE $S.content_logs (LIKE public.content_logs INCLUDING DEFAULTS);
CREATE TABLE $S.access_content_logs (LIKE public.access_content_logs INCLUDING DEFAULTS);
CREATE TABLE $S.evidence_run_request_index (LIKE public.evidence_run_request_index INCLUDING DEFAULTS);
ALTER TABLE $S.evidence_run_request_index ADD PRIMARY KEY (tenant_id, request_log_id);
SQL
  # 把函数定义装进本 schema（函数体里的表名不带 schema 前缀，靠 search_path 解析到本 schema）
  sed -E "s/FUNCTION public\./FUNCTION $S./; /^BEGIN;\$/d; /^COMMIT;\$/d" "$2" | P -c "SET search_path=$S,public;" -f -
  P <<SQL
SET search_path=$S,public;
ALTER FUNCTION $S.sync_evidence_run_request_index() SET search_path=$S,public;
ALTER FUNCTION $S.jjdguard_refresh_request_customer_content_projection(varchar,varchar) SET search_path=$S,public;
CREATE OR REPLACE FUNCTION $S.refresh_request_customer_content_projection() RETURNS trigger LANGUAGE plpgsql SET search_path=$S,public AS \$t\$
BEGIN
  IF TG_OP='INSERT' THEN PERFORM $S.jjdguard_refresh_request_customer_content_projection(NEW.tenant_id,(SELECT request_id FROM request_logs WHERE id=NEW.request_id)); END IF;
  RETURN NEW;
END \$t\$;
CREATE TRIGGER t1 AFTER INSERT ON content_logs FOR EACH ROW EXECUTE FUNCTION $S.refresh_request_customer_content_projection();
CREATE TRIGGER t2 AFTER INSERT OR UPDATE OF content, role, session_id ON content_logs FOR EACH ROW EXECUTE FUNCTION $S.sync_evidence_run_request_index();
CREATE TRIGGER t3 AFTER INSERT OR UPDATE OF request_id, tenant_id, created_at, session_id, agent_type, agent_runtime, agent_detection_source, agent_detection_confidence, evidence_run_id, evidence_run_source, user_id, client_id, proxy_source_ip, source_ip ON request_logs FOR EACH ROW EXECUTE FUNCTION $S.sync_evidence_run_request_index();
-- 场景：3 个会话 × 40 轮，每轮请求带完整历史（system + 交替 user/assistant/tool），含一条 codex 候选链请求
INSERT INTO request_logs (id,request_id,tenant_id,user_id,client_id,session_id,agent_type,evidence_run_source,proxy_mode,created_at)
SELECT 'log_'||s||'_'||r, 'req_'||s||'_'||r, 't1', 'u'||s, 'k'||s, 'sess'||s,
       CASE WHEN s=3 THEN 'vscode' ELSE 'claude-code' END,
       CASE WHEN s=2 THEN 'responses_prompt_cache_key' ELSE '' END,
       CASE WHEN s=1 AND r%7=0 THEN 'forward' ELSE 'chat_completion' END,
       timestamptz '2026-10-22 00:00:00+00' + (s*100+r)*interval '1 second'
FROM generate_series(1,3) s, generate_series(1,40) r;
SQL
  # 逐请求逐条插入消息（与网关写法相同：一条一条 INSERT）
  P <<SQL
SET search_path=$S,public;
DO \$d\$
DECLARE s int; r int; i int; role text; body text;
BEGIN
  FOR s IN 1..3 LOOP FOR r IN 1..40 LOOP
    FOR i IN 0..(r*2) LOOP
      role := CASE WHEN i=0 THEN 'system' WHEN i%3=1 THEN 'user' WHEN i%3=2 THEN 'assistant' ELSE 'tool' END;
      body := CASE WHEN i=0 THEN 'You are Claude Code. 系统提示词' WHEN s=3 AND i=1 THEN 'OpenAI Codex 请帮我看代码 '||i ELSE '第'||i||'条 '||role||' 内容 '||repeat('x', (i%5)*20) END;
      INSERT INTO content_logs (id,request_id,tenant_id,user_id,session_id,role,content,tokens,created_at,message_index)
      VALUES ('cl_'||s||'_'||r||'_'||i, 'log_'||s||'_'||r, 't1', 'u'||s, 'sess'||s, role, body, 0,
              timestamptz '2026-10-22 00:00:00+00' + (s*100+r)*interval '1 second' + i*interval '1 ms', i);
    END LOOP;
  END LOOP; END LOOP;
END \$d\$;
SQL
  # 导出派生结果（排除 updated_at 这种时间戳），并统计写入次数
  P -c "SET search_path=$S,public;" -c "COPY (SELECT id,request_id,has_customer_content,has_customer_request_body,has_customer_response_body,customer_content_rule_version FROM request_logs ORDER BY id) TO STDOUT" > $W/$1.request_logs.tsv
  P -c "SET search_path=$S,public;" -c "COPY (SELECT tenant_id,request_log_id,request_id,created_at,effective_agent_type,effective_agent_runtime,effective_detection_source,effective_detection_confidence,session_id,evidence_run_id,evidence_run_source,conversation_id,section_id,chain_principal,title_hash,transcript_signature,derived_chain_root,derived_chain_size,chain_dirty FROM evidence_run_request_index ORDER BY 1,2) TO STDOUT" > $W/$1.eri.tsv
  P -c "select pg_stat_force_next_flush()" >/dev/null 2>&1 || true
  sleep 1
  P -c "select relname, n_tup_upd, n_tup_ins from pg_stat_user_tables where schemaname='$S' and relname in ('request_logs','evidence_run_request_index') order by 1" | sed "s/^/$1 /"
  P -c "select count(*) from $S.content_logs" | sed "s/^/$1 content_logs 行数 /"
}
run orig $WT/deploy/migrations/rollback/986_content_projection_write_amplification.sql
run fixed $WT/deploy/migrations/986_content_projection_write_amplification.sql
echo "=== 派生结果是否完全一致 ==="
for t in request_logs eri; do
  if cmp -s $W/orig.$t.tsv $W/fixed.$t.tsv; then echo "$t: 完全一致（$(wc -l < $W/orig.$t.tsv) 行）"; else echo "$t: 不一致!"; diff $W/orig.$t.tsv $W/fixed.$t.tsv | head -10; fi
done
P -c "DROP SCHEMA replay_orig CASCADE; DROP SCHEMA replay_fixed CASCADE;" 2>/dev/null
