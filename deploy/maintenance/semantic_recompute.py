"""Pure evidence selection and conservative semantic-history reconciliation."""
import copy
import hashlib
import json
import re

VERSION='semantic-revalidate-v2'
UNTRUSTED={'tool_result','rag','rag_context','retrieval','retrieval_result','web_content'}
WITHDRAW={'exonerated':'context_conviction_withdrawn','context_exonerated':'context_exonerated','uncorroborated':'semantic_indirect_uncorroborated'}
RANK={'low':0,'medium':1,'high':2,'critical':3}

def digest(value):
 return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def text_content(value):
 if isinstance(value,str):return value
 if isinstance(value,list):
  return '\n'.join(v.get('text','') for v in value if isinstance(v,dict) and v.get('type') in ('text','input_text','output_text'))
 return ''

def resolve_evidence(item):
 f=item['finding'];raw=f.get('raw_evidence')
 text=None;source=None
 if isinstance(raw,str) and raw.strip():text,source=raw,'finding.raw_evidence'
 else:
  index=f.get('message_index')
  try:index=int(index) if index is not None else None
  except (ValueError,TypeError):index=None
  exact=[row for row in item.get('content',[]) if index is not None and row.get('message_index')==index]
  if len(exact)==1:text,source=exact[0].get('content'),'content_logs.message_index'
  if text is None:
   for part in item.get('parts',[]):
    if f.get('inspection_part_index') is not None and str(part.get('part_index'))==str(f['inspection_part_index']):
     payload=part.get('payload') or {}
     if isinstance(payload,dict) and isinstance(payload.get('content'),str):text,source=payload['content'],'proxy_inspection_parts.part_index';break
  if text is None and index is not None:
   access=item.get('access') or {};location=str(f.get('matched_location') or '')
   field='response_content_redacted' if location.startswith('output') else 'request_content_redacted'
   try:
    protocol=json.loads(access.get(field) or '{}')
    for _ in range(3):
     if isinstance(protocol,str):protocol=json.loads(protocol)
    messages=protocol.get('messages',protocol.get('input',[])) if isinstance(protocol,dict) else []
    if isinstance(messages,list) and 0<=index<len(messages) and isinstance(messages[index],dict):
     selected=messages[index]
     for block_index in re.findall(r'content\[(\d+)\]',location):
      content=selected.get('content') if isinstance(selected,dict) else None
      if not isinstance(content,list) or int(block_index)>=len(content):selected=None;break
      selected=content[int(block_index)]
     if isinstance(selected,dict):
      text,source=text_content(selected.get('text',selected.get('content'))),'access_content_logs.protocol.message_index'
   except (ValueError,TypeError,AttributeError):pass
  # Retained full messages are not the hit window when offsets are known.
  if text and source!='finding.raw_evidence':
   location=str(f.get('matched_location') or '')
   match=re.search(r'(?:chars?|offset)[:=\[]\s*(\d+)\s*[-:,]\s*(\d+)',location)
   if match:
    start,end=map(int,match.groups())
    if 0<=start<end<=len(text):text=text[start:end];source+=':matched_location'
    else:text=None
 if not isinstance(text,str) or not text.strip():return None,{'source':'missing'}
 expected=f.get('raw_evidence_sha256')
 if source!='finding.raw_evidence' and isinstance(expected,str) and re.fullmatch(r'[0-9a-fA-F]{64}',expected) and hashlib.sha256(text.encode()).hexdigest()!=expected.lower():
  return None,{'source':'retained_evidence_hash_mismatch'}
 return text,{'source':source,'sha256':hashlib.sha256(text.encode()).hexdigest(),'characters':len(text)}

def evaluate(text,source,context,signal,judge,wrap):
 if not text:return {'outcome':'evidence_missing'}
 if source in UNTRUSTED and not signal(text):return {'outcome':'uncorroborated','signal':False}
 bare=judge(wrap(text,source,context) if source in UNTRUSTED else text)
 if not bare:return {'outcome':'judge_unavailable'}
 if bare.get('verdict')=='budget':return {'outcome':'judge_budget'}
 if bare.get('verdict')=='window_budget':return {'outcome':'evidence_window_exceeds_budget'}
 if bare.get('verdict')=='malicious':
  if source not in UNTRUSTED and context:
   review=judge(wrap(text,source,context))
   if not review or review.get('verdict')=='budget':return {'outcome':'still_valid','bare':bare,'context_review':'unavailable'}
   if review.get('verdict')=='window_budget':return {'outcome':'evidence_window_exceeds_budget','bare':bare}
   if review.get('verdict')=='benign':return {'outcome':'context_exonerated','bare':bare,'review':review}
  return {'outcome':'still_valid','bare':bare}
 if bare.get('verdict') in ('benign','suspicious'):return {'outcome':'exonerated','bare':bare}
 return {'outcome':'judge_unavailable'}

def reconcile_finding(current,original,result):
 outcome=result['outcome'];prior=(current.get('evidence_revalidation') or {})
 previous=prior.get('version')=='semantic-revalidate-v1'
 if previous and (outcome not in WITHDRAW or (prior.get('reason') and prior['reason']!=WITHDRAW[outcome])):
  return copy.deepcopy(original),'restore'
 if outcome not in WITHDRAW:return copy.deepcopy(current),'unchanged'
 revised=copy.deepcopy(original if previous else current)
 revised['counts_as_security_finding']=False
 revised['evidence_revalidation']={'version':VERSION,'status':'observation','reason':WITHDRAW[outcome],'original_counts_as_security_finding':original.get('counts_as_security_finding'),'recomputed_against':dict(result.get('basis') or {},logic_revision='7c1b025e6',bare_verdict=(result.get('bare') or {}).get('verdict'),context_verdict=(result.get('review') or {}).get('verdict'))}
 return revised,'consistent' if previous else 'new_withdrawal'

def recompute_summary(summary,severity):
 revised=copy.deepcopy(summary);findings=revised.get('findings') or []
 active=[f for f in findings if isinstance(f,dict) and f.get('counts_as_security_finding') is not False]
 revised['findings_count']=len(active)
 primary=revised.get('primary_finding')
 if isinstance(primary,dict):
  for f in findings:
   if isinstance(f,dict) and all(f.get(k)==primary.get(k) for k in ('rule_id','message_index','matched_location','raw_evidence')):revised['primary_finding']=copy.deepcopy(f);break
 level=max((f.get('severity',severity) for f in active),key=lambda s:RANK.get(s,0),default='low')
 return revised,level

def build_apply_sql(changes,guards=()):
 def quote(value):return "'"+str(value).replace("'","''")+"'"
 query="BEGIN; SET LOCAL lock_timeout='3s'; LOCK TABLE security_events,security_event_occurrences,alert_groups,alert_inbox IN SHARE ROW EXCLUSIVE MODE;\nCREATE TEMP TABLE semantic_plan_cas(ok boolean NOT NULL CHECK(ok)) ON COMMIT DROP;\n"
 for guard in guards:
  for table in ('security_events','security_event_occurrences'):
   expected=sorted(guard[table],key=lambda row:row['id'])
   where='tenant_id='+quote(guard['tenant_id'])+' AND alert_group_id='+quote(guard['group_id'])
   query+='INSERT INTO semantic_plan_cas SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.id),\'[]\'::jsonb)='+quote(json.dumps(expected,ensure_ascii=False))+'::jsonb FROM '+table+' r WHERE '+where+';\n'
 for change in changes:
  table=change['table']
  if table not in ('security_events','alert_groups','alert_inbox'):raise ValueError('invalid table')
  before=change['before'];assign=[]
  for field,value in change['after'].items():
   if field not in ('matched_summary','effective_severity','body_json','disposition_class','severity','occurrence_count','distinct_occurrences','affected_users','last_calc_at'):raise ValueError('invalid field')
   literal=quote(json.dumps(value,ensure_ascii=False))+'::jsonb' if isinstance(value,(dict,list)) else ('NULL' if value is None else quote(value))
   assign.append(field+'='+literal)
  match='tenant_id='+quote(before['tenant_id'])+' AND id='+quote(before['id'])
  query+='INSERT INTO semantic_plan_cas SELECT EXISTS(SELECT 1 FROM '+table+' r WHERE '+match+' AND to_jsonb(r)='+quote(json.dumps(before,ensure_ascii=False))+'::jsonb);\n'
  query+='UPDATE '+table+' SET '+','.join(assign)+' WHERE '+match+';\n'
 return query+'COMMIT;'

def decrypt_aes_gcm(key,nonce,ciphertext_and_tag,aad):
 """Authenticate queue payloads with the platform OpenSSL library (no pip install)."""
 import ctypes as c
 import ctypes.util
 if len(key)!=32 or len(nonce)!=12 or len(ciphertext_and_tag)<16:raise ValueError('invalid GCM input')
 lib=c.CDLL(ctypes.util.find_library('crypto'))
 lib.EVP_CIPHER_CTX_new.restype=c.c_void_p
 lib.EVP_aes_256_gcm.restype=c.c_void_p
 lib.EVP_DecryptInit_ex.argtypes=[c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p]
 lib.EVP_DecryptUpdate.argtypes=[c.c_void_p,c.c_void_p,c.POINTER(c.c_int),c.c_void_p,c.c_int]
 lib.EVP_CIPHER_CTX_ctrl.argtypes=[c.c_void_p,c.c_int,c.c_int,c.c_void_p]
 lib.EVP_DecryptFinal_ex.argtypes=[c.c_void_p,c.c_void_p,c.POINTER(c.c_int)]
 lib.EVP_CIPHER_CTX_free.argtypes=[c.c_void_p]
 ctx=lib.EVP_CIPHER_CTX_new()
 if not ctx:raise ValueError('GCM context unavailable')
 try:
  def require(value):
   if value!=1:raise ValueError('queue payload authentication failed')
  require(lib.EVP_DecryptInit_ex(ctx,lib.EVP_aes_256_gcm(),None,c.create_string_buffer(key),c.create_string_buffer(nonce)))
  length=c.c_int();ciphertext=ciphertext_and_tag[:-16];out=c.create_string_buffer(len(ciphertext)+16)
  require(lib.EVP_DecryptUpdate(ctx,None,c.byref(length),c.create_string_buffer(aad),len(aad)))
  require(lib.EVP_DecryptUpdate(ctx,out,c.byref(length),c.create_string_buffer(ciphertext),len(ciphertext)));size=length.value
  require(lib.EVP_CIPHER_CTX_ctrl(ctx,0x11,16,c.create_string_buffer(ciphertext_and_tag[-16:])))
  tail=c.create_string_buffer(16);require(lib.EVP_DecryptFinal_ex(ctx,tail,c.byref(length)))
  return out.raw[:size]+tail.raw[:length.value]
 finally:lib.EVP_CIPHER_CTX_free(ctx)
