"""Runs inside security-engine, reading credentials only from its environment."""
import base64, collections, hashlib, json, os, sys, time, types
sys.path.insert(0,'/app')
request=json.loads(sys.stdin.read())
core=types.ModuleType('semantic_recompute');exec(request['core'],core.__dict__)
from app.detectors.llm_judge import judge_semantic, SEMANTIC_EXCERPT_CHARS
from app.detectors.prompt_injection import indirect_instruction_signal
from app.detectors.semantic import SemanticDetector
try:
 from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
 AESGCM=None
cfg=request['config'];key=os.environ.get('SECURITY_LLM_JUDGE_API_KEY','')
# Use the same signed managed configuration as the running engine. Authentication
# comes from container environment; encrypted database text is never a bearer key.
import httpx
from app.semantic_config_loader import _auth_headers, _validate_managed_config, _verify_managed_config_attestation, _effective_managed_config, SEMANTIC_CONFIG_PATH
managed=httpx.get(os.environ['CONTROL_PLANE_URL'].rstrip('/')+SEMANTIC_CONFIG_PATH,headers=_auth_headers(os.environ['JJD_INTERNAL_API_SECRET']),timeout=5)
managed.raise_for_status();managed=managed.json()
_validate_managed_config(managed);_verify_managed_config_attestation(managed);managed=_effective_managed_config(managed)
cfg={name:managed[name] for name in ('judge_url','judge_model','judge_backend')};cfg['priv']=managed['judge_allow_private_egress']
key=managed['judge_api_key'] or key
if not key:raise RuntimeError('judge credential missing from container environment')
previous=request.get('previous') or {}
calls=previous.get('judge_calls',0);failed=False;cache={};request_calls=collections.Counter(previous.get('judge_calls_by_request',{}))
previous_results={(r['event_id'],r['finding_index']):r for r in previous.get('results',[]) if r['outcome'] not in ('judge_budget','judge_unavailable','evidence_missing')}
max_calls=request['max_calls'];results=[]
for item in request['items']:
 # Queue payloads are authenticated with tenant/request/part identity.
 for part in item.get('parts',[]):
  encoded=part.get('payload_encrypted')
  if not encoded:continue
  try:
   secret=os.environ.get('JJD_INTERNAL_API_SECRET','')
   k=hashlib.sha256(('jjdguard:inspection-queue:v1:'+secret).encode()).digest()
   blob=base64.b64decode(encoded+'='*((-len(encoded))%4))
   aad=f"{item['tenant_id']}/{item['request_id']}/{part['part_index']}/payload".encode()
   plain=AESGCM(k).decrypt(blob[:12],blob[12:],aad) if AESGCM else core.decrypt_aes_gcm(k,blob[:12],blob[12:],aad)
   part['payload']=json.loads(plain)
  except Exception:pass
 text,basis=core.resolve_evidence(item)
 source=(item['finding'].get('content_source') or 'unknown').strip()
 context=item.get('task_context')
 cache_key=core.digest([source,text,context])
 prior=previous_results.get((item['event_id'],item['finding_index']))
 if prior and prior.get('basis',{}).get('sha256')==basis.get('sha256') and prior.get('basis',{}).get('context_sha256')==(core.digest(context) if context else None):
  cache[cache_key]={k:v for k,v in prior.items() if k not in ('event_id','finding_index','agent_type','source')}
 wrapped=SemanticDetector._indirect_judge_content(text or '',source,context)
 if text and (len(text)>SEMANTIC_EXCERPT_CHARS or (source in core.UNTRUSTED and len(wrapped)>SEMANTIC_EXCERPT_CHARS) or (context and len(wrapped)>SEMANTIC_EXCERPT_CHARS and (cache.get(cache_key,{}).get('bare') or {}).get('verdict')=='malicious')):
  cache[cache_key]={'outcome':'evidence_window_exceeds_budget','basis':dict(basis,context_sha256=core.digest(context) if context else None)}
 def judge(target):
  global calls,failed
  if failed:return None
  if calls>=max_calls or request_calls[item['request_id']]>=8:return {'verdict':'budget'}
  if len(target)>SEMANTIC_EXCERPT_CHARS or len(target.encode())>12000:return {'verdict':'window_budget'}
  calls+=1;request_calls[item['request_id']]+=1
  try:
   opinion=judge_semantic(target,url=cfg['judge_url'],model=cfg['judge_model'],api_key=key,timeout=20.0,judge_backend=cfg.get('judge_backend') or '',allow_private_egress=cfg.get('priv',False))
  except Exception:opinion=None
  # Stop this run on the first unavailable result; never reset a breaker.
  if opinion is None:failed=True;return None
  time.sleep(.15)
  return {'verdict':opinion.verdict,'category':opinion.category,'confidence':opinion.confidence}
 if cache_key not in cache:
  result=core.evaluate(text,source,context,indirect_instruction_signal,judge,SemanticDetector._indirect_judge_content)
  result['basis']=dict(basis,context_sha256=core.digest(context) if context else None)
  cache[cache_key]=result
 result=dict(cache[cache_key],event_id=item['event_id'],finding_index=item['finding_index'],agent_type=item['agent_type'],source=source)
 results.append(result)
print(json.dumps({'results':results,'judge_calls':calls,'judge_calls_by_request':dict(request_calls),'stopped_on_unavailable':failed,'unique_targets':len(cache)},ensure_ascii=False))
