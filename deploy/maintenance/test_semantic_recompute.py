import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('core',Path(__file__).with_name('semantic_recompute.py'))
core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)

class RecomputeTests(unittest.TestCase):
 def test_queue_gcm_authentication_and_tamper_rejection(self):
  encrypted=bytes.fromhex('cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919')
  self.assertEqual(core.decrypt_aes_gcm(bytes(32),bytes(12),encrypted,b''),bytes(16))
  with self.assertRaises(ValueError):core.decrypt_aes_gcm(bytes(32),bytes(12),encrypted,b'other-tenant')
 def test_raw_window_precedes_unrelated_request_prefix(self):
  item={'finding':{'raw_evidence':'actual hit'},'content':[{'message_index':0,'content':'wrong prefix'}]}
  text,basis=core.resolve_evidence(item)
  self.assertEqual(text,'actual hit');self.assertEqual(basis['source'],'finding.raw_evidence')
 def test_content_requires_exact_message_index(self):
  item={'finding':{'message_index':2},'content':[{'message_index':1,'content':'wrong'},{'message_index':2,'content':'right'}]}
  self.assertEqual(core.resolve_evidence(item)[0],'right')
  item['finding']['message_index']=3;self.assertIsNone(core.resolve_evidence(item)[0])
 def test_never_falls_back_to_request_prefix(self):
  self.assertIsNone(core.resolve_evidence({'finding':{},'access':{'request_content_redacted':'unrelated'}})[0])
 def test_serialized_protocol_uses_exact_message(self):
  import json
  protocol={'messages':[{'role':'system','content':'history'},{'role':'user','content':'target'}]}
  for _ in range(3):
   protocol=json.dumps(protocol)
   item={'finding':{'message_index':1},'access':{'request_content_redacted':protocol}}
   self.assertEqual(core.resolve_evidence(item)[0],'target')
 def test_matched_block_and_evidence_hash_reject_unrelated_text(self):
  import json,hashlib
  item={'finding':{'message_index':0,'matched_location':'messages[0].content[1].text','raw_evidence_sha256':hashlib.sha256(b'target').hexdigest()},'access':{'request_content_redacted':json.dumps({'messages':[{'role':'user','content':[{'type':'text','text':'unrelated'},{'type':'text','text':'target'}]}]})}}
  self.assertEqual(core.resolve_evidence(item)[0],'target')
  item['finding']['matched_location']='messages[0].content[0].text'
  self.assertIsNone(core.resolve_evidence(item)[0])
 def test_direct_context_can_only_exonerate(self):
  calls=[]
  def judge(text):calls.append(text);return {'verdict':'benign'}
  result=core.evaluate('target','user','hostile context',lambda _:True,judge,lambda t,s,c:c+' '+t)
  self.assertEqual(result['outcome'],'exonerated');self.assertEqual(calls,['target'])
  calls=[]
  def review(text):calls.append(text);return {'verdict':'malicious' if len(calls)==1 else 'benign'}
  self.assertEqual(core.evaluate('target','user','context',lambda _:True,review,lambda t,s,c:c+' '+t)['outcome'],'context_exonerated')
  self.assertEqual(len(calls),2)
  opinions=iter([{'verdict':'malicious'},None])
  self.assertEqual(core.evaluate('target','user','context',lambda _:True,lambda _:next(opinions),lambda t,s,c:c+t)['outcome'],'still_valid')
 def test_untrusted_needs_corroboration_before_judge(self):
  def judge(_):raise AssertionError('must not call judge')
  self.assertEqual(core.evaluate('quoted persona','tool_result',None,lambda _:False,judge,lambda t,s,c:t)['outcome'],'uncorroborated')
 def test_attack_stays_and_unknown_is_not_exonerated(self):
  wrap=lambda t,s,c:t
  self.assertEqual(core.evaluate('attack','user',None,lambda _:True,lambda _:{'verdict':'malicious'},wrap)['outcome'],'still_valid')
  self.assertEqual(core.evaluate('attack','user',None,lambda _:True,lambda _:None,wrap)['outcome'],'judge_unavailable')
 def test_window_budget_never_silently_judges_a_prefix(self):
  result=core.evaluate('complete target','user',None,lambda _:True,lambda _:{'verdict':'window_budget'},lambda t,s,c:t)
  self.assertEqual(result['outcome'],'evidence_window_exceeds_budget')
 def test_previous_wrong_or_missing_restores_original(self):
  original={'type':'semantic_attack','severity':'high','raw_evidence':'window'}
  current={**original,'counts_as_security_finding':False,'evidence_revalidation':{'version':'semantic-revalidate-v1'}}
  for outcome in ['still_valid','evidence_missing','judge_budget','judge_unavailable']:
   revised,decision=core.reconcile_finding(current,original,{'outcome':outcome,'basis':{}})
   self.assertEqual(revised,original);self.assertEqual(decision,'restore')
 def test_same_result_records_real_basis(self):
  original={'type':'semantic_attack','severity':'high','raw_evidence':'window'}
  current={**original,'counts_as_security_finding':False,'evidence_revalidation':{'version':'semantic-revalidate-v1'}}
  revised,decision=core.reconcile_finding(current,original,{'outcome':'exonerated','basis':{'source':'finding.raw_evidence','sha256':'abc'}})
  self.assertEqual(decision,'consistent');self.assertFalse(revised['counts_as_security_finding'])
  self.assertEqual(revised['evidence_revalidation']['recomputed_against']['sha256'],'abc')

if __name__=='__main__':unittest.main()
